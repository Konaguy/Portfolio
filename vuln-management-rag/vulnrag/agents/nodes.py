"""
The agent nodes.

The graph is a small multi-agent pipeline:

    router  ->  retriever  ->  {remediation | prioritization | policy}  ->  END

*   **router** classifies the analyst's question into an intent. It uses a
    fast keyword heuristic and only falls back to the LLM when the heuristic
    is unsure -- cheap, deterministic routing for the common cases, model
    judgement for the ambiguous ones.
*   **retriever** pulls the most relevant corpus chunks from Qdrant. For a
    policy question it biases toward policy chunks; otherwise it retrieves
    across both vulns and policy so remediation answers stay policy-grounded.
*   the three **specialist** nodes share the same structured-output contract
    but differ in system prompt, so each "agent" reasons with the right frame
    (fix-it steps vs. risk ranking vs. policy interpretation).

Every node takes its dependencies (vector store, llm client, settings) via a
factory closure, so nodes stay pure `state -> state` functions and the graph
is trivially testable with a FakeLLMClient + in-memory store.
"""

from __future__ import annotations

from typing import Callable

from ..config import Settings
from ..llm import LLMClient, parse_and_validate
from ..schema import QueryIntent, RetrievedChunk
from ..vectorstore import VectorStore
from .state import GraphState

NodeFn = Callable[[GraphState], GraphState]

_REMEDIATION_HINTS = ("remediat", "fix", "patch", "how do i", "how to", "resolve", "mitigat")
_PRIORITIZATION_HINTS = ("prioriti", "which first", "most critical", "risk", "worst", "urgent", "triage")
_POLICY_HINTS = ("policy", "sla", "standard", "compliance", "required", "deadline", "how long")


def _append_trace(state: GraphState, line: str) -> list[str]:
    return [*state.get("trace", []), line]


def make_router(llm: LLMClient) -> NodeFn:
    def router(state: GraphState) -> GraphState:
        q = state["query"].lower()
        intent = _heuristic_intent(q)
        if intent is None:
            intent = _llm_intent(llm, state["query"])
        return {"intent": intent, "trace": _append_trace(state, f"router -> {intent}")}

    return router


def _heuristic_intent(q: str) -> str | None:
    scores = {
        QueryIntent.POLICY.value: sum(h in q for h in _POLICY_HINTS),
        QueryIntent.PRIORITIZATION.value: sum(h in q for h in _PRIORITIZATION_HINTS),
        QueryIntent.REMEDIATION.value: sum(h in q for h in _REMEDIATION_HINTS),
    }
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else None


def _llm_intent(llm: LLMClient, query: str) -> str:
    system = (
        "You are a router. Classify the analyst's question into exactly one intent: "
        "remediation, prioritization, policy, or general. Put the single word in the "
        "'summary' field and leave the other fields empty."
    )
    try:
        raw = llm.generate_answer(system, f"Question: {query}")
        candidate = str(raw.get("summary", "")).strip().lower()
        return candidate if candidate in {i.value for i in QueryIntent} else QueryIntent.GENERAL.value
    except Exception:
        return QueryIntent.GENERAL.value


def make_retriever(store: VectorStore, settings: Settings) -> NodeFn:
    def retriever(state: GraphState) -> GraphState:
        intent = state.get("intent", QueryIntent.GENERAL.value)
        query = state["query"]
        if intent == QueryIntent.POLICY.value:
            retrieved = store.search(query, top_k=settings.top_k, kind="policy")
        else:
            # Blend vuln + policy so answers cite the SLA/standard they invoke.
            half = max(1, settings.top_k // 2)
            vulns = store.search(query, top_k=settings.top_k - half, kind="vulnerability")
            policies = store.search(query, top_k=half, kind="policy")
            retrieved = _dedup(vulns + policies)
        return {
            "retrieved": retrieved,
            "trace": _append_trace(state, f"retriever -> {len(retrieved)} chunks"),
        }

    return retriever


def _dedup(chunks: list[RetrievedChunk]) -> list[RetrievedChunk]:
    seen: set[str] = set()
    out: list[RetrievedChunk] = []
    for c in sorted(chunks, key=lambda x: x.score, reverse=True):
        if c.chunk_id not in seen:
            seen.add(c.chunk_id)
            out.append(c)
    return out


_BASE_RULES = (
    "Ground every claim in the retrieved context below. Cite the chunk_ids you "
    "relied on in cited_chunk_ids -- only chunk_ids that appear in the context, "
    "never invented ones. If the context does not answer the question, say so in "
    "the summary rather than guessing. Respond only by calling the submit_answer tool."
)

_SYSTEM_PROMPTS = {
    QueryIntent.REMEDIATION.value: (
        "You are a vulnerability-remediation assistant for a SOC analyst. Given "
        "vulnerability findings and security-policy context, produce concrete, "
        "ordered remediation steps and a short prioritization rationale. " + _BASE_RULES
    ),
    QueryIntent.PRIORITIZATION.value: (
        "You are a vulnerability-prioritization assistant for a SOC analyst. Rank the "
        "retrieved findings by real-world risk using severity, CVSS, VPR, host "
        "exposure, and any policy SLA in the context. Put the ranked reasoning in "
        "prioritization_rationale and the recommended order-of-operations in "
        "remediation_steps. " + _BASE_RULES
    ),
    QueryIntent.POLICY.value: (
        "You are a security-policy assistant for a SOC analyst. Answer using the "
        "retrieved policy/standard text: quote the relevant requirement, SLA, or "
        "owner. " + _BASE_RULES
    ),
    QueryIntent.GENERAL.value: (
        "You are a vulnerability-management assistant for a SOC analyst. Answer the "
        "question using the retrieved context. " + _BASE_RULES
    ),
}


def _format_context(chunks: list[RetrievedChunk]) -> str:
    if not chunks:
        return "(no context retrieved)"
    return "\n\n---\n\n".join(c.document for c in chunks)


def make_specialist(llm: LLMClient) -> NodeFn:
    """A single specialist node whose behaviour is selected by intent -- the
    graph routes here after retrieval. Framed as one node with intent-specific
    prompts rather than three near-identical nodes."""

    def specialist(state: GraphState) -> GraphState:
        intent = state.get("intent", QueryIntent.GENERAL.value)
        chunks = state.get("retrieved", [])
        system = _SYSTEM_PROMPTS.get(intent, _SYSTEM_PROMPTS[QueryIntent.GENERAL.value])
        user = (
            f"## Analyst question\n{state['query']}\n\n"
            f"## Retrieved context\n{_format_context(chunks)}\n"
        )
        raw = llm.generate_answer(system, user)
        allowed = {c.chunk_id for c in chunks}
        answer = parse_and_validate(raw, allowed)
        return {
            "answer": answer.model_dump(),
            "trace": _append_trace(state, f"specialist[{intent}] -> answered"),
        }

    return specialist
