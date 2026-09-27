"""
Chainlit frontend.

    chainlit run app.py

On chat start it builds the agent graph (pointing at the configured Qdrant),
and if the collection is empty it auto-ingests the bundled sample data so the
demo works with zero setup. Each analyst message is run through the graph and
the structured answer is rendered with its citations and the router/retriever
trace.

Chainlit and the Anthropic SDK are imported lazily/at module load so the core
`vulnrag` package (and its tests) don't depend on them.
"""

from __future__ import annotations

import os
from pathlib import Path

import chainlit as cl

from vulnrag.agents.graph import VulnRagGraph
from vulnrag.config import Settings
from vulnrag.embeddings import build_embedder
from vulnrag.ingest import parse_policy_dir, parse_tenable_file
from vulnrag.llm import ClaudeClient, FakeLLMClient
from vulnrag.vectorstore import VectorStore

_DATA = Path(__file__).parent / "data"


def _build_llm(settings: Settings):
    # Fall back to the offline FakeLLMClient if no API key is configured, so
    # the UI is still demonstrable without credentials.
    if os.getenv("ANTHROPIC_API_KEY"):
        return ClaudeClient(model=settings.anthropic_model, max_tokens=settings.max_tokens)
    return FakeLLMClient()


def _bootstrap_corpus(store: VectorStore) -> None:
    if store.count() > 0:
        return
    tenable = _DATA / "sample_tenable_export.csv"
    policies = _DATA / "sample_policies"
    if tenable.exists():
        store.upsert_vulnerabilities(parse_tenable_file(tenable))
    if policies.exists():
        store.upsert_policies(parse_policy_dir(policies))


@cl.on_chat_start
async def on_chat_start() -> None:
    settings = Settings.from_env()
    store = VectorStore(settings, build_embedder(settings))
    _bootstrap_corpus(store)
    graph = VulnRagGraph.from_settings(settings, _build_llm(settings), store=store)
    cl.user_session.set("graph", graph)

    using_llm = "Claude (%s)" % settings.anthropic_model if os.getenv("ANTHROPIC_API_KEY") else "offline stub"
    await cl.Message(
        content=(
            "**Vulnerability Management RAG Assistant**\n\n"
            f"Corpus: {store.count()} chunks · LLM: {using_llm}\n\n"
            "Ask me things like:\n"
            "- *How do I remediate the log4j findings on the DMZ hosts?*\n"
            "- *Which of the critical findings should I patch first?*\n"
            "- *What's our SLA for patching critical vulnerabilities?*"
        )
    ).send()


@cl.on_message
async def on_message(message: cl.Message) -> None:
    graph: VulnRagGraph = cl.user_session.get("graph")
    final = await cl.make_async(graph.answer)(message.content)
    answer = final["answer"]

    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(answer["remediation_steps"], 1))
    citations = ", ".join(answer["cited_chunk_ids"]) or "(none)"
    trace = " → ".join(final.get("trace", []))

    body = (
        f"{answer['summary']}\n\n"
        f"**Remediation steps**\n{steps or '(none)'}\n\n"
        f"**Prioritization**\n{answer['prioritization_rationale'] or '(none)'}\n\n"
        f"**Citations:** {citations}\n\n"
        f"_trace: {trace}_"
    )
    await cl.Message(content=body).send()
