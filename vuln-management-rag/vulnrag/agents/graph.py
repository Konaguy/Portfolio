"""
Assemble the nodes into a LangGraph state machine and wrap it in a small
facade (`VulnRagGraph`) that the Chainlit app and the tests both call.

    router --(conditional on intent)--> retriever --> specialist --> END

The conditional edge after the router is cosmetic in the current wiring (all
intents go through the same retriever -> specialist path, and the intent
drives behaviour inside those nodes), but it's wired as a real conditional so
the graph is easy to extend with intent-specific branches (e.g. a dedicated
CVE-enrichment agent for remediation) without restructuring.
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from ..config import Settings
from ..embeddings import build_embedder
from ..llm import LLMClient
from ..schema import RemediationAnswer
from ..vectorstore import VectorStore
from .nodes import make_retriever, make_router, make_specialist
from .state import GraphState


def build_graph(store: VectorStore, llm: LLMClient, settings: Settings):
    """Compile the LangGraph app. Returns a compiled graph you can .invoke()."""
    router = make_router(llm)
    retriever = make_retriever(store, settings)
    specialist = make_specialist(llm)

    builder = StateGraph(GraphState)
    builder.add_node("router", router)
    builder.add_node("retriever", retriever)
    builder.add_node("specialist", specialist)

    builder.set_entry_point("router")
    builder.add_conditional_edges(
        "router",
        lambda state: state.get("intent", "general"),
        {
            "remediation": "retriever",
            "prioritization": "retriever",
            "policy": "retriever",
            "general": "retriever",
        },
    )
    builder.add_edge("retriever", "specialist")
    builder.add_edge("specialist", END)
    return builder.compile()


class VulnRagGraph:
    """Convenience facade: build the store/embedder/graph from settings and
    expose a single `answer()` method."""

    def __init__(self, store: VectorStore, llm: LLMClient, settings: Settings) -> None:
        self._settings = settings
        self._store = store
        self._graph = build_graph(store, llm, settings)

    @classmethod
    def from_settings(
        cls, settings: Settings, llm: LLMClient, store: VectorStore | None = None
    ) -> "VulnRagGraph":
        if store is None:
            store = VectorStore(settings, build_embedder(settings))
        return cls(store, llm, settings)

    @property
    def store(self) -> VectorStore:
        return self._store

    def answer(self, query: str) -> dict:
        """Run the graph and return the full final state (answer + trace)."""
        final = self._graph.invoke({"query": query, "trace": []})
        return final

    def answer_structured(self, query: str) -> RemediationAnswer:
        final = self.answer(query)
        return RemediationAnswer(**final["answer"])
