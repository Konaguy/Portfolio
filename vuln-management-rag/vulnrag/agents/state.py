"""
The state object that flows through the agent graph.

LangGraph nodes are functions `state -> partial state`; the graph merges each
node's returned dict into the running state. Keeping this a plain TypedDict
(rather than a Pydantic model) matches LangGraph's expectations and keeps the
merge semantics obvious.
"""

from __future__ import annotations

from typing import TypedDict

from ..schema import RetrievedChunk


class GraphState(TypedDict, total=False):
    # Input
    query: str

    # Set by the router node
    intent: str

    # Set by the retriever node
    retrieved: list[RetrievedChunk]

    # Set by a specialist node
    answer: dict  # RemediationAnswer.model_dump()

    # Diagnostics / trace, appended by nodes for observability
    trace: list[str]
