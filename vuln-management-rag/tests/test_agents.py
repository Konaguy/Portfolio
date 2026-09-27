from __future__ import annotations

from vulnrag.agents.graph import VulnRagGraph
from vulnrag.agents.nodes import _heuristic_intent
from vulnrag.llm import FakeLLMClient
from vulnrag.schema import QueryIntent


def test_heuristic_router_classifies_common_questions():
    assert _heuristic_intent("how do i remediate log4j?") == QueryIntent.REMEDIATION.value
    assert _heuristic_intent("which findings should i prioritize first?") == QueryIntent.PRIORITIZATION.value
    assert _heuristic_intent("what is our patch sla policy?") == QueryIntent.POLICY.value
    assert _heuristic_intent("tell me about the weather") is None


def test_graph_end_to_end_remediation(seeded_store, settings):
    graph = VulnRagGraph.from_settings(settings, FakeLLMClient(), store=seeded_store)
    final = graph.answer("How do I remediate the log4j findings?")
    assert final["intent"] == QueryIntent.REMEDIATION.value
    assert final["retrieved"], "retriever should return context"
    assert final["answer"]["summary"]
    # trace records the pipeline: router -> retriever -> specialist
    assert any("router" in t for t in final["trace"])
    assert any("specialist" in t for t in final["trace"])


def test_graph_citations_are_grounded(seeded_store, settings):
    graph = VulnRagGraph.from_settings(settings, FakeLLMClient(), store=seeded_store)
    final = graph.answer("Which critical vulnerabilities should I patch first?")
    retrieved_ids = {c.chunk_id for c in final["retrieved"]}
    for cited in final["answer"]["cited_chunk_ids"]:
        assert cited in retrieved_ids


def test_policy_query_retrieves_policy(seeded_store, settings):
    graph = VulnRagGraph.from_settings(settings, FakeLLMClient(), store=seeded_store)
    final = graph.answer("What is our SLA for patching critical vulnerabilities?")
    assert final["intent"] == QueryIntent.POLICY.value
    assert any(c.kind == "policy" for c in final["retrieved"])


def test_structured_answer_helper(seeded_store, settings):
    graph = VulnRagGraph.from_settings(settings, FakeLLMClient(), store=seeded_store)
    answer = graph.answer_structured("How do I fix the SMBv1 finding?")
    assert answer.summary
    assert isinstance(answer.remediation_steps, list)
