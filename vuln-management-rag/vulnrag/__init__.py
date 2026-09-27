"""
vulnrag -- a multi-agent RAG assistant for vulnerability management.

Ingests exported Tenable vulnerability reports and enterprise security
policies into a Qdrant vector store, then answers SOC-analyst questions
("how do I remediate the log4j findings on my crown-jewel hosts?") with
contextual, policy-grounded, cited answers via a LangGraph agent graph.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
