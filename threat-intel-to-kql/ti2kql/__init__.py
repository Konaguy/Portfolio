"""
ti2kql -- turn raw threat intelligence into Microsoft Defender hunting queries.

Consumes unstructured threat-intel reports, CVE descriptions, or IOC feeds,
extracts indicators deterministically, and uses Claude to synthesize
actionable KQL hunting queries for Microsoft Defender advanced hunting -- then
validates the generated KQL against a real table catalog and checks that every
IOC the query hunts for was actually present in the source intel.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
