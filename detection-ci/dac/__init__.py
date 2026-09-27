"""
dac -- Detection-as-Code validation for a detection repository.

Discovers detection content (Sigma rules, Microsoft Defender custom detection
rules, Microsoft Sentinel analytics rules) and runs a battery of static checks
on it -- structure, required fields, MITRE ATT&CK tagging, and KQL sanity -- so
a CI job can gate every pull request that touches a detection. Self-contained:
the only third-party dependency is PyYAML.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
