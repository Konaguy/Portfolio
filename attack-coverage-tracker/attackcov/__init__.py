"""
attackcov -- map a repository's detections to the MITRE ATT&CK matrix and report
coverage.

Parses detection content (Microsoft Defender custom detection rules, Sentinel
analytics rules, and Sigma rules), extracts the ATT&CK techniques each one
addresses, and produces (a) a coverage model / JSON for the dashboard and (b) an
ATT&CK Navigator layer you can load into the official navigator.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
