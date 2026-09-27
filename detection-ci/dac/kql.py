"""
Minimal KQL sanity checks for detection queries.

This is a static linter, not a query engine: it confirms a query starts with a
known Microsoft Defender / Sentinel table, balances its brackets and quotes,
actually filters (`where`/`summarize`), and contains no control/management
commands. Enough to catch the mistakes that would make a rule fail at deploy
time, without a live cluster.
"""

from __future__ import annotations

import re

# Common Defender XDR + Sentinel tables detection queries start from.
KNOWN_TABLES: set[str] = {
    # Defender XDR advanced hunting
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
    "DeviceRegistryEvents", "DeviceImageLoadEvents", "DeviceEvents",
    "DeviceLogonEvents", "DeviceInfo", "DeviceNetworkInfo",
    "DeviceTvmSoftwareVulnerabilities", "EmailEvents", "EmailUrlInfo",
    "EmailAttachmentInfo", "IdentityLogonEvents", "IdentityDirectoryEvents",
    "IdentityQueryEvents", "UrlClickEvents", "AADSignInEventsBeta", "CloudAppEvents",
    # Sentinel / Azure Monitor
    "SigninLogs", "AuditLogs", "SecurityEvent", "Syslog", "CommonSecurityLog",
    "AzureActivity", "OfficeActivity", "DeviceEvents", "SecurityAlert",
    "AADNonInteractiveUserSignInLogs", "W3CIISLog", "DnsEvents",
}

_TABLE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")
_CONTROL_RE = re.compile(r"\.(?:drop|set|append|delete|create|alter|ingest)\b", re.IGNORECASE)


def _balanced(text: str) -> bool:
    pairs = {")": "(", "]": "["}
    stack: list[str] = []
    in_str: str | None = None
    for ch in text:
        if in_str:
            if ch == in_str:
                in_str = None
            continue
        if ch in {'"', "'"}:
            in_str = ch
        elif ch in "([":
            stack.append(ch)
        elif ch in ")]":
            if not stack or stack.pop() != pairs[ch]:
                return False
    return in_str is None and not stack


def check_kql(kql: str, strict_tables: bool = True) -> list[str]:
    """Return a list of problems with a KQL query (empty == clean)."""
    problems: list[str] = []
    q = (kql or "").strip()
    if not q:
        return ["query is empty"]

    m = _TABLE_RE.match(q)
    table = m.group(1) if m else None
    if not table:
        problems.append("query does not start with a table name")
    elif strict_tables and table not in KNOWN_TABLES:
        problems.append(f"unknown table {table!r} (not in the Defender/Sentinel catalog)")

    if not _balanced(q):
        problems.append("unbalanced parentheses/brackets/quotes")

    if not re.search(r"\|\s*(where|summarize|where\b)", q, re.IGNORECASE) and "where" not in q.lower():
        problems.append("query has no 'where'/'summarize' — would scan the whole table")

    if _CONTROL_RE.search(q):
        problems.append("query contains a control/management command, not a read-only detection")

    return problems
