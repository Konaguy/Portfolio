"""
Static validation for generated KQL hunting queries.

This is the safety net around the LLM. An LLM will occasionally invent a table
name, unbalance a parenthesis, or hunt for an indicator that wasn't in the
source. None of that should reach an analyst's console, so every generated
query is checked here before it's returned.

The checks are intentionally static (no live cluster): the first identifier
must be a known Defender table; brackets/parens/quotes must balance; the query
must actually filter (contain a `where`); and it must reference at least one of
the source IOCs. `validate_hunt` also enforces that the hunt's declared
`iocs_used` is a subset of the indicators extracted from the intel.
"""

from __future__ import annotations

import re

from .schema import GeneratedHunt, HuntQuery
from .tables import known_tables

_TABLE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")
_DESTRUCTIVE_RE = re.compile(
    r"\.(?:drop|set|append|delete|create|alter|ingest)\b", re.IGNORECASE
)


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


def validate_query(
    query: HuntQuery, ioc_values: set[str], strict_tables: bool = True
) -> list[str]:
    """Return a list of problems with a single query (empty == valid)."""
    problems: list[str] = []
    kql = query.kql.strip()

    m = _TABLE_RE.match(kql)
    table = m.group(1) if m else None
    if not table:
        problems.append("query does not start with a table name")
    elif strict_tables and table not in known_tables():
        problems.append(f"unknown Defender table: {table!r}")

    if query.table and table and query.table != table:
        problems.append(
            f"declared table {query.table!r} does not match query's first table {table!r}"
        )

    if not _balanced(kql):
        problems.append("unbalanced parentheses/brackets/quotes")

    if not re.search(r"\bwhere\b", kql, re.IGNORECASE):
        problems.append("query has no 'where' filter (would return the whole table)")

    if _DESTRUCTIVE_RE.search(kql):
        problems.append("query contains a control/management command, not a read-only hunt")

    # The query must actually hunt for one of the source indicators.
    if ioc_values and not any(v.lower() in kql.lower() for v in ioc_values):
        problems.append("query references none of the source IOCs")

    return problems


def validate_hunt(
    hunt: GeneratedHunt, ioc_values: set[str], strict_tables: bool = True
) -> list[str]:
    """Return all problems across a hunt (empty == valid)."""
    problems: list[str] = []

    lowered = {v.lower() for v in ioc_values}
    fabricated = [v for v in hunt.iocs_used if v.lower() not in lowered]
    if fabricated:
        problems.append(f"hunt uses IOCs not present in the source intel: {fabricated}")

    if not hunt.queries:
        problems.append("hunt contains no queries")

    for i, q in enumerate(hunt.queries):
        for p in validate_query(q, ioc_values, strict_tables=strict_tables):
            problems.append(f"query[{i}] ({q.name!r}): {p}")

    return problems
