"""
Command-line entry point.

    # From a CVE description or report file (auto-detects format):
    python -m ti2kql.cli --input data/sample_cve.txt

    # From stdin:
    cat report.txt | python -m ti2kql.cli

    # From a STIX/MISP/CSV feed:
    python -m ti2kql.cli --input feed.json --format stix

Without ANTHROPIC_API_KEY it uses the offline deterministic generator, so you
can see the extract -> generate -> validate pipeline end to end with no key.
Output is Markdown by default, or KQL-only with --kql-only.
"""

from __future__ import annotations

import argparse
import os
import sys

from .config import Settings
from .feeds import from_text, load_file
from .llm import ClaudeClient, FakeLLMClient
from .schema import GeneratedHunt, ThreatIntel
from .translator import Translator


def _build_llm(intel: ThreatIntel, settings: Settings):
    if os.getenv("ANTHROPIC_API_KEY"):
        return ClaudeClient(model=settings.anthropic_model, max_tokens=settings.max_tokens)
    return FakeLLMClient(intel=intel)


def _render_markdown(hunt: GeneratedHunt, intel: ThreatIntel) -> str:
    out = [f"# {hunt.title}", ""]
    if hunt.description:
        out += [hunt.description, ""]
    out += [f"**Source:** {intel.source} · **IOCs extracted:** {len(intel.iocs)}", ""]
    if hunt.mitre_techniques:
        out += [f"**MITRE ATT&CK:** {', '.join(hunt.mitre_techniques)}", ""]
    for q in hunt.queries:
        out += [f"## {q.name}  (`{q.table}`)"]
        if q.rationale:
            out += [f"_{q.rationale}_", ""]
        out += ["```kql", q.kql.strip(), "```", ""]
    if hunt.iocs_used:
        out += [f"**IOCs hunted:** {', '.join(hunt.iocs_used)}", ""]
    if hunt.caveats:
        out += [f"> **Caveats:** {hunt.caveats}", ""]
    return "\n".join(out)


def _render_kql_only(hunt: GeneratedHunt) -> str:
    blocks = []
    for q in hunt.queries:
        blocks.append(f"// {q.name} ({q.table})\n{q.kql.strip()}")
    return "\n\n".join(blocks)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Translate threat intel into Defender KQL hunts.")
    parser.add_argument("--input", help="Path to intel file (default: read stdin)")
    parser.add_argument(
        "--format",
        default="auto",
        choices=["auto", "text", "csv", "stix", "misp"],
        help="Input format (default: auto-detect)",
    )
    parser.add_argument("--kql-only", action="store_true", help="Emit KQL only, no Markdown")
    args = parser.parse_args(argv)

    if args.input:
        intel = load_file(args.input, fmt=args.format)
    else:
        text = sys.stdin.read()
        intel = from_text(text, source="stdin")

    if not intel.iocs:
        print("No IOCs found in the input.", file=sys.stderr)
        return 2

    settings = Settings.from_env()
    translator = Translator(_build_llm(intel, settings), settings)
    hunt = translator.translate(intel)

    print(_render_kql_only(hunt) if args.kql_only else _render_markdown(hunt, intel))
    return 0


if __name__ == "__main__":
    sys.exit(main())
