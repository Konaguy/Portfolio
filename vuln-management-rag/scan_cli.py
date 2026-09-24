"""
Scan the configured devices via Microsoft Defender Vulnerability Management,
ingest the findings into Qdrant (so the RAG bot can answer questions about
them), and write dashboard/findings.json for the dashboard.

    # Live scan (needs AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
    # and the devices onboarded to Defender for Endpoint):
    python scan_cli.py --devices srv-web-01 srv-sql-01 pc-hr-07 pc-eng-12

    # Offline demo against the bundled sample findings (no Azure needed):
    python scan_cli.py --sample

Findings are written to dashboard/findings.json by default; open
dashboard/index.html to view them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulnrag.config import Settings
from vulnrag.connectors import DefenderConnector, FakeDefenderConnector
from vulnrag.connectors.defender import findings_to_vulnerabilities
from vulnrag.embeddings import build_embedder
from vulnrag.export import build_findings_document
from vulnrag.vectorstore import VectorStore

_HERE = Path(__file__).parent
_SAMPLE = _HERE / "data" / "sample_defender_findings.json"
_DEFAULT_OUT = _HERE / "dashboard" / "findings.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan devices via Defender MDVM and build the dashboard data.")
    parser.add_argument("--devices", nargs="*", help="Device names to scan (default: all returned)")
    parser.add_argument("--sample", action="store_true", help="Use bundled sample findings (no Azure)")
    parser.add_argument("--out", default=str(_DEFAULT_OUT), help="Path to write findings.json")
    parser.add_argument("--no-ingest", action="store_true", help="Skip upserting into Qdrant")
    args = parser.parse_args(argv)

    if args.sample:
        connector = FakeDefenderConnector.from_json_file(str(_SAMPLE))
        print("Using bundled sample findings (offline).")
    else:
        connector = DefenderConnector()  # reads AZURE_* env vars
        print("Querying Microsoft Defender Vulnerability Management...")

    raw = connector.get_findings(args.devices)
    vulns = findings_to_vulnerabilities(raw)
    print(f"Retrieved {len(vulns)} findings across {len({v.host for v in vulns})} device(s).")

    if not args.no_ingest:
        settings = Settings.from_env()
        store = VectorStore(settings, build_embedder(settings))
        n = store.upsert_vulnerabilities(vulns)
        print(f"Ingested {n} findings into Qdrant collection '{settings.qdrant_collection}'.")

    doc = build_findings_document(vulns)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"Wrote dashboard data to {out_path}")
    print("Open dashboard/index.html to view the findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
