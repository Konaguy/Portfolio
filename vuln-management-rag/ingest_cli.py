"""
CLI to ingest a Tenable CSV export and/or a directory of policy documents
into the configured Qdrant collection.

    python ingest_cli.py --tenable data/sample_tenable_export.csv \
                         --policies data/sample_policies

Run it against the docker-compose Qdrant (QDRANT_URL=http://localhost:6333)
to build a persistent corpus the Chainlit app can query.
"""

from __future__ import annotations

import argparse
import sys

from vulnrag.config import Settings
from vulnrag.embeddings import build_embedder
from vulnrag.ingest import parse_policy_dir, parse_tenable_file
from vulnrag.vectorstore import VectorStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest vuln reports / policies into Qdrant.")
    parser.add_argument("--tenable", help="Path to a Tenable/Nessus CSV export")
    parser.add_argument("--policies", help="Path to a directory of policy .md/.txt files")
    args = parser.parse_args(argv)

    if not args.tenable and not args.policies:
        parser.error("provide at least one of --tenable or --policies")

    settings = Settings.from_env()
    store = VectorStore(settings, build_embedder(settings))
    print(f"Qdrant: {settings.qdrant_url} | collection: {settings.qdrant_collection}")

    if args.tenable:
        vulns = parse_tenable_file(args.tenable)
        n = store.upsert_vulnerabilities(vulns)
        print(f"Ingested {n} vulnerability findings from {args.tenable}")

    if args.policies:
        chunks = parse_policy_dir(args.policies)
        n = store.upsert_policies(chunks)
        print(f"Ingested {n} policy chunks from {args.policies}")

    print(f"Collection now holds {store.count()} points.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
