"""
CLI for translating a Sigma rule file into Sentinel/Defender KQL and/or
CrowdStrike Falcon Event Search query syntax.

Usage:
    python translator/cli.py rules/example.yml --target sentinel
    python translator/cli.py rules/example.yml --target falcon
    python translator/cli.py rules/example.yml --target all
"""

from __future__ import annotations

import click
from sigma.collection import SigmaCollection
from sigma.backends.microsoft365defender import KustoBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline

from falcon_backend import FalconBackend, falcon_pipeline


def _load_rules(path: str) -> SigmaCollection:
    """
    Parse a fresh SigmaCollection from disk.

    IMPORTANT: pySigma's processing pipelines mutate SigmaRule objects
    in place (field names get rewritten during conversion). Converting
    the *same* SigmaCollection object through two backends back-to-back
    silently reuses whatever the first backend's pipeline already
    rewrote -- e.g. converting to Sentinel first would leave 'Image'
    renamed to 'FolderPath' by the time the Falcon backend tries to map
    it, and the Falcon field-mapping table (which expects the original
    'Image' field name) would then silently fail to apply.
    A fresh parse per backend avoids this entirely.
    """
    with open(path, "r", encoding="utf-8") as f:
        return SigmaCollection.from_yaml(f.read())


def to_sentinel(rule_path: str) -> list[str]:
    backend = KustoBackend(processing_pipeline=microsoft_365_defender_pipeline())
    return backend.convert(_load_rules(rule_path))


def to_falcon(rule_path: str) -> list[str]:
    backend = FalconBackend(processing_pipeline=falcon_pipeline())
    return backend.convert(_load_rules(rule_path))


@click.command()
@click.argument("rule_path", type=click.Path(exists=True))
@click.option(
    "--target",
    type=click.Choice(["sentinel", "falcon", "all"]),
    default="all",
    help="Which backend(s) to translate to.",
)
def main(rule_path: str, target: str) -> None:
    if target in ("sentinel", "all"):
        click.secho("=== Sentinel / Defender (KQL) ===", fg="cyan", bold=True)
        for query in to_sentinel(rule_path):
            click.echo(query)
        click.echo()

    if target in ("falcon", "all"):
        click.secho("=== CrowdStrike Falcon (Event Search) ===", fg="cyan", bold=True)
        for query in to_falcon(rule_path):
            click.echo(query)
        click.echo()


if __name__ == "__main__":
    main()
