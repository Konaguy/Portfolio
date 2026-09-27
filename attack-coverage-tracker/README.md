# ATT&CK Coverage Tracker

Maps the detections in this portfolio to the **MITRE ATT&CK** matrix and reports
where the coverage is — and where the gaps are. It parses the actual detection
content (Microsoft Defender custom detection rules, Microsoft Sentinel analytics
rules, and Sigma rules), extracts the ATT&CK techniques each one addresses, and
produces two things:

1. an **ATT&CK Navigator layer** (`navigator-layer.json`) you can load into the
   official [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), and
2. a **self-contained coverage dashboard** (`dashboard/index.html`) — a heatmap
   matrix, per-tactic coverage, and the full detection-to-technique mapping.

## Why this exists

Most detection portfolios show a pile of rules. The harder, more senior question
is *what do these rules actually cover, and what don't they?* This tool answers
that by reading the detections already in the repo — it isn't a separate list you
have to keep in sync. Point it at the detection directories and it tells you the
coverage story, honestly including the gaps.

It's the connective tissue for the rest of the portfolio: it consumes the
`security-automation-soar` rules and the `sigma-rule-translator` rules rather
than sitting beside them.

## What it reads

| Source | Format | Techniques from |
|---|---|---|
| Microsoft Defender custom detection rules | JSON | `detectionAction.alertTemplate.mitreTechniques` |
| Microsoft Sentinel analytics rules | YAML | each rule's `relevantTechniques` |
| Sigma rules | YAML | `tags:` (`attack.tXXXX[.yyy]`) |

Technique IDs are normalized (`T1059.001`), sub-techniques roll up to their
parent for coverage, and a regex sweep backs up the structured parse so a
technique mentioned only in prose is still counted. A JSON/YAML file in the tree
that isn't a detection is skipped, not fatal.

## Quickstart

```bash
pip install -r requirements.txt
pytest                       # 14 tests, fully offline

# Scan this portfolio's real detections (from the repo root or anywhere):
python -m attackcov.cli --repo

# Or run standalone against the bundled sample rule set:
python -m attackcov.cli --sample

# Or point it at any directories/files:
python -m attackcov.cli --path /path/to/rules --path other-rule.yml
```

This writes `dashboard/coverage.json` and `navigator-layer.json`, and prints a
summary:

```
Parsed 31 detections (defender: 15, sentinel: 15, sigma: 1).
Covered 18 techniques across 9/14 tactics (26.7% of the catalog).
```

### View the dashboard

```bash
# regenerate the embedded snapshot after a scan, then open the page
python scripts/build_dashboard.py
open dashboard/index.html
```

The dashboard fetches `coverage.json` when served and falls back to an embedded
snapshot so it renders standalone. It's theme-aware (light/dark) and the matrix
scrolls horizontally to fit all 14 tactics.

### View in the official Navigator

Load `navigator-layer.json` into <https://mitre-attack.github.io/attack-navigator/>
(Open Existing Layer → Upload). Techniques are scored by detection count, so
denser coverage reads darker.

## Layout

```
attackcov/
  attack_data.py   bundled ATT&CK catalog (14 tactics + curated techniques)
  parsers.py       Defender JSON / Sentinel YAML / Sigma YAML -> Detection
  coverage.py      build the coverage model (per-technique, per-tactic rollups)
  navigator.py     emit an ATT&CK Navigator layer
  cli.py           scan -> coverage.json + navigator-layer.json
scripts/
  build_dashboard.py   inject coverage.json into the standalone dashboard
data/sample_rules/     one of each source format, for --sample
dashboard/             index.html + coverage.json
tests/                 14 tests, all offline
```

## A note on the catalog

`attack_data.py` ships a **curated snapshot** of the ATT&CK Enterprise matrix —
the 14 tactics and a representative set of techniques, including every technique
referenced by this portfolio's detections. It's enough for a meaningful coverage
denominator and a credible matrix, but it is not the full 600+ technique set. The
parser, coverage, navigator, and dashboard code are all independent of catalog
size, so swapping in the full matrix (regenerated from the official MITRE CTI
STIX bundle) changes only that one file. ATT&CK and the technique IDs are
© The MITRE Corporation, used under the ATT&CK Terms of Use.

## Where this fits in the portfolio

The measurement layer over the detection-authoring projects
(`security-automation-soar`, `sigma-rule-translator`, `threat-intel-to-kql`):
they produce detections; this says how much of the adversary playbook those
detections actually cover.
