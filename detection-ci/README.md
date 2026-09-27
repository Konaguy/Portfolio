# Detection-as-Code CI

A validation gate that treats detections like code: every change to a Sigma,
Microsoft Defender, or Microsoft Sentinel rule is parsed and checked in CI before
it can merge, so a broken detection never reaches production.

The GitHub Actions workflow ([`.github/workflows/detection-ci.yml`](../.github/workflows/detection-ci.yml))
runs on any PR that touches detection content and fails the build on error-level
findings — with the problems annotated inline on the PR's Files-changed view.

## What it checks

| Source | Checks |
|---|---|
| **Sigma** (`.yml`) | required fields (title/logsource/detection), valid `status` & `level`, a `condition` that only references search identifiers that exist, well-formed ATT&CK tags (`attack.tNNNN[.NNN]`), and a UUID `id` |
| **Defender** custom detection rules (`.json`) | `displayName`, valid severity, well-formed `mitreTechniques`, and a KQL `queryText` that passes the KQL checks below |
| **Sentinel** analytics rules (`.yaml`) | `name`, valid severity, well-formed `relevantTechniques`, and a KQL `query` that passes the KQL checks below |
| **KQL** (both platforms) | starts with a known Defender/Sentinel table, balanced parens/brackets/quotes, actually filters (`where`/`summarize`), and contains no control/management commands |

Findings have three severities: **error** fails the build, **warning** and
**info** are advisory (use `--strict` to fail on warnings too).

## Run it locally

```bash
pip install -r requirements.txt

# Validate this repo's detections (from anywhere in the repo):
python -m dac.cli --repo

# Validate specific paths; emit GitHub annotations; write a JSON report:
python -m dac.cli --path some/rules --format github --json-out dac-report.json

# Fail on warnings too:
python -m dac.cli --repo --strict

pytest        # 21 tests, fully offline
```

Example run against this repo's detections:

```
Detection-as-Code validation
  files checked : 3
  rules checked : 31
  errors        : 0
  warnings      : 0
Result: PASS
```

## The pipeline

Three jobs run in parallel on each PR:

1. **validate-detections** — the gate above; uploads a JSON report artifact.
2. **unit-tests** — the DAC library's own test suite.
3. **coverage-report** *(informational)* — if the `attack-coverage-tracker`
   project is present, regenerates the ATT&CK coverage report and Navigator
   layer and uploads them as artifacts, so every merge refreshes the coverage
   picture. Skips cleanly when the tracker isn't in the checkout.

## Layout

```
dac/
  report.py     Finding / Report + text, JSON, and GitHub-annotation renderers
  kql.py        KQL sanity checks + known Defender/Sentinel table catalog
  sigma.py      Sigma rule linter
  rules.py      Defender (JSON) + Sentinel (YAML) rule validators
  discover.py   classify files by content and run the right validator
  cli.py        the gate (exit non-zero on error findings)
tests/          21 tests + good/bad rule fixtures
../.github/workflows/detection-ci.yml   the pipeline
```

Self-contained: the only third-party dependency is PyYAML.

## Where this fits in the portfolio

This is the CI backbone under the detection-authoring projects
(`security-automation-soar`, `sigma-rule-translator`) and the `threat-intel-to-kql`
generator: they produce detections, the `attack-coverage-tracker` measures what
they cover, and this makes every change to them prove itself before it merges.
