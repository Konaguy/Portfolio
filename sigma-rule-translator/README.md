# Sigma Rule Translator

A CLI tool that translates vendor-agnostic [Sigma](https://github.com/SigmaHQ/sigma)
detection rules into platform-specific query syntax — currently Microsoft
Sentinel/Defender KQL and CrowdStrike Falcon query syntax — using
[`pySigma`](https://github.com/SigmaHQ/pySigma) as the translation engine.

## Why this exists

Detection logic shouldn't be locked to one platform. Writing rules in
Sigma's vendor-neutral YAML format and translating them at deploy time
means the same detection logic can be validated once and shipped to every
backend a team runs — useful for orgs mid-migration between SIEMs, or
running EDR and SIEM detections in parallel and wanting them to agree.

## How it works

```
sigma_rule.yml  →  pySigma parser  →  backend-specific query
                                        ├── Sentinel/Defender KQL (SigmaHQ pySigma-backend-microsoft365defender)
                                        └── CrowdStrike Falcon query syntax (custom backend, see below)
```

Sigma already ships a maintained Microsoft backend
(`pysigma-backend-microsoft365defender`). CrowdStrike doesn't have an
official community backend yet, so this project includes a minimal custom
`pySigma` backend (`translator/falcon_backend.py`) implementing the
field-mapping and query-syntax conventions for Falcon's event search.

## Usage

```bash
pip install -r requirements.txt

python translator/cli.py rules/example.yml --target sentinel
python translator/cli.py rules/example.yml --target falcon
python translator/cli.py rules/example.yml --target all   # prints both
```

## Example

Input (`rules/example.yml`, a Sigma rule for encoded PowerShell):

```yaml
title: Encoded PowerShell Execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
```

Output for `--target sentinel`:

```kql
DeviceProcessEvents
| where FileName endswith @"\powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand")
```

Output for `--target falcon`:

```
event_simpleName=ProcessRollup2 FileName="*\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")
```

## Status / limitations

- Field mapping between Sigma's common taxonomy and Falcon's event schema
  is implemented for the process-creation and network-connection log
  sources used in this portfolio's detection rules. Extending it to
  registry, file, and image-load events would follow the same pattern —
  see `translator/falcon_backend.py` for the mapping table to extend.
- The Sentinel backend defers to the official `pysigma-backend-
  microsoft365defender` package rather than reimplementing it.

## Tests

```bash
pytest tests/
```

Tests validate the Falcon backend's field mapping and confirm round-trip
translation produces syntactically valid queries for both targets against
the full 15-rule set from the `security-automation-soar` project.
