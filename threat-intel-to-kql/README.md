# Threat Intel → KQL Translator

Turn raw threat intelligence — a CVE advisory, a vendor report, a STIX/MISP
feed, or a plain IOC list — into **validated Microsoft Defender hunting
queries** (KQL), automatically.

```
$ python -m ti2kql.cli --input advisory.txt
# Hunt for indicators from advisory.txt
## File hash hunt  (DeviceFileEvents)
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ ("702421bcee1785...", "387cee566aedbafa...")
    | project Timestamp, DeviceName, SHA256
...
```

## Why this exists

When a threat report lands, an analyst's first job is "are we seeing any of
this?" — which means turning the report's indicators into hunting queries for
whatever platform they run. That translation is repetitive and error-prone by
hand. This tool does it: it pulls the indicators out of the intel, has an LLM
write the KQL, and then **validates that KQL before an analyst ever sees it.**

The design splits the work between what each part is good at:

- **Deterministic where precision matters.** IOC extraction is done with
  regex, not the LLM — a hash that's wrong by one character makes a hunt
  useless. This also handles defanged indicators (`hxxp`, `1.2.3[.]4`,
  `user[at]evil[.]com`) and avoids double-counting a SHA-256 as an MD5.
- **LLM where judgement helps.** Claude turns the extracted indicators into
  well-formed, grouped KQL against the right Defender tables, with a rationale
  per query. It is given the table schema to ground it and told to hunt *only*
  for the provided IOCs.
- **Validated before it's trusted.** Every generated query is checked
  statically: it must start with a real Defender table, balance its
  parens/quotes, contain a `where` filter, avoid control commands, and
  actually reference a source IOC. The hunt's declared `iocs_used` must be a
  subset of the indicators found in the intel — a fabricated indicator is a
  hard failure, not a warning.

## How is this different from `sigma-rule-translator`?

Both emit KQL, but they solve opposite halves of the problem:

| | `sigma-rule-translator` | `threat-intel-to-kql` (this) |
|---|---|---|
| **Input** | A structured Sigma rule (YAML) | Unstructured intel: reports, CVE text, STIX/MISP/CSV |
| **Method** | Deterministic AST translation (pySigma) | IOC extraction + LLM synthesis + validation |
| **Job** | Port one authored detection across backends | Generate fresh hunts from indicators you were just handed |

Use the Sigma translator when you already have a detection written; use this
when you have a fresh report full of indicators and no queries yet.

## Architecture

```
raw intel ──► feeds.py / iocs.py ──► ThreatIntel (raw_text + typed IOCs)
                                          │
                                          ▼
                     prompts.py ──► LLM (llm.py, forced tool-use)
                                          │
                                          ▼
                                    GeneratedHunt
                                          │
                                          ▼
              validate.py: schema + Defender table catalog + IOC grounding
                                          │
                                          ▼
                             validated KQL  (cli.py renders MD/KQL)
```

## Layout

```
ti2kql/
  schema.py      Pydantic models (IOC, ThreatIntel, HuntQuery, GeneratedHunt)
  iocs.py        deterministic IOC extraction + refanging
  feeds.py       loaders: text / CSV / STIX 2.x / MISP
  tables.py      Defender advanced-hunting table + column catalog
  prompts.py     system prompt (schema-grounded) + user-message builder
  llm.py         forced tool-use client + offline FakeLLMClient
  validate.py    static KQL validation + IOC-grounding guard
  translator.py  orchestration: extract -> generate -> validate
  cli.py         command-line entry point (Markdown or KQL-only output)
data/            sample CVE advisory, IOC CSV, STIX bundle
tests/           27 tests, all offline (no API key required)
```

## Quickstart

```bash
pip install -r requirements.txt

# Run the tests (fully offline)
pytest

# Generate hunts from the bundled sample advisory. With no ANTHROPIC_API_KEY
# it uses the offline deterministic generator so you can see the whole
# pipeline; set the key for Claude-authored queries.
python -m ti2kql.cli --input data/sample_cve.txt

# Other formats (auto-detected, or force with --format)
python -m ti2kql.cli --input data/sample_stix.json
python -m ti2kql.cli --input data/sample_iocs.csv --kql-only

# Or pipe intel in:
cat advisory.txt | python -m ti2kql.cli

# With Claude:
export ANTHROPIC_API_KEY=sk-ant-...
python -m ti2kql.cli --input advisory.txt
```

## What it extracts

IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256 hashes, CVE IDs, email addresses,
Windows file paths, and registry keys — with defanging handled and common
infrastructure domains (microsoft.com, mitre.org, …) filtered out as noise.

## Supported Defender tables

`DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceFileEvents`,
`DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceEvents`,
`DeviceLogonEvents`, `DeviceTvmSoftwareVulnerabilities`, `EmailEvents`,
`EmailUrlInfo`, `EmailAttachmentInfo`, `IdentityLogonEvents`,
`IdentityDirectoryEvents`, `UrlClickEvents`, and more (see `tables.py`). The
validator rejects queries against tables outside this catalog unless
`TI2KQL_STRICT_TABLES=0`.

## Notes and limitations

- Static validation confirms KQL *shape and grounding*, not that a query is
  optimal or that it runs against your exact schema version — treat generated
  hunts as a strong first draft to review, not final detections.
- Forced `tool_choice` is used for structured output (supported on
  `claude-opus-5`); on `claude-opus-5-5` / the Fable family, use structured
  outputs (`output_config.format`) instead.
- The offline generator is deterministic and covers the common IOC→table
  mappings; the Claude path produces richer, better-reasoned queries.

## Where this fits in the portfolio

This is the "fresh indicators → hunts" counterpart to `sigma-rule-translator`
(authored rule → backends) and feeds the same SOC the `security-automation-soar`
detections and the `llm-soc-copilot` triage assistant serve.
