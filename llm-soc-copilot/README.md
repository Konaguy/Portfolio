# LLM-Powered SOC Analyst Copilot

An alert-triage assistant that takes a raw SIEM/EDR alert, enriches it
with asset context and RAG-retrieved similar prior cases, and returns a
structured, schema-validated triage verdict (severity, false-positive
probability, recommended action, rationale, and citations back to the
prior cases it relied on) via a forced tool-use call to Claude.

## Why this exists

Most "AI SOC copilot" demos parse free-text LLM output and hope for the
best. This one is built around three things that actually matter in
production:

1. **Structured output via tool-use, not prompt-and-pray.** The model is
   given exactly one tool (`submit_triage_verdict`) with a JSON schema
   and `tool_choice` forces it to call that tool — see `copilot/triage.py`.
2. **Grounding, verified.** The model is given retrieved prior cases and
   asked to cite the ones it relied on. If it cites a `case_id` that
   wasn't actually offered to it, that's treated as a hallucination and
   rejected (`TriageParseError`), not silently accepted.
3. **An eval harness with real metrics**, not just "it seems to work" —
   precision/recall on false-positive detection, severity exact-match
   and within-one-level rates, and action match rate, against a labeled
   alert set.

## Architecture

```
Alert (JSON) ──▶ enrich_alert()
                     │
                     ├── AssetLookup: asset criticality / owner
                     └── VectorStoreBackend: RAG retrieval of similar
                         closed cases (TF-IDF cosine similarity)
                     │
                     ▼
              EnrichmentContext
                     │
                     ▼
              TriageEngine.triage()
                     │  (forced tool-use call to Claude)
                     ▼
              TriageVerdict (Pydantic-validated, citation-checked)
```

Exposed over HTTP via FastAPI (`copilot/api.py`):

```
POST /triage   { alert JSON }  ->  { TriageVerdict JSON }
GET  /health
```

## Design choices worth knowing about

- **The vector store is TF-IDF, not a hosted vector DB.** This keeps the
  whole project runnable offline with `pip install` and no external
  services — important for something a reviewer will actually try to
  run. `VectorStoreBackend` is a small protocol so swapping in
  Chroma/pgvector/a hosted embeddings API for production is a matter of
  implementing that interface, not rewriting `enrichment.py` or
  `triage.py`.
- **Asset lookup is a pluggable interface**, not hardcoded. In production
  this would call ServiceNow's CMDB API — see the `security-automation-
  soar` project in this same portfolio for that integration pattern.
- **The tool schema is hand-written, not derived from the Pydantic
  model**, so this file has no import-time coupling to Pydantic's
  JSON-schema export behavior across versions. A test
  (`test_tool_schema_matches_pydantic_model`) asserts the two stay in
  sync as the schema evolves, catching drift at test time instead of at
  runtime.

## Usage

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...

# Run the API locally
uvicorn copilot.api:app --reload

# Try it
curl -X POST http://localhost:8000/triage \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "a1",
    "source": "sentinel",
    "raw_title": "Encoded PowerShell Execution",
    "raw_description": "powershell.exe -enc launched by winword.exe",
    "entity_type": "host",
    "entity_value": "WIN-FIN-04",
    "timestamp": "2026-09-22T10:00:00Z",
    "mitre_techniques": ["T1059.001"]
  }'
```

Note: the demo app in `copilot/api.py` starts with an empty case corpus
and asset lookup (see `_vector_store` / `_asset_lookup` module globals).
Load your own closed-case corpus and asset data there, or wire it to a
real database, before relying on retrieval quality.

## Evaluation

```bash
python eval/eval_harness.py eval/sample_labeled_alerts.json
```

This runs the full pipeline (real enrichment + real LLM call) against
6 hand-labeled example alerts and prints precision/recall on
false-positive detection, severity match rates, and action match rate,
plus a list of specific misses to review. `eval/eval_harness.py`'s
`compute_metrics()` function is the testable, pure-function core (no API
calls) — see `tests/test_eval_harness.py`.

To build a real eval set: export 100-200 closed cases from your SIEM/
case-management system with their final resolution (true/false positive,
final severity, action taken), format them like
`eval/sample_labeled_alerts.json`, and hold them out from the case corpus
used for RAG retrieval (or the copilot will "recognize" its own eval set).

## Testing

```bash
pytest tests/
```

36 tests across schema validation, vector-store retrieval quality,
enrichment, the triage engine (including the hallucination-citation
guard and malformed-output rejection), the FastAPI layer, and the eval
harness's metrics computation.

## What I'd build next

- Replace the TF-IDF store with a real embeddings-based retriever
  (Voyage or Anthropic embeddings + pgvector) once there's a large enough
  case corpus for semantic similarity to meaningfully outperform TF-IDF.
- Add a feedback loop: when an analyst overrides a verdict, log the
  override as a new labeled example and periodically re-run the eval
  harness to track drift.
- Wire `update_detection_status`-style write-back into the
  `crowdstrike-rtr-toolkit` project in this portfolio, so a triage
  verdict of `close_false_positive` above a confidence threshold can
  auto-close the source detection.
