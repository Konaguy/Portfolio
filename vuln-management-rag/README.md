# Vulnerability Management RAG Assistant

A multi-agent chatbot that lets a SOC analyst ask natural-language questions
about their vulnerability posture — *"how do I remediate the Log4Shell
findings on the DMZ hosts, and what's our SLA for them?"* — and get a
concrete, **policy-grounded, cited** answer.

It ingests exported **Tenable/Nessus** vulnerability reports and enterprise
**security policies** into a **Qdrant** vector store, and answers questions
through a **LangGraph** agent pipeline, with a **Chainlit** chat frontend.
Answers are produced as schema-validated structured output from **Claude**,
with a hallucinated-citation guard so the bot can't cite a finding it wasn't
actually shown.

## Why this exists

Vulnerability scanners produce thousands of findings; the hard part is the
question an analyst actually asks — *what do I do about this one, on this
host, given our policy?* That answer lives across three places: the finding
itself (Tenable), the fix (vendor solution), and the rules (the remediation
SLA and secure-config standard). This project retrieves across all three and
has an LLM compose the answer, grounded in what it retrieved.

It's deliberately built around the things that separate a real RAG system
from a demo:

- **Grounding, verified.** The model is given the retrieved chunks and must
  cite the `chunk_id`s it relied on. If it cites one that wasn't retrieved,
  that's a hallucinated citation and the answer is rejected
  (`AnswerParseError`) rather than trusted — see `vulnrag/llm.py`.
- **Structured output via tool-use, not prompt-and-pray.** The model is given
  one tool (`submit_answer`) with a JSON schema and forced to call it; the
  output is validated against a Pydantic model. Same pattern (and reasoning)
  as the `llm-soc-copilot` project in this portfolio.
- **Runs with zero setup.** Defaults to an embedded in-memory Qdrant, a
  dependency-free deterministic embedder, and an offline stub LLM — so the
  pipeline (and the full test suite) runs without a server, a model download,
  or an API key. Swap each piece for the real thing via environment variables.

## Architecture

```
                Chainlit UI  (app.py)
                     │  analyst question
                     ▼
        ┌──────────  LangGraph  ──────────┐
        │                                 │
        │   router ──► retriever ──► specialist ──► END
        │  (intent)   (Qdrant)      (Claude,
        │                            forced tool-use,
        │                            citation guard)
        └─────────────────────────────────┘
                     │                 ▲
             ingest_cli.py             │
        Tenable CSV + policies ────────┘
             (embed → Qdrant)
```

**The agent graph** (`vulnrag/agents/`):

| Node | Role |
|------|------|
| **router** | Classifies the question into an intent (`remediation` / `prioritization` / `policy` / `general`). Fast keyword heuristic first, LLM fallback only when unsure. |
| **retriever** | Pulls the top-k relevant chunks from Qdrant. Policy questions bias to policy chunks; everything else blends vulnerability + policy so remediation answers cite the SLA they invoke. |
| **specialist** | Generates the structured answer. The intent selects the system prompt, so the same node reasons as a fix-it agent, a risk-ranking agent, or a policy agent as appropriate. |

The router → retriever edge is wired as a real LangGraph conditional edge, so
adding an intent-specific branch later (e.g. a dedicated CVE-enrichment agent
before remediation) is a wiring change, not a rewrite.

## Layout

```
vulnrag/
  schema.py         Pydantic models (corpus + structured answer)
  config.py         env-driven settings
  embeddings.py     HashingEmbedder (default) + SentenceTransformerEmbedder
  vectorstore.py    Qdrant wrapper (in-memory or server), idempotent upsert
  ingest.py         Tenable CSV parser (+ column aliases) & policy chunker
  llm.py            forced tool-use client + FakeLLMClient + citation guard
  export.py         build findings.json (aggregates + SLA) for the dashboard
  connectors/       Azure connectors (Defender/MDVM) -> Vulnerability
  agents/           LangGraph nodes, state, and graph assembly
app.py              Chainlit frontend (auto-ingests sample data on first run)
ingest_cli.py       ingest Tenable exports / policy dirs into Qdrant
scan_cli.py         scan Azure endpoints via Defender, ingest, build dashboard data
dashboard/          self-contained HTML dashboard + findings.json
data/               sample Tenable export, policies, and Defender findings
tests/              36 tests, all offline (in-memory store + fake LLM/connector)
```

## Scanning an Azure environment (Defender / MDVM) and a dashboard

The bot answers questions about `Vulnerability` records regardless of where they
came from. To feed it live Azure data instead of a Tenable CSV, use the
**Defender Vulnerability Management** connector: it pulls per-device findings
from Microsoft Defender for Endpoint and maps them into the same schema, so the
whole embed → Qdrant → agent pipeline works unchanged.

```
 Azure endpoints           connectors/defender.py         existing RAG pipeline
 (2 servers +   ── MDVM ──► pull findings ──► map to  ──► Qdrant ──► LangGraph
  2 Win11 PCs)              (MDE API)         Vulnerability            agents
                                   │
                                   └── export.py ──► dashboard/findings.json ──► dashboard/index.html
```

### One command, offline

```bash
python scan_cli.py --sample
# open dashboard/index.html
```

This uses the bundled sample findings for two servers (`srv-web-01`,
`srv-sql-01`) and two Windows 11 PCs (`pc-hr-07`, `pc-eng-12`), ingests them into
Qdrant, and writes `dashboard/findings.json`. No Azure tenant required.

### Against a real Azure tenant

1. **Onboard the four endpoints to Microsoft Defender for Endpoint** and enable
   Defender Vulnerability Management:
   - servers → enable **Defender for Servers** in Defender for Cloud (via Azure
     Arc if they aren't native Azure VMs);
   - Windows 11 PCs → onboard via **Intune** (or a local onboarding script).
2. **Create an Entra ID app registration** (service principal) with the
   Defender for Endpoint *application* permissions `Vulnerability.Read.All` and
   `Machine.Read.All`, and grant admin consent.
3. **Set credentials** (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
   `AZURE_CLIENT_SECRET` — use Key Vault in production) and run:
   ```bash
   pip install requests           # or: pip install -e ".[azure]"
   python scan_cli.py --devices srv-web-01 srv-sql-01 pc-hr-07 pc-eng-12
   ```
   The connector authenticates (OAuth2 client credentials), pulls
   `SoftwareVulnerabilitiesByMachine`, filters to those devices, ingests them,
   and regenerates the dashboard data.

### The dashboard

`dashboard/index.html` is a **self-contained** page (no build step, no server):
KPI tiles, a severity breakdown, per-host risk stacked by severity, and a
filterable/searchable findings table with per-finding remediation and NVD links.
It reads `dashboard/findings.json` when served, and falls back to an embedded
sample so it renders even opened directly from disk. It is theme-aware
(light/dark) and works down to phone width. Host it anywhere static (including
GitHub Pages) or just open the file.

## Quickstart

```bash
pip install -r requirements.txt

# Run the tests (no services, no API key needed)
pytest

# Launch the chat UI. With no ANTHROPIC_API_KEY it uses the offline stub
# answer so you can see the pipeline; set the key for real answers.
export ANTHROPIC_API_KEY=sk-ant-...
chainlit run app.py
```

The app auto-ingests the bundled `data/` corpus on first run, so you can ask
questions immediately.

### Point it at a real Qdrant + your own data

```bash
docker compose up -d qdrant          # starts Qdrant on localhost:6333
export QDRANT_URL=http://localhost:6333

python ingest_cli.py \
  --tenable /path/to/your_tenable_export.csv \
  --policies /path/to/your_policies_dir

chainlit run app.py
```

For real semantic retrieval instead of the deterministic hashing embedder:

```bash
pip install sentence-transformers
export VULNRAG_EMBEDDER=sentence-transformers
```

## Configuration

All optional — see `.env.example`. Key variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | — | Unset → offline stub LLM; set → real Claude answers |
| `ANTHROPIC_MODEL` | `claude-opus-5` | Forced tool-use requires an Opus-5-class model |
| `QDRANT_URL` | `:memory:` | `:memory:` (embedded) or `http://host:6333` |
| `VULNRAG_EMBEDDER` | `hashing` | `hashing` (offline) or `sentence-transformers` |
| `VULNRAG_TOP_K` | `6` | Chunks retrieved per query |

## Notes and limitations

- The **hashing embedder** makes the system runnable and testable offline; it
  is not competitive with a trained model on semantic recall. Use
  `sentence-transformers` (or wire in a hosted embedding API) for real use.
- The Tenable parser tolerates the common Nessus / Tenable.io / Tenable.sc
  column-name variants (`ingest.py::_COLUMN_ALIASES`) and drops informational
  plugins. Point it at a real export to confirm coverage for your version.
- Forced `tool_choice` is used for structured output. That is supported on
  `claude-opus-5`; on `claude-opus-5-5` / the Fable family use structured
  outputs (`output_config.format`) instead.

## Where this fits in the portfolio

This is the RAG-heavy sibling of `llm-soc-copilot` (alert triage) — same
discipline (structured output, verified grounding, offline-testable), applied
to vulnerability management instead of alert triage. The `sigma-rule-translator`
and `threat-intel-to-kql` projects cover the detection-authoring side of the
same SOC.
