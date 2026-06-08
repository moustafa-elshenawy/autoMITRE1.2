# threat_pipeline — three-layer MITRE ATT&CK mapping engine

Maps raw security telemetry (event logs, SIEM alerts, SOC logs) to MITRE
ATT&CK with high precision, avoiding naive keyword matching and LLM
hallucination. Optimised for local execution on Apple Silicon (M1).

```
raw log
   │
   ▼  Layer 1  extractor.py      LLM-as-NLP relation extraction (mlx-lm)
   │            └─ [Action] -> [Tool] -> [Target/Modifier]  (+ deterministic context)
   ▼  Layer 2  retriever.py      ChromaDB + sentence-transformers (all-mpnet-base-v2)
   │            └─ top-K MITRE techniques by cosine similarity
   ▼  Layer 3  logic_engine.py   deterministic constraint / gatekeeper engine
   │            └─ protocol / dependency / platform rules, adjusted confidence
   ▼  final JSON  { mapped_techniques[], suppressed[], context, relations }
```

## Files

| File              | Layer | Responsibility |
|-------------------|-------|----------------|
| `config.py`       | —     | Paths, model names, thresholds (all env-overridable) |
| `schema.py`       | —     | Dataclasses passed between layers |
| `extractor.py`    | 1     | mlx-lm relation extraction + deterministic context + regex fallback |
| `retriever.py`    | 2     | ChromaDB vector store, cosine retrieval |
| `build_index.py`  | 2     | CLI to populate the vector store from `data/mitre_attack.json` |
| `logic_engine.py` | 3     | `ConstraintEngine` — the rule-based gatekeeper |
| `pipeline.py`     | —     | `ThreatMappingPipeline` orchestrator + `run_pipeline()` / `map_log_to_attack_techniques()` |
| `main.py`         | —     | Standalone demo over sample logs |
| `tests.py`        | —     | Deterministic constraint-engine assertions (no models needed) |

## Setup

From the backend root, inside the venv:

```bash
# 1. Install deps (already in requirements.txt)
pip install mlx-lm chromadb

# 2. Build the MITRE vector index (one-off; rebuild with --force)
python -m core.threat_pipeline.build_index

# 3. Run the demo
python -m core.threat_pipeline.main --all
```

The Layer-1 LLM (`mlx-community/Llama-3.2-3B-Instruct-4bit`) downloads from
Hugging Face on first use. Until then — or on non-Apple-Silicon hosts — the
extractor automatically falls back to a deterministic regex parser, so the
pipeline always runs. Force the fallback explicitly with
`AUTOMITRE_EXTRACTOR_FALLBACK=1`.

## Configuration (env vars)

| Var | Default | Purpose |
|-----|---------|---------|
| `AUTOMITRE_MLX_MODEL` | `mlx-community/Llama-3.2-3B-Instruct-4bit` | Layer-1 LLM |
| `AUTOMITRE_EXTRACTOR_FALLBACK` | `0` | `1` forces the regex extractor |
| `AUTOMITRE_EMBEDDING_MODEL` | `all-mpnet-base-v2` | Layer-2 embeddings |
| `AUTOMITRE_TOP_K` | `5` | Candidates retrieved per relation |
| `AUTOMITRE_MIN_SIMILARITY` | `0.20` | Cosine floor before Layer 3 |
| `AUTOMITRE_ACCEPT_THRESHOLD` | `0.35` | Min adjusted confidence to accept |
| `AUTOMITRE_USE_RAG` | `1` | FastAPI toggle: `0` reverts to the legacy SecBERT pipeline |

## FastAPI integration

`core/ai_threat_analyzer.py::analyze_threat()` calls
`map_log_to_attack_techniques()`. When it returns techniques they supersede the
legacy SecBERT/heuristic list; any failure (or `AUTOMITRE_USE_RAG=0`) silently
retains the legacy path. Narrative fields (title, summary, predicted steps)
still come from the existing reasoning stage.
