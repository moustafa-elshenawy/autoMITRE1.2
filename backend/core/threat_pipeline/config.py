"""
threat_pipeline.config
======================
Central configuration for the three-layer MITRE ATT&CK mapping pipeline.

Layer 1 (extractor)  -> local LLM used purely as an NLP relation extractor (mlx-lm).
Layer 2 (retriever)  -> ChromaDB + sentence-transformers semantic retrieval.
Layer 3 (logic)      -> deterministic constraint / gatekeeper engine.

All paths are resolved relative to the backend root so the package works the
same whether it is imported by FastAPI or run standalone via ``main.py``.
"""
import os

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# backend/core/threat_pipeline/config.py  -> backend/
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))

DATA_DIR = os.path.join(BACKEND_ROOT, "data")

# Source MITRE corpus (already shipped with the app, derived from STIX).
MITRE_ATTACK_JSON = os.path.join(DATA_DIR, "mitre_attack.json")

# Persistent ChromaDB store for the vectorised technique corpus.
CHROMA_DIR = os.path.join(DATA_DIR, "chroma_mitre")
CHROMA_COLLECTION = "mitre_attack_techniques"

# ---------------------------------------------------------------------------
# Layer 1 — Semantic Extraction (LLM as NLP engine)
# ---------------------------------------------------------------------------
# mlx-lm is preferred on Apple Silicon (unified-memory friendly). The model is
# downloaded from the Hugging Face hub on first use. A 4-bit 3B instruct model
# is a good latency/quality trade-off on an M1; override via env if desired.
MLX_MODEL = os.getenv("AUTOMITRE_MLX_MODEL", "mlx-community/Llama-3.2-3B-Instruct-4bit")

# Generation budget for the extraction call. Extraction output is small JSON,
# so a tight cap keeps inference fast and deterministic.
EXTRACTOR_MAX_TOKENS = int(os.getenv("AUTOMITRE_EXTRACTOR_MAX_TOKENS", "512"))
EXTRACTOR_TEMPERATURE = float(os.getenv("AUTOMITRE_EXTRACTOR_TEMPERATURE", "0.0"))

# When True (or the model can't load) the extractor uses the deterministic
# regex/keyword fallback instead of the LLM. Lets the whole pipeline run with
# zero model downloads, and guarantees the FastAPI app always boots.
EXTRACTOR_FORCE_FALLBACK = os.getenv("AUTOMITRE_EXTRACTOR_FALLBACK", "0") == "1"

# Token-overlap grounding gate. A small instruct model will sometimes hallucinate
# a plausible-but-absent behaviour (e.g. "dumped credentials" from an opaque
# base64 -enc blob), which then poisons Layer-2 retrieval. When enabled, an LLM
# relation whose `action` shares fewer than MIN_TOKEN_OVERLAP content tokens with
# the source log is dropped entirely (the action is the behavioural claim and the
# retrieval query); ungrounded tool/target/modifier fields are scrubbed to null
# so they can't leak into the query or evidence. Only applies to the LLM backend;
# the regex fallback is grounded by construction. MIN_TOKEN_OVERLAP=1 means
# "share at least one word with the log", i.e. drop only fully-invented relations.
EXTRACTOR_GROUND_RELATIONS = os.getenv("AUTOMITRE_GROUND_RELATIONS", "1") == "1"
EXTRACTOR_MIN_TOKEN_OVERLAP = int(os.getenv("AUTOMITRE_MIN_TOKEN_OVERLAP", "1"))

# ---------------------------------------------------------------------------
# Layer 2 — RAG retrieval
# ---------------------------------------------------------------------------
# Reuse the sentence-transformer already cached by the app (technique_embedder).
EMBEDDING_MODEL = os.getenv("AUTOMITRE_EMBEDDING_MODEL", "all-mpnet-base-v2")

# How many technique candidates to retrieve per extracted action.
TOP_K = int(os.getenv("AUTOMITRE_TOP_K", "5"))

# Cosine similarity floor. Candidates below this are treated as noise and never
# reach the constraint engine.
MIN_SIMILARITY = float(os.getenv("AUTOMITRE_MIN_SIMILARITY", "0.20"))

# Command-intent enrichment. Terse CLI/LOLBin queries (e.g. "vssadmin delete
# shadows") embed poorly against MITRE's prose, so when enabled the retriever
# appends MITRE-vocabulary intent terms to the *embedding* query (never to the
# stored evidence) before the bi-encoder runs. See command_intent.py.
ENRICH_COMMAND_INTENT = os.getenv("AUTOMITRE_ENRICH_COMMANDS", "1") == "1"

# ---------------------------------------------------------------------------
# Layer 3 — Constraint engine
# ---------------------------------------------------------------------------
# A mapped technique is only emitted if its constraint-adjusted confidence is at
# or above this value. Hard-eliminated techniques are dropped regardless.
ACCEPT_THRESHOLD = float(os.getenv("AUTOMITRE_ACCEPT_THRESHOLD", "0.35"))
