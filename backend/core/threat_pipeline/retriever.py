"""
threat_pipeline.retriever  —  LAYER 2: RAG retrieval
====================================================
Vectorise the actions extracted in Layer 1 and query a local ChromaDB store of
the MITRE ATT&CK corpus to retrieve the top-K closest techniques by cosine
similarity.

Why ChromaDB over FAISS here: Layer 3 needs to filter candidates by *platform*
and *tactic*. Chroma stores that metadata alongside the vectors and supports
`where=` filters natively, so platform-scoped retrieval is a one-liner instead
of a hand-maintained side index.

Embeddings use ``all-mpnet-base-v2`` — the same sentence-transformer the rest of
the app already caches, so no extra model download.
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

from . import config
from .command_intent import enrich as enrich_command_intent
from .schema import Extraction, RetrievedTechnique

log = logging.getLogger("threat_pipeline.retriever")


class TechniqueRetriever:
    """Persistent vector store over the MITRE technique corpus."""

    def __init__(self) -> None:
        self._embedder = None
        self._client = None
        self._collection = None

    # -- lazy resources -----------------------------------------------------
    def _get_embedder(self):
        if self._embedder is None:
            from sentence_transformers import SentenceTransformer
            log.info("Loading embedding model '%s' ...", config.EMBEDDING_MODEL)
            self._embedder = SentenceTransformer(config.EMBEDDING_MODEL)
        return self._embedder

    def _get_collection(self):
        if self._collection is None:
            import chromadb
            self._client = chromadb.PersistentClient(path=config.CHROMA_DIR)
            # cosine space so distance maps cleanly to 1 - similarity.
            self._collection = self._client.get_or_create_collection(
                name=config.CHROMA_COLLECTION,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collection

    def _embed(self, texts: List[str]):
        # normalised embeddings + cosine space => similarity = 1 - distance.
        return self._get_embedder().encode(
            texts, normalize_embeddings=True, show_progress_bar=False
        ).tolist()

    # -- index population ---------------------------------------------------
    def is_populated(self) -> bool:
        try:
            return self._get_collection().count() > 0
        except Exception:
            return False

    def ensure_index(self) -> None:
        """Build the vector index if it doesn't exist yet."""
        if not self.is_populated():
            self.build_index()

    def build_index(self, force: bool = False) -> int:
        """(Re)build the Chroma collection from the shipped MITRE corpus.

        Each technique becomes one document: ``"<name>. <description>"``.
        Returns the number of techniques indexed.
        """
        coll = self._get_collection()
        if force and coll.count() > 0:
            self._client.delete_collection(config.CHROMA_COLLECTION)
            self._collection = None
            coll = self._get_collection()

        with open(config.MITRE_ATTACK_JSON, "r", encoding="utf-8") as fh:
            techniques = json.load(fh)

        ids, documents, metadatas = [], [], []
        for t in techniques:
            tid = t.get("id")
            if not tid:
                continue
            name = t.get("name", "")
            desc = t.get("description", "")
            platforms = t.get("platforms", []) or []
            ids.append(tid)
            documents.append(f"{name}. {desc}".strip())
            metadatas.append(
                {
                    "id": tid,
                    "name": name,
                    "tactic": t.get("tactic", "Unknown"),
                    "tactic_id": t.get("tactic_id", ""),
                    # Chroma metadata values must be scalars -> join the list.
                    "platforms": ",".join(platforms),
                    "is_subtechnique": "." in tid,
                }
            )

        log.info("Embedding %d MITRE techniques ...", len(ids))
        # Batch to keep peak memory low on an M1.
        BATCH = 256
        for i in range(0, len(ids), BATCH):
            sl = slice(i, i + BATCH)
            coll.upsert(
                ids=ids[sl],
                documents=documents[sl],
                embeddings=self._embed(documents[sl]),
                metadatas=metadatas[sl],
            )
        log.info("Indexed %d techniques into ChromaDB at %s", len(ids), config.CHROMA_DIR)
        return len(ids)

    # -- retrieval ----------------------------------------------------------
    def retrieve(
        self,
        query_text: str,
        top_k: int = config.TOP_K,
        platform: Optional[str] = None,
    ) -> List[RetrievedTechnique]:
        """Return the top-K techniques most similar to ``query_text``.

        ``platform`` (optional) restricts results to techniques whose platform
        list contains that OS — a soft pre-filter; the hard platform veto still
        happens in Layer 3.
        """
        if not query_text.strip():
            return []
        coll = self._get_collection()
        where = None
        if platform and platform != "unknown":
            # Chroma can't substring-match a joined string, so filter in Python
            # below instead. Left as None to keep recall; Layer 3 enforces it.
            where = None

        # Append LOLBin/command intent vocabulary for embedding only — the stored
        # source_query below stays the original so evidence remains faithful.
        embed_query = (
            enrich_command_intent(query_text)
            if config.ENRICH_COMMAND_INTENT else query_text
        )
        res = coll.query(
            query_embeddings=self._embed([embed_query]),
            n_results=max(top_k * 2, top_k),  # over-fetch, trim after filtering
            where=where,
        )
        out: List[RetrievedTechnique] = []
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        for meta, dist, doc in zip(metas, dists, docs):
            similarity = 1.0 - float(dist)  # cosine distance -> similarity
            if similarity < config.MIN_SIMILARITY:
                continue
            platforms = [p for p in (meta.get("platforms") or "").split(",") if p]
            out.append(
                RetrievedTechnique(
                    id=meta["id"],
                    name=meta.get("name", ""),
                    tactic=meta.get("tactic", "Unknown"),
                    platforms=platforms,
                    description=doc or "",
                    similarity=round(similarity, 4),
                    source_query=query_text,
                )
            )
        return out[:top_k]

    def retrieve_for_extraction(
        self, extraction: Extraction, top_k: int = config.TOP_K
    ) -> List[RetrievedTechnique]:
        """Aggregate candidates across every extracted relation.

        Each relation is embedded and queried independently; results are merged,
        keeping the highest similarity seen for each technique id.
        """
        best: Dict[str, RetrievedTechnique] = {}
        for relation in extraction.relations:
            q = relation.query_text()
            for cand in self.retrieve(q, top_k=top_k, platform=extraction.context.platform):
                existing = best.get(cand.id)
                if existing is None or cand.similarity > existing.similarity:
                    best[cand.id] = cand
        # Stable, highest-similarity-first ordering.
        return sorted(best.values(), key=lambda c: c.similarity, reverse=True)


# App-wide singleton.
retriever = TechniqueRetriever()
