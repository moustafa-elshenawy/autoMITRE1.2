"""
attack_hierarchical.reranker
============================
The Bi-Encoder semantic verification gate.

The classifier proposes techniques; this module independently checks whether the
raw input *text* actually aligns with the official MITRE *definition* of each
proposed technique. A bi-encoder embeds the input and every technique definition
into a local vector index; a fast cosine query gives a "does this even belong in
the neighbourhood?" support score, which gates acceptance.

(A cross-encoder stage was removed: the ms-marco model under-scored
CTI-vs-definition pairs to ~0.0 even for clearly-correct techniques, making it
useless as a gate while adding load-time and memory cost on small machines. The
bi-encoder support cleanly separates correct (~0.45-0.53) from noise (~0.0).)

The model is loaded lazily so importing this module is cheap.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

import numpy as np

from . import config
from .taxonomy import Taxonomy

log = logging.getLogger("attack_hierarchical.reranker")


class SemanticVerifier:
    """Bi-encoder vector index over the taxonomy definitions."""

    def __init__(self, taxonomy: Taxonomy,
                 biencoder_name: Optional[str] = None):
        self.tax = taxonomy
        self.biencoder_name = biencoder_name or config.BIENCODER_MODEL

        self._bi = None
        self._index: Optional[np.ndarray] = None          # [num_tech, dim], L2-normalised
        self._index_ids: List[str] = list(self.tax.techniques)
        self._definitions: List[str] = [self.tax.technique_text[t] for t in self._index_ids]

    # -- lazy loader --------------------------------------------------------
    def _get_biencoder(self):
        if self._bi is None:
            from sentence_transformers import SentenceTransformer
            log.info("Loading bi-encoder: %s", self.biencoder_name)
            self._bi = SentenceTransformer(self.biencoder_name)
        return self._bi

    # -- index --------------------------------------------------------------
    def build_index(self) -> None:
        """Embed every technique definition into the local vector index."""
        if self._index is not None:
            return
        emb = self._get_biencoder().encode(
            self._definitions, normalize_embeddings=True, show_progress_bar=False
        )
        self._index = np.asarray(emb, dtype=np.float32)
        log.info("Bi-encoder index built: %s", self._index.shape)

    def bi_support(self, text: str, top_k: int = 10, chunk_text: bool = False) -> Dict[str, float]:
        """Cosine similarity of ``text`` to each technique definition (top_k)."""
        self.build_index()
        
        if chunk_text:
            words = text.split()
            if len(words) <= 50:
                q = self._get_biencoder().encode([text], normalize_embeddings=True)[0]
                sims = self._index @ np.asarray(q, dtype=np.float32)
            else:
                chunks = [" ".join(words[i:i + 50]) for i in range(0, len(words), 50)]
                q = self._get_biencoder().encode(chunks, normalize_embeddings=True)
                sims_all = self._index @ np.asarray(q, dtype=np.float32).T
                sims = np.max(sims_all, axis=1)
        else:
            q = self._get_biencoder().encode([text], normalize_embeddings=True)[0]
            sims = self._index @ np.asarray(q, dtype=np.float32)  # cosine (normalised)
            
        order = np.argsort(-sims)[:top_k]
        return {self._index_ids[i]: float(sims[i]) for i in order}

    def verify(self, text: str, candidate_ids: List[str], chunk_text: bool = False
               ) -> Dict[str, float]:
        """Return bi-encoder cosine support for each candidate technique."""
        self.build_index()
        
        if chunk_text:
            words = text.split()
            if len(words) <= 50:
                q = self._get_biencoder().encode([text], normalize_embeddings=True)[0]
                sims = self._index @ np.asarray(q, dtype=np.float32)
            else:
                chunks = [" ".join(words[i:i + 50]) for i in range(0, len(words), 50)]
                q = self._get_biencoder().encode(chunks, normalize_embeddings=True)
                sims_all = self._index @ np.asarray(q, dtype=np.float32).T
                sims = np.max(sims_all, axis=1)
        else:
            q = self._get_biencoder().encode([text], normalize_embeddings=True)[0]
            sims = self._index @ np.asarray(q, dtype=np.float32)
            
        tid_to_sim = {self._index_ids[i]: float(sims[i]) for i in range(len(self._index_ids))}
        return {tid: tid_to_sim.get(tid, 0.0) for tid in candidate_ids}
