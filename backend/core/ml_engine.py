import os
import re
import json
import pickle
import logging
import torch
import numpy as np
import pandas as pd
import scipy.sparse
from typing import List, Tuple, Dict, Any, Optional
import xgboost as xgb
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# File paths for saving/loading the models
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'models')
IFOREST_PATH    = os.path.join(MODEL_DIR, 'text_isolation_forest.pkl')
XGB_PATH        = os.path.join(MODEL_DIR, 'xgboost_severity.json')
TFIDF_PATH      = os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl')
TEXT_XGB_PATH   = os.path.join(MODEL_DIR, 'text_severity_xgb.json')

# Regex patterns for entity extraction (matches training pipeline)
_CRITICAL_PATTERNS = re.compile(
    r'(remote code execution|arbitrary code|buffer overflow|heap overflow'
    r'|stack overflow|use.after.free|privilege escalation|authentication bypass'
    r'|sql injection|command injection|code injection|rce|root access'
    r'|zero.day|0.day|unauthenticated|pre.auth'
    r'|ransomware|data breach|complete compromise|apt|nation state'
    r'|supply chain|encrypt|domain compromise|lsass|dcsync|golden ticket)',
    re.IGNORECASE
)
_NETWORK_PATTERNS = re.compile(
    r'(network|http|https|tcp|udp|dns|smtp|ssh|ftp|ssl|tls'
    r'|remote|server|client|request|packet|socket|port|web'
    r'|c2|beacon|callback|reverse shell|tunnel|proxy)',
    re.IGNORECASE
)
_ENTITY_RE = re.compile(
    r'(CVE-\d{4}-\d+|CWE-\d+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|https?://[^\s]+|[a-fA-F0-9]{32,64})',
    re.IGNORECASE
)


class TextSeverityClassifier:
    """
    TF-IDF + XGBoost severity regressor trained on real NVD CVE descriptions
    with CVSS v3.1 base scores.  Provides genuine text understanding beyond
    the 5-feature numerical model.
    """
    def __init__(self):
        self.tfidf = None
        self.model = None
        self._load()

    def _load(self):
        try:
            if os.path.exists(TFIDF_PATH) and os.path.exists(TEXT_XGB_PATH):
                with open(TFIDF_PATH, 'rb') as f:
                    self.tfidf = pickle.load(f)
                self.model = xgb.XGBRegressor()
                self.model.load_model(TEXT_XGB_PATH)
                logger.info("TextSeverityClassifier: loaded NVD-trained TF-IDF + XGBoost")
            else:
                logger.info("TextSeverityClassifier: no trained model yet — run scripts/train_real_data.py")
        except Exception as e:
            logger.warning(f"TextSeverityClassifier load failed: {e}")

    def predict(self, text: str) -> Optional[float]:
        """Returns a CVSS-calibrated severity score (0-10) or None if not available."""
        if not self.tfidf or not self.model:
            return None
        try:
            X = self.tfidf.transform([text])
            score = self.model.predict(scipy.sparse.csr_matrix(X))[0]
            return float(np.clip(score, 0.0, 10.0))
        except Exception as e:
            logger.warning(f"TextSeverityClassifier.predict failed: {e}")
            return None

    @property
    def available(self) -> bool:
        return self.tfidf is not None and self.model is not None

class EnsembleMLEngine:
    def __init__(self):
        self.iforest = None
        self.xgb_model = None
        self.text_classifier = TextSeverityClassifier()
        self._load_models()

    def _load_models(self):
        """Loads pre-trained models if they exist."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        
        # Load Isolation Forest
        if os.path.exists(IFOREST_PATH):
            try:
                with open(IFOREST_PATH, 'rb') as f:
                    self.iforest = pickle.load(f)
                logger.info("Loaded pre-trained Isolation Forest model.")
            except Exception as e:
                logger.error(f"Failed to load Isolation Forest: {e}")
        else:
            logger.warning("No pre-trained Isolation Forest model found. Need to baseline.")

        # Load XGBoost
        if os.path.exists(XGB_PATH):
            try:
                self.xgb_model = xgb.XGBRegressor()
                self.xgb_model.load_model(XGB_PATH)
                logger.info("Loaded pre-trained XGBoost model.")
            except Exception as e:
                logger.error(f"Failed to load XGBoost: {e}")
        else:
            logger.warning("No pre-trained XGBoost model found. Need to baseline.")


    def _extract_features(self, text: str, entities: list, heuristic_score: float) -> np.ndarray:
        """
        Converts unstructured threat data into a numerical feature vector.
        Features (aligned with CVE-derived training pipeline):
          0: text_length      — proxy for threat complexity
          1: entity_count     — regex count of CVEs, IPs, URLs, hashes + pre-extracted entities
          2: keyword_severity — heuristic severity from critical keyword density (0-10)
          3: has_critical      — binary: contains RCE, APT, ransomware, etc.
          4: has_network       — binary: contains network/C2 indicators
        """
        text_len = len(text)

        # Regex-based entity extraction from raw text (complements pre-extracted entities)
        regex_entities = len(_ENTITY_RE.findall(text))
        num_entities = max(len(entities), regex_entities)

        # Critical keyword density → 0-10 severity proxy
        critical_matches = len(_CRITICAL_PATTERNS.findall(text))
        has_critical = 1.0 if critical_matches > 0 else 0.0
        keyword_severity = min(10.0, critical_matches * 2.5 + (heuristic_score * 0.3))

        # Network/C2 indicator presence
        has_network = 1.0 if _NETWORK_PATTERNS.search(text) else 0.0

        return np.array([[text_len, num_entities, keyword_severity, has_critical, has_network]])


    def evaluate_threat(self, processed_input: Dict[str, Any], heuristic_score: float, deep_analysis: bool = False) -> Tuple[bool, Optional[float], Dict[str, Any]]:
        """
        Industrial-Grade Hybrid Evaluation.
        Returns:
            Tuple: (is_anomalous: bool, blended_severity: float, deep_insights: dict)

        Logic:
        1.  Heuristic (15%): Fast keyword-based severity.
        2.  Numerical XGBoost (15%): Metadata complexity rules.
        3.  Deep Intelligence (70% - Optional):
            - Stage 1: SecBERT Multi-Label TTP Mapping (Domain-Specific).
            - Stage 2: Phi-3.5-mini Reasoning & Entity Extraction (Contextual).
        """
        text = processed_input.get('normalized_text', '')
        entities = processed_input.get('entities', [])

        # Default results
        is_anomalous = False
        deep_insights = {"title": "Standard Analysis", "summary": "", "terms": []}

        try:
            # 1. Extraction & Anomaly Detection
            features = self._extract_features(text, entities, heuristic_score)
            if self.iforest:
                anomaly_pred = self.iforest.predict(features)[0]
                is_anomalous = (anomaly_pred == -1)

            # 2. Numerical Score (XGBoost) - 0-10
            num_score = 5.0
            if self.xgb_model:
                num_score = float(np.clip(self.xgb_model.predict(features)[0], 0.0, 10.0))

            if not deep_analysis:
                # Standard Blend: 40% Heuristic, 60% XGBoost
                final_severity = (0.40 * heuristic_score) + (0.60 * num_score)
                return is_anomalous, float(np.clip(final_severity, 0.0, 10.0)), deep_insights

            # 3. Deep Intelligence Stage 1: SecBERT TTP Mapping
            from core.secbert_classifier import secbert_clf
            detected_ttps = secbert_clf.predict_techniques(text) # Dict {ID: Conf}
            
            # Convert to list of dicts for LLM/UI
            ttp_list = [{"id": tid, "name": "Classified Technique", "confidence": conf} for tid, conf in detected_ttps.items()]
            
            # SecBERT Severity proxy (average confidence of top TTPs * 10)
            secbert_score = 5.0
            if detected_ttps:
                secbert_score = min(10.0, sum(detected_ttps.values()) / len(detected_ttps) * 10)

            # 4. Deep Intelligence Stage 2: Phi-3.5 Reasoning
            from core.nano_llm_engine import nano_llm
            llm_results = nano_llm.extract_and_analyze(text, ttp_list)
            
            # 5. Deep Intelligence Stage 3: Technical Evidence Alignment (Deterministic)
            from core.evidence_aligner import evidence_aligner
            llm_terms = llm_results.get("terms", [])
            final_ttps = evidence_aligner.align_techniques(ttp_list, llm_terms, text)

            deep_insights = {
                "title": llm_results.get("title", "Threat Detected"),
                "summary": llm_results.get("summary", ""),
                "analysis": llm_results.get("analysis", ""),
                "terms": llm_terms,
                "ttps": final_ttps
            }

            # 5. Industrial Blended Severity
            # Weights: 15% Heuristic, 15% XGBoost, 70% SecBERT (Proxied)
            final_severity = (0.15 * heuristic_score) + (0.15 * num_score) + (0.70 * secbert_score)
            
            # Clip final result
            final_severity = float(np.clip(final_severity, 0.0, 10.0))

            return is_anomalous, final_severity, deep_insights

        except Exception as e:
            logger.error(f"Industrial ML evaluation failed: {e}")
            return False, heuristic_score, deep_insights


    def baseline_training(self):
        """
        Generates CVE-inspired baseline data and trains both models.
        This provides a reasonable starting point until the full training
        pipeline (train_real_data.py) is run with real NVD/CICIDS data.

        Feature schema matches CVE-derived training:
          0: text_length, 1: entity_count, 2: keyword_severity,
          3: has_critical, 4: has_network
        """
        logger.info("Starting baseline ML training (CVE-inspired distributions)...")
        np.random.seed(42)

        # --- Distributions calibrated to real CVE description statistics ---
        # Low severity CVEs (CVSS 0-3.9): short, few entities, no critical keywords
        n_low = 200
        low_len    = np.random.lognormal(4.5, 0.5, n_low).clip(50, 500)
        low_ent    = np.random.poisson(0.3, n_low)
        low_kwsev  = np.random.uniform(0, 2.0, n_low)
        low_crit   = np.zeros(n_low)
        low_net    = np.random.binomial(1, 0.3, n_low).astype(float)
        low_scores = np.random.uniform(1.0, 3.9, n_low)

        # Medium severity CVEs (CVSS 4-6.9): moderate length, some entities
        n_med = 300
        med_len    = np.random.lognormal(5.0, 0.4, n_med).clip(80, 800)
        med_ent    = np.random.poisson(1.0, n_med)
        med_kwsev  = np.random.uniform(1.5, 5.0, n_med)
        med_crit   = np.random.binomial(1, 0.15, n_med).astype(float)
        med_net    = np.random.binomial(1, 0.5, n_med).astype(float)
        med_scores = np.random.uniform(4.0, 6.9, n_med)

        # High severity CVEs (CVSS 7-8.9): longer, more entities, critical keywords
        n_high = 250
        high_len    = np.random.lognormal(5.3, 0.5, n_high).clip(100, 1200)
        high_ent    = np.random.poisson(2.5, n_high)
        high_kwsev  = np.random.uniform(4.0, 8.0, n_high)
        high_crit   = np.random.binomial(1, 0.55, n_high).astype(float)
        high_net    = np.random.binomial(1, 0.65, n_high).astype(float)
        high_scores = np.random.uniform(7.0, 8.9, n_high)

        # Critical severity CVEs (CVSS 9-10): longest, most entities, always critical
        n_crit = 150
        crit_len    = np.random.lognormal(5.6, 0.4, n_crit).clip(150, 2000)
        crit_ent    = np.random.poisson(4.0, n_crit)
        crit_kwsev  = np.random.uniform(6.0, 10.0, n_crit)
        crit_crit   = np.random.binomial(1, 0.85, n_crit).astype(float)
        crit_net    = np.random.binomial(1, 0.75, n_crit).astype(float)
        crit_scores = np.random.uniform(9.0, 10.0, n_crit)

        # Combine all
        X = np.column_stack([
            np.concatenate([low_len, med_len, high_len, crit_len]),
            np.concatenate([low_ent, med_ent, high_ent, crit_ent]),
            np.concatenate([low_kwsev, med_kwsev, high_kwsev, crit_kwsev]),
            np.concatenate([low_crit, med_crit, high_crit, crit_crit]),
            np.concatenate([low_net, med_net, high_net, crit_net]),
        ])
        y = np.concatenate([low_scores, med_scores, high_scores, crit_scores])
        X = np.maximum(X, 0)

        # Train Isolation Forest (critical samples ≈ 17% treated as anomalous)
        self.iforest = IsolationForest(contamination=0.15, random_state=42, n_estimators=200)
        self.iforest.fit(X)
        os.makedirs(MODEL_DIR, exist_ok=True)
        with open(IFOREST_PATH, 'wb') as f:
            pickle.dump(self.iforest, f)

        # Train XGBoost with better hyperparameters
        self.xgb_model = xgb.XGBRegressor(
            objective='reg:squarederror', n_estimators=200, max_depth=4,
            learning_rate=0.08, subsample=0.85, colsample_bytree=0.8,
            random_state=42, verbosity=0
        )
        self.xgb_model.fit(X, y)
        self.xgb_model.save_model(XGB_PATH)

        logger.info(f"Baseline models trained on {len(y)} CVE-inspired samples and saved.")

# Singleton instance
ml_engine = EnsembleMLEngine()
