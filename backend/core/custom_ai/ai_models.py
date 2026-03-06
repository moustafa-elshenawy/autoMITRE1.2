"""
AutoMITRE AI Models
===================
All 6 core AI models for the AutoMITRE Threat Intelligence System.
Each model is trained to achieve maximum accuracy using ensemble methods.

Models:
  1. ThreatClassifier         - Classifies threat type (13 categories)
  2. FrameworkMapper          - Maps threat to ATT&CK / D3FEND / NIST / OWASP
  3. SeverityScorer           - Predicts severity level (Critical/High/Medium/Low)
  4. PcapAnalyzer             - Analyzes PCAP network features (8 traffic types)
  5. LogAnomalyDetector       - Detects malicious vs benign log entries
  6. ThreatPredictor          - Predicts next likely threat / trend

Integration:
  All models expose a unified .predict(input) and .predict_proba(input) API
  compatible with the AutoMITRE FastAPI backend.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier,
    VotingClassifier, ExtraTreesClassifier
)
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import (
    LabelEncoder, StandardScaler, label_binarize
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, roc_auc_score
)
from sklearn.multioutput import MultiOutputClassifier

MODELS_DIR = Path(__file__).parent.parent.parent / "models" / "custom"
DATA_DIR = Path(__file__).parent.parent.parent / "data" / "training_data"
MODELS_DIR.mkdir(exist_ok=True, parents=True)
DATA_DIR.mkdir(exist_ok=True, parents=True)

# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def evaluate_model(name, model, X_test, y_test, le=None):
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    print(f"\n{'─'*50}")
    print(f"Model: {name}")
    print(f"  Accuracy : {acc*100:.2f}%")
    print(f"  F1-Score : {f1*100:.2f}%")
    
    print(classification_report(y_test, y_pred, zero_division=0))
    return acc, f1


# ─────────────────────────────────────────────────────────────────────────────
# Model 1: Threat Classifier
# ─────────────────────────────────────────────────────────────────────────────

class ThreatClassifier:
    """
    Classifies threat text into one of 13 MITRE ATT&CK tactic categories.
    Uses an ensemble of TF-IDF + Gradient Boosting + Extra Trees + Logistic Regression.
    """
    
    def __init__(self):
        self.le = LabelEncoder()
        self.pipeline = None
        self.accuracy = None
        self.f1 = None

    def build_pipeline(self):
        tfidf = TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=30000,
            sublinear_tf=True,
            analyzer="word",
            min_df=1,
            max_df=0.95,
            strip_accents="unicode",
        )
        gb = GradientBoostingClassifier(
            n_estimators=20, max_depth=6, learning_rate=0.1,
            subsample=0.85, random_state=42
        )
        et = ExtraTreesClassifier(
            n_estimators=20, max_depth=None, min_samples_leaf=1,
            random_state=42, n_jobs=1
        )
        lr = LogisticRegression(
            C=10, max_iter=2000, solver="lbfgs",
            random_state=42
        )
        # SGD with calibration for probability estimates
        sgd = CalibratedClassifierCV(
            SGDClassifier(loss="hinge", alpha=1e-4, max_iter=200, random_state=42)
        )

        ensemble = VotingClassifier(
            estimators=[("gb", gb), ("et", et), ("lr", lr), ("sgd", sgd)],
            voting="soft",
            weights=[3, 3, 2, 1],
            n_jobs=1,
        )
        return Pipeline([("tfidf", tfidf), ("clf", ensemble)])

    def train(self, df):
        print_section("Training: ThreatClassifier")
        X = df["text"].astype(str)
        y = self.le.fit_transform(df["threat_category"])
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, stratify=y, random_state=42
        )
        
        self.pipeline = self.build_pipeline()
        print(f"  Training on {len(X_train)} samples, {len(self.le.classes_)} classes...")
        self.pipeline.fit(X_train, y_train)
        
        self.accuracy, self.f1 = evaluate_model(
            "ThreatClassifier", self.pipeline, X_test, y_test, self.le
        )
        return self

    def predict(self, texts):
        if isinstance(texts, str):
            texts = [texts]
        preds = self.pipeline.predict(texts)
        return self.le.inverse_transform(preds)

    def predict_proba(self, texts):
        if isinstance(texts, str):
            texts = [texts]
        proba = self.pipeline.predict_proba(texts)
        return [
            {cls: float(p) for cls, p in zip(self.le.classes_, row)}
            for row in proba
        ]

    def save(self):
        joblib.dump({"pipeline": self.pipeline, "le": self.le,
                     "accuracy": self.accuracy, "f1": self.f1},
                    MODELS_DIR / "threat_classifier.pkl")
        print(f"  ✓ Saved ThreatClassifier (acc={self.accuracy*100:.2f}%)")

    @classmethod
    def load(cls):
        obj = cls()
        data = joblib.load(MODELS_DIR / "threat_classifier.pkl")
        obj.pipeline, obj.le = data["pipeline"], data["le"]
        obj.accuracy, obj.f1 = data["accuracy"], data["f1"]
        return obj


# ─────────────────────────────────────────────────────────────────────────────
# Model 2: Framework Mapper
# ─────────────────────────────────────────────────────────────────────────────

class FrameworkMapper:
    """
    Maps threat text to:
      - MITRE ATT&CK technique ID
      - MITRE D3FEND technique
      - NIST SP 800-53 control
      - OWASP ASVS requirement
    Uses 4 independent classifiers (one per framework).
    """

    def __init__(self):
        self.encoders = {}
        self.pipelines = {}
        self.accuracies = {}

    def _build_pipeline(self, n_classes):
        tfidf = TfidfVectorizer(
            ngram_range=(1, 3), max_features=25000,
            sublinear_tf=True, min_df=1
        )
        if n_classes <= 30:
            clf = GradientBoostingClassifier(
                n_estimators=250, max_depth=5, learning_rate=0.1,
                random_state=42
            )
        else:
            clf = ExtraTreesClassifier(
                n_estimators=20, random_state=42, n_jobs=1
            )
        return Pipeline([("tfidf", tfidf), ("clf", clf)])

    def train(self, df):
        print_section("Training: FrameworkMapper")
        targets = {
            "attck": "attck_technique_id",
            "d3fend": "d3fend_technique",
            "nist": "nist_control",
            "owasp": "owasp_requirement",
        }
        X = df["text"].astype(str)

        for key, col in targets.items():
            le = LabelEncoder()
            y = le.fit_transform(df[col])
            self.encoders[key] = le

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.15, random_state=42
            )
            n_classes = len(le.classes_)
            pipe = self._build_pipeline(n_classes)
            print(f"\n  [{key.upper()}] Training {n_classes} classes on {len(X_train)} samples...")
            pipe.fit(X_train, y_train)
            self.pipelines[key] = pipe

            acc = accuracy_score(y_test, pipe.predict(X_test))
            f1 = f1_score(y_test, pipe.predict(X_test), average="weighted", zero_division=0)
            self.accuracies[key] = acc
            print(f"  [{key.upper()}] Accuracy={acc*100:.2f}%  F1={f1*100:.2f}%")

        return self

    def predict(self, texts):
        if isinstance(texts, str):
            texts = [texts]
        results = []
        for i in range(len(texts)):
            text_slice = [texts[i]]
            result = {}
            for key, pipe in self.pipelines.items():
                pred_idx = pipe.predict(text_slice)[0]
                result[key] = self.encoders[key].inverse_transform([pred_idx])[0]
            results.append(result)
        return results

    def save(self):
        joblib.dump({"pipelines": self.pipelines, "encoders": self.encoders,
                     "accuracies": self.accuracies},
                    MODELS_DIR / "framework_mapper.pkl")
        avg_acc = np.mean(list(self.accuracies.values()))
        print(f"  ✓ Saved FrameworkMapper (avg_acc={avg_acc*100:.2f}%)")

    @classmethod
    def load(cls):
        obj = cls()
        data = joblib.load(MODELS_DIR / "framework_mapper.pkl")
        obj.pipelines = data["pipelines"]
        obj.encoders = data["encoders"]
        obj.accuracies = data["accuracies"]
        return obj


# ─────────────────────────────────────────────────────────────────────────────
# Model 3: Severity Scorer
# ─────────────────────────────────────────────────────────────────────────────

class SeverityScorer:
    """
    Predicts threat severity: Critical / High / Medium / Low.
    Ensemble: GradientBoosting + ExtraTrees + LogisticRegression.
    """

    def __init__(self):
        self.le = LabelEncoder()
        self.pipeline = None
        self.accuracy = None

    def train(self, df):
        print_section("Training: SeverityScorer")
        X = df["text"].astype(str)
        y = self.le.fit_transform(df["severity"])

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, stratify=y, random_state=42
        )

        tfidf = TfidfVectorizer(
            ngram_range=(1, 3), max_features=20000,
            sublinear_tf=True, min_df=1
        )
        gb = GradientBoostingClassifier(n_estimators=20, max_depth=5, random_state=42)
        et = ExtraTreesClassifier(n_estimators=20, random_state=42, n_jobs=1)
        lr = LogisticRegression(C=10, max_iter=1000, random_state=42)

        ensemble = VotingClassifier(
            estimators=[("gb", gb), ("et", et), ("lr", lr)],
            voting="soft", weights=[3, 3, 2], n_jobs=1
        )
        self.pipeline = Pipeline([("tfidf", tfidf), ("clf", ensemble)])
        print(f"  Training on {len(X_train)} samples...")
        self.pipeline.fit(X_train, y_train)
        self.accuracy, f1 = evaluate_model(
            "SeverityScorer", self.pipeline, X_test, y_test, self.le
        )
        return self

    def predict(self, texts):
        if isinstance(texts, str):
            texts = [texts]
        preds = self.pipeline.predict(texts)
        return self.le.inverse_transform(preds)

    def predict_proba(self, texts):
        if isinstance(texts, str):
            texts = [texts]
        proba = self.pipeline.predict_proba(texts)
        return [
            {cls: float(p) for cls, p in zip(self.le.classes_, row)}
            for row in proba
        ]

    def save(self):
        joblib.dump({"pipeline": self.pipeline, "le": self.le, "accuracy": self.accuracy},
                    MODELS_DIR / "severity_scorer.pkl")
        print(f"  ✓ Saved SeverityScorer (acc={self.accuracy*100:.2f}%)")

    @classmethod
    def load(cls):
        obj = cls()
        data = joblib.load(MODELS_DIR / "severity_scorer.pkl")
        obj.pipeline, obj.le, obj.accuracy = data["pipeline"], data["le"], data["accuracy"]
        return obj


# ─────────────────────────────────────────────────────────────────────────────
# Model 4: PCAP Network Traffic Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class PcapAnalyzer:
    """
    Classifies network traffic into 8 categories using extracted PCAP features.
    Uses Random Forest + Gradient Boosting ensemble on numerical features.
    """

    FEATURES = [
        "pkt_len_mean", "pkt_rate", "flow_duration", "dst_port_entropy",
        "payload_entropy", "syn_flag_ratio", "bytes_per_second",
        "unique_dst_ips", "failed_conn_ratio", "avg_ttl"
    ]

    def __init__(self):
        self.le = LabelEncoder()
        self.pipeline = None
        self.accuracy = None

    def train(self, df):
        print_section("Training: PcapAnalyzer")
        X = df[self.FEATURES].values
        y = self.le.fit_transform(df["label"])

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, stratify=y, random_state=42
        )

        scaler = StandardScaler()
        rf = RandomForestClassifier(
            n_estimators=200, max_depth=None, min_samples_leaf=1,
            random_state=42, n_jobs=1
        )
        gb = GradientBoostingClassifier(
            n_estimators=20, max_depth=6, learning_rate=0.1,
            subsample=0.85, random_state=42
        )
        et = ExtraTreesClassifier(n_estimators=20, random_state=42, n_jobs=1)

        ensemble = VotingClassifier(
            estimators=[("rf", rf), ("gb", gb), ("et", et)],
            voting="soft", weights=[3, 3, 3], n_jobs=1
        )
        self.pipeline = Pipeline([("scaler", scaler), ("clf", ensemble)])
        print(f"  Training on {len(X_train)} samples, {len(self.le.classes_)} traffic classes...")
        self.pipeline.fit(X_train, y_train)
        self.accuracy, f1 = evaluate_model(
            "PcapAnalyzer", self.pipeline, X_test, y_test, self.le
        )
        return self

    def predict(self, features_dict_or_array):
        """
        Accept dict with feature keys or numpy array.
        Returns predicted traffic label.
        """
        if isinstance(features_dict_or_array, dict):
            X = np.array([[features_dict_or_array[f] for f in self.FEATURES]])
        else:
            X = np.array(features_dict_or_array)
            if X.ndim == 1:
                X = X.reshape(1, -1)
        preds = self.pipeline.predict(X)
        return self.le.inverse_transform(preds)

    def predict_proba(self, features_dict_or_array):
        if isinstance(features_dict_or_array, dict):
            X = np.array([[features_dict_or_array[f] for f in self.FEATURES]])
        else:
            X = np.array(features_dict_or_array)
            if X.ndim == 1:
                X = X.reshape(1, -1)
        proba = self.pipeline.predict_proba(X)
        return [
            {cls: float(p) for cls, p in zip(self.le.classes_, row)}
            for row in proba
        ]

    def save(self):
        joblib.dump({"pipeline": self.pipeline, "le": self.le,
                     "accuracy": self.accuracy, "features": self.FEATURES},
                    MODELS_DIR / "pcap_analyzer.pkl")
        print(f"  ✓ Saved PcapAnalyzer (acc={self.accuracy*100:.2f}%)")

    @classmethod
    def load(cls):
        obj = cls()
        data = joblib.load(MODELS_DIR / "pcap_analyzer.pkl")
        obj.pipeline, obj.le, obj.accuracy = data["pipeline"], data["le"], data["accuracy"]
        return obj


# ─────────────────────────────────────────────────────────────────────────────
# Model 5: Log Anomaly Detector
# ─────────────────────────────────────────────────────────────────────────────

class LogAnomalyDetector:
    """
    Binary classifier: detects Malicious vs Benign log entries.
    Uses TF-IDF on log text + ensemble.
    """

    def __init__(self):
        self.le = LabelEncoder()
        self.pipeline = None
        self.accuracy = None

    def train(self, df):
        print_section("Training: LogAnomalyDetector")
        X = df["log_text"].astype(str)
        y = self.le.fit_transform(df["label"])

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, stratify=y, random_state=42
        )

        tfidf = TfidfVectorizer(
            ngram_range=(1, 3), max_features=15000,
            sublinear_tf=True, min_df=1,
            analyzer="word",
        )
        gb = GradientBoostingClassifier(n_estimators=20, max_depth=5, random_state=42)
        et = ExtraTreesClassifier(n_estimators=20, random_state=42, n_jobs=1)
        lr = LogisticRegression(C=10, max_iter=1000, random_state=42)

        ensemble = VotingClassifier(
            estimators=[("gb", gb), ("et", et), ("lr", lr)],
            voting="soft", weights=[3, 3, 2], n_jobs=1
        )
        self.pipeline = Pipeline([("tfidf", tfidf), ("clf", ensemble)])
        print(f"  Training on {len(X_train)} samples...")
        self.pipeline.fit(X_train, y_train)
        self.accuracy, f1 = evaluate_model(
            "LogAnomalyDetector", self.pipeline, X_test, y_test, self.le
        )
        return self

    def predict(self, log_texts):
        if isinstance(log_texts, str):
            log_texts = [log_texts]
        preds = self.pipeline.predict(log_texts)
        return self.le.inverse_transform(preds)

    def predict_proba(self, log_texts):
        if isinstance(log_texts, str):
            log_texts = [log_texts]
        proba = self.pipeline.predict_proba(log_texts)
        return [
            {cls: float(p) for cls, p in zip(self.le.classes_, row)}
            for row in proba
        ]

    def save(self):
        joblib.dump({"pipeline": self.pipeline, "le": self.le, "accuracy": self.accuracy},
                    MODELS_DIR / "log_anomaly_detector.pkl")
        print(f"  ✓ Saved LogAnomalyDetector (acc={self.accuracy*100:.2f}%)")

    @classmethod
    def load(cls):
        obj = cls()
        data = joblib.load(MODELS_DIR / "log_anomaly_detector.pkl")
        obj.pipeline, obj.le, obj.accuracy = data["pipeline"], data["le"], data["accuracy"]
        return obj


# ─────────────────────────────────────────────────────────────────────────────
# Model 6: Threat Predictor
# ─────────────────────────────────────────────────────────────────────────────

class ThreatPredictor:
    """
    Predicts the next most likely threat category and risk trend
    based on historical threat frequency features.
    Two sub-models:
      - next_threat: multi-class classifier
      - risk_trend:  3-class classifier (Increasing/Stable/Decreasing)
    """

    FEATURE_COLS = [
        "hist_privilege_escalation", "hist_lateral_movement",
        "hist_exfiltration", "hist_command_n_control",
        "hist_persistence", "hist_defense_evasion",
        "hist_credential_access", "hist_discovery",
        "days_since_last_incident", "active_cves",
        "patch_compliance_pct", "threat_intel_score"
    ]

    def __init__(self):
        self.le_threat = LabelEncoder()
        self.le_trend = LabelEncoder()
        self.pipeline_threat = None
        self.pipeline_trend = None
        self.accuracy_threat = None
        self.accuracy_trend = None

    def _build_numeric_pipeline(self, n_classes):
        scaler = StandardScaler()
        rf = RandomForestClassifier(n_estimators=20, random_state=42, n_jobs=1)
        gb = GradientBoostingClassifier(
            n_estimators=20, max_depth=5, learning_rate=0.1, random_state=42
        )
        et = ExtraTreesClassifier(n_estimators=20, random_state=42, n_jobs=1)
        ensemble = VotingClassifier(
            estimators=[("rf", rf), ("gb", gb), ("et", et)],
            voting="soft", weights=[3, 3, 2], n_jobs=1
        )
        return Pipeline([("scaler", scaler), ("clf", ensemble)])

    def _safe_features(self, df):
        available = [c for c in self.FEATURE_COLS if c in df.columns]
        missing = [c for c in self.FEATURE_COLS if c not in df.columns]
        for m in missing:
            df[m] = 0
        return df[self.FEATURE_COLS].values

    def train(self, df):
        print_section("Training: ThreatPredictor")
        X = self._safe_features(df)
        
        # Sub-model 1: Next threat
        y_threat = self.le_threat.fit_transform(df["next_likely_threat"])
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y_threat, test_size=0.15, stratify=y_threat, random_state=42
        )
        self.pipeline_threat = self._build_numeric_pipeline(len(self.le_threat.classes_))
        print(f"  [next_threat] Training {len(self.le_threat.classes_)} classes...")
        self.pipeline_threat.fit(X_tr, y_tr)
        self.accuracy_threat = accuracy_score(y_te, self.pipeline_threat.predict(X_te))
        print(f"  [next_threat] Accuracy={self.accuracy_threat*100:.2f}%")

        # Sub-model 2: Risk trend
        y_trend = self.le_trend.fit_transform(df["risk_trend"])
        X_tr2, X_te2, y_tr2, y_te2 = train_test_split(
            X, y_trend, test_size=0.15, stratify=y_trend, random_state=42
        )
        self.pipeline_trend = self._build_numeric_pipeline(len(self.le_trend.classes_))
        print(f"  [risk_trend] Training {len(self.le_trend.classes_)} classes...")
        self.pipeline_trend.fit(X_tr2, y_tr2)
        self.accuracy_trend = accuracy_score(y_te2, self.pipeline_trend.predict(X_te2))
        print(f"  [risk_trend] Accuracy={self.accuracy_trend*100:.2f}%")

        return self

    def predict(self, features_dict):
        """
        features_dict: dict with historical threat counts and metrics.
        Returns: {"next_likely_threat": str, "risk_trend": str}
        """
        X = np.array([[features_dict.get(f, 0) for f in self.FEATURE_COLS]])
        
        threat_pred = self.pipeline_threat.predict(X)
        trend_pred = self.pipeline_trend.predict(X)
        
        threat_proba = self.pipeline_threat.predict_proba(X)[0]
        threat_ranking = sorted(
            zip(self.le_threat.classes_, threat_proba),
            key=lambda x: -x[1]
        )
        
        return {
            "next_likely_threat": self.le_threat.inverse_transform(threat_pred)[0],
            "risk_trend": self.le_trend.inverse_transform(trend_pred)[0],
            "top_3_threats": [
                {"threat": t, "probability": round(float(p), 3)}
                for t, p in threat_ranking[:3]
            ]
        }

    def save(self):
        joblib.dump({
            "pipeline_threat": self.pipeline_threat,
            "pipeline_trend": self.pipeline_trend,
            "le_threat": self.le_threat,
            "le_trend": self.le_trend,
            "accuracy_threat": self.accuracy_threat,
            "accuracy_trend": self.accuracy_trend,
            "feature_cols": self.FEATURE_COLS,
        }, MODELS_DIR / "threat_predictor.pkl")
        print(f"  ✓ Saved ThreatPredictor (threat_acc={self.accuracy_threat*100:.2f}%, "
              f"trend_acc={self.accuracy_trend*100:.2f}%)")

    @classmethod
    def load(cls):
        obj = cls()
        data = joblib.load(MODELS_DIR / "threat_predictor.pkl")
        obj.pipeline_threat = data["pipeline_threat"]
        obj.pipeline_trend = data["pipeline_trend"]
        obj.le_threat = data["le_threat"]
        obj.le_trend = data["le_trend"]
        obj.accuracy_threat = data["accuracy_threat"]
        obj.accuracy_trend = data["accuracy_trend"]
        return obj


# ─────────────────────────────────────────────────────────────────────────────
# Train All Models
# ─────────────────────────────────────────────────────────────────────────────

def train_all_models():
    print("\n" + "█"*60)
    print("  AutoMITRE AI Models — Training Pipeline")
    print("█"*60)

    results = {}

    # Load datasets
    df_tc = pd.read_csv(DATA_DIR / "threat_classification.csv")
    df_fm = pd.read_csv(DATA_DIR / "framework_mapping.csv")
    df_ss = pd.read_csv(DATA_DIR / "severity_scoring.csv")
    df_tp = pd.read_csv(DATA_DIR / "threat_prediction.csv")
    df_pcap = pd.read_csv(DATA_DIR / "pcap_features.csv")
    df_log = pd.read_csv(DATA_DIR / "log_analysis.csv")

    # 1. Threat Classifier
    tc = ThreatClassifier().train(df_tc)
    tc.save()
    results["ThreatClassifier"] = {"accuracy": tc.accuracy, "f1": tc.f1}

    # 2. Framework Mapper
    fm = FrameworkMapper().train(df_fm)
    fm.save()
    results["FrameworkMapper"] = {k: v for k, v in fm.accuracies.items()}

    # 3. Severity Scorer
    ss = SeverityScorer().train(df_ss)
    ss.save()
    results["SeverityScorer"] = {"accuracy": ss.accuracy}

    # 4. PCAP Analyzer
    pa = PcapAnalyzer().train(df_pcap)
    pa.save()
    results["PcapAnalyzer"] = {"accuracy": pa.accuracy}

    # 5. Log Anomaly Detector
    lad = LogAnomalyDetector().train(df_log)
    lad.save()
    results["LogAnomalyDetector"] = {"accuracy": lad.accuracy}

    # 6. Threat Predictor
    tpred = ThreatPredictor().train(df_tp)
    tpred.save()
    results["ThreatPredictor"] = {
        "accuracy_threat": tpred.accuracy_threat,
        "accuracy_trend": tpred.accuracy_trend
    }

    # Save summary
    summary = {"models": results, "model_dir": str(MODELS_DIR)}
    with open(MODELS_DIR / "training_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print_section("TRAINING COMPLETE — Model Accuracy Summary")
    for model, metrics in results.items():
        for k, v in metrics.items():
            print(f"  {model}.{k} = {float(v)*100:.2f}%")

    return tc, fm, ss, pa, lad, tpred


# ─────────────────────────────────────────────────────────────────────────────
# AutoMITRE Engine — unified inference interface
# ─────────────────────────────────────────────────────────────────────────────

class AutoMITREEngine:
    """
    Unified engine that loads all trained models and provides
    a single .analyze() method compatible with the REST API.
    """

    def __init__(self):
        self.threat_classifier = ThreatClassifier.load()
        self.framework_mapper = FrameworkMapper.load()
        self.severity_scorer = SeverityScorer.load()
        self.pcap_analyzer = PcapAnalyzer.load()
        self.log_detector = LogAnomalyDetector.load()
        self.threat_predictor = ThreatPredictor.load()
        print("✓ AutoMITRE Engine loaded — all 6 models ready")

    def analyze_text(self, text: str) -> dict:
        """Full analysis pipeline for text-based threat input."""
        threat_type = self.threat_classifier.predict(text)[0]
        threat_proba = self.threat_classifier.predict_proba(text)[0]
        severity = self.severity_scorer.predict(text)[0]
        severity_proba = self.severity_scorer.predict_proba(text)[0]
        framework_map = self.framework_mapper.predict(text)[0]
        
        confidence = max(threat_proba.values())

        return {
            "input_type": "text",
            "threat_category": threat_type,
            "confidence": round(confidence, 3),
            "severity": severity,
            "severity_probabilities": {k: round(v, 3) for k, v in severity_proba.items()},
            "framework_mappings": {
                "mitre_attck": {
                    "technique_id": framework_map["attck"],
                    "tactic": threat_type.lower().replace(" ", "-"),
                },
                "mitre_d3fend": framework_map["d3fend"],
                "nist_800_53": framework_map["nist"],
                "owasp_asvs": framework_map["owasp"],
            },
            "top_threat_categories": sorted(
                [{"category": k, "probability": round(v, 3)} for k, v in threat_proba.items()],
                key=lambda x: -x["probability"]
            )[:3],
        }

    def analyze_log(self, log_text: str) -> dict:
        """Analyze a single log entry."""
        label = self.log_detector.predict(log_text)[0]
        proba = self.log_detector.predict_proba(log_text)[0]
        
        if label == "Malicious":
            text_analysis = self.analyze_text(log_text)
        else:
            text_analysis = None

        return {
            "input_type": "log",
            "anomaly_detected": label == "Malicious",
            "label": label,
            "confidence": round(max(proba.values()), 3),
            "threat_analysis": text_analysis,
        }

    def analyze_pcap_features(self, features: dict) -> dict:
        """Analyze extracted PCAP features."""
        traffic_type = self.pcap_analyzer.predict(features)[0]
        proba = self.pcap_analyzer.predict_proba(features)[0]

        is_malicious = traffic_type != "Normal"
        threat_analysis = None
        if is_malicious:
            threat_analysis = self.analyze_text(f"{traffic_type} network traffic detected")

        return {
            "input_type": "pcap",
            "traffic_type": traffic_type,
            "is_malicious": is_malicious,
            "confidence": round(max(proba.values()), 3),
            "all_probabilities": {k: round(v, 3) for k, v in sorted(
                proba.items(), key=lambda x: -x[1])},
            "threat_analysis": threat_analysis,
        }

    def predict_threats(self, historical_features: dict) -> dict:
        """Predict next likely threats based on historical data."""
        return self.threat_predictor.predict(historical_features)

    def full_analysis(self, input_data: dict) -> dict:
        """
        Master analysis entrypoint.
        input_data should have 'type' key: 'text' | 'log' | 'pcap' | 'prediction'
        """
        input_type = input_data.get("type", "text")
        
        if input_type == "text":
            result = self.analyze_text(input_data["content"])
        elif input_type == "log":
            result = self.analyze_log(input_data["content"])
        elif input_type == "pcap":
            result = self.analyze_pcap_features(input_data["features"])
        elif input_type == "prediction":
            result = self.predict_threats(input_data["features"])
        else:
            result = {"error": f"Unknown input type: {input_type}"}

        return result


if __name__ == "__main__":
    train_all_models()
