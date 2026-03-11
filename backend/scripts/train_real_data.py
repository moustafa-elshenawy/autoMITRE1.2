#!/usr/bin/env python3
"""
train_real_data.py — autoMITRE Enhanced Training Pipeline v2
==============================================================
Downloads public cybersecurity datasets and trains all ML models:

  1. TextSeverityClassifier — NVD CVE 2020-2024 descriptions + CVSS scores (20K+)
  2. Numerical XGBoost      — CVE-derived 5-feature severity regressor (replaces synthetic)
  3. attack_keywords.json   — MITRE ATT&CK STIX technique keyword expansion
  4. Isolation Forest        — NSL-KDD real network intrusion data
  5. CICIDS Isolation Forest — CICIDS 2017 Kaggle network flow anomaly model (optional)

Run from backend dir:
    source venv/bin/activate
    python scripts/train_real_data.py
"""
import os, sys, json, pickle, time, logging, re
import requests
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("train")

DATA_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
RAW_DIR   = os.path.join(DATA_DIR, "raw")
MODEL_DIR = os.path.join(DATA_DIR, "models")
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

# Evaluation results collector
EVAL_RESULTS = {}


# ─────────────────────────────────────────────────────────────
# PHASE 1 — Download / Cache Datasets
# ─────────────────────────────────────────────────────────────

def load_cve_data(max_results=50000):
    """Load CVE records with CVSS scores from Kaggle CSV dataset.
    
    Primary source: Kaggle CVE & CWE Dataset (1999-2025) — 280K+ entries
    Fallback: cached NVD API JSON if available
    
    Prefers CVSS v3 scores; falls back to v2 if v3 unavailable.
    """
    import pandas as pd

    cache = os.path.join(RAW_DIR, "nvd_cves.json")
    
    # Try Kaggle CSV first (much larger and doesn't require API calls)
    kaggle_csv = os.path.join(RAW_DIR, "kaggle_cve2", "CVE_CWE_2025.csv")
    if os.path.exists(kaggle_csv):
        log.info(f"Loading CVE data from Kaggle CSV: {kaggle_csv}")
        df = pd.read_csv(kaggle_csv, usecols=['CVE-ID', 'CVSS-V3', 'CVSS-V2', 'DESCRIPTION'])
        
        records = []
        for _, row in df.iterrows():
            desc = str(row.get('DESCRIPTION', ''))
            if len(desc) < 30:
                continue
            
            # Prefer CVSS v3, fallback to v2
            score = row.get('CVSS-V3')
            if pd.isna(score):
                score = row.get('CVSS-V2')
            if pd.isna(score):
                continue
            
            score = float(score)
            if 0 <= score <= 10:
                records.append({"text": desc, "score": score})
        
        log.info(f"Kaggle CVE: loaded {len(records)} records with CVSS scores")
        
        # Subsample if too many (for training efficiency)
        if len(records) > max_results:
            import random
            random.seed(42)
            records = random.sample(records, max_results)
            log.info(f"Subsampled to {max_results} records for training efficiency")
        
        # Cache as JSON for future fast loading
        with open(cache, "w") as f:
            json.dump(records, f)
        return records
    
    # Fallback: use cached NVD API data if available
    if os.path.exists(cache):
        with open(cache) as f:
            records = json.load(f)
        log.info(f"Loading cached NVD CVEs: {len(records)} records")
        return records
    
    # If no data at all, try downloading from Kaggle
    log.info("No cached CVE data found. Attempting Kaggle download…")
    try:
        import kaggle
        kaggle.api.authenticate()
        kaggle_dir = os.path.join(RAW_DIR, "kaggle_cve2")
        os.makedirs(kaggle_dir, exist_ok=True)
        kaggle.api.dataset_download_files(
            "stanislavvinokur/cve-and-cwe-dataset-1999-2025",
            path=kaggle_dir, unzip=True
        )
        # Recurse to load the just-downloaded file
        return load_cve_data(max_results)
    except Exception as e:
        log.error(f"Could not load CVE data: {e}")
        log.error("Please download from: kaggle datasets download -d stanislavvinokur/cve-and-cwe-dataset-1999-2025")
        return []

def fetch_attack_stix():
    """Download MITRE ATT&CK Enterprise STIX bundle from GitHub."""
    cache = os.path.join(RAW_DIR, "enterprise_attack.json")
    if os.path.exists(cache):
        log.info(f"Loading cached ATT&CK STIX from {cache}")
        with open(cache) as f:
            return json.load(f)

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    log.info("Downloading MITRE ATT&CK Enterprise STIX bundle (~25 MB)…")
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    data = r.json()
    with open(cache, "w") as f:
        json.dump(data, f)
    log.info(f"ATT&CK STIX: {len(data.get('objects', []))} STIX objects downloaded")
    return data


def fetch_nslkdd():
    """Download NSL-KDD training set (CSV format)."""
    cache  = os.path.join(RAW_DIR, "KDDTrain+.txt")
    if os.path.exists(cache):
        log.info(f"Loading cached NSL-KDD from {cache}")
    else:
        url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
        log.info("Downloading NSL-KDD training set…")
        r = requests.get(url, timeout=120)
        r.raise_for_status()
        with open(cache, "wb") as f:
            f.write(r.content)
        log.info(f"NSL-KDD downloaded ({len(r.content)//1024} KB)")
    return cache


def fetch_cicids_2017():
    """Download CICIDS 2017 dataset from Kaggle (requires kaggle credentials).
    
    Uses a smaller subset (~17MB) for practical training.
    Falls back gracefully if Kaggle is not available.
    """
    cache_dir = os.path.join(RAW_DIR, "cicids2017")
    # Check if we already have CSV files
    if os.path.exists(cache_dir):
        csvs = [f for f in os.listdir(cache_dir) if f.endswith('.csv')]
        if csvs:
            log.info(f"Loading cached CICIDS 2017: {len(csvs)} CSV files in {cache_dir}")
            return cache_dir

    try:
        import kaggle
        os.makedirs(cache_dir, exist_ok=True)
        log.info("Downloading CICIDS 2017 from Kaggle (Thursday subset ~17MB)…")
        # Use a smaller subset for practical training
        kaggle.api.authenticate()
        kaggle.api.dataset_download_files(
            "sweety18/cicids2017-thu",
            path=cache_dir,
            unzip=True
        )
        csvs = [f for f in os.listdir(cache_dir) if f.endswith('.csv')]
        log.info(f"CICIDS 2017 downloaded: {len(csvs)} CSV files")
        return cache_dir
    except ImportError:
        log.warning("kaggle package not installed — skipping CICIDS download")
        return None
    except Exception as e:
        log.warning(f"CICIDS 2017 download failed: {e}")
        log.warning("Skipping CICIDS — will use NSL-KDD only for anomaly detection")
        return None


# ─────────────────────────────────────────────────────────────
# PHASE 2 — Train TextSeverityClassifier on NVD CVEs (Improved)
# ─────────────────────────────────────────────────────────────

def train_text_severity(records):
    """Train TF-IDF + XGBoost on CVE text → CVSS score regression.
    
    Improvements over v1:
    - Increased max_features (12K vs 8K)
    - 5-fold cross-validation for model selection
    - Stratified train/test split by CVSS score bins
    - Per-severity-bin evaluation metrics
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
    import xgboost as xgb
    import scipy.sparse

    log.info(f"Training TextSeverityClassifier on {len(records)} CVE records…")

    texts  = [r["text"] for r in records]
    scores = np.array([r["score"] for r in records])

    # Create severity bins for stratified splitting
    bins = np.digitize(scores, bins=[0, 4.0, 7.0, 9.0, 10.1]) - 1  # 0=Low, 1=Med, 2=High, 3=Crit

    # TF-IDF — enhanced cybersecurity-aware settings
    tfidf = TfidfVectorizer(
        max_features=12000,           # Increased from 8K for richer vocabulary
        ngram_range=(1, 2),           # unigrams + bigrams
        min_df=2,                     # Lower threshold for rare but important terms
        max_df=0.85,
        sublinear_tf=True,
        stop_words="english",
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_\-]{2,}\b",
    )
    X = tfidf.fit_transform(texts)

    # Stratified split by CVSS bins
    X_tr, X_val, y_tr, y_val, bins_tr, bins_val = train_test_split(
        X, scores, bins, test_size=0.15, random_state=42, stratify=bins
    )

    model = xgb.XGBRegressor(
        objective="reg:squarederror",
        n_estimators=500,             # Increased from 400
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.7,
        min_child_weight=5,
        reg_alpha=0.1,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )

    # 5-fold cross-validation on training set
    log.info("Running 5-fold cross-validation…")
    kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(
        model, scipy.sparse.csr_matrix(X_tr), y_tr,
        cv=kfold.split(X_tr, bins_tr),
        scoring='neg_mean_absolute_error',
        n_jobs=-1
    )
    log.info(f"CV MAE: {-cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    # Train final model on full training set
    model.fit(scipy.sparse.csr_matrix(X_tr), y_tr, verbose=False)

    preds = model.predict(scipy.sparse.csr_matrix(X_val))
    preds = np.clip(preds, 0, 10)
    mae   = mean_absolute_error(y_val, preds)
    rmse  = np.sqrt(mean_squared_error(y_val, preds))
    r2    = r2_score(y_val, preds)

    log.info(f"TextSeverity — MAE: {mae:.3f} | RMSE: {rmse:.3f} | R²: {r2:.3f}")

    # Per-severity-bin evaluation
    bin_names = ["Low (0-3.9)", "Medium (4-6.9)", "High (7-8.9)", "Critical (9-10)"]
    per_bin = {}
    for bin_idx, bin_name in enumerate(bin_names):
        mask = bins_val == bin_idx
        if mask.sum() > 0:
            bin_mae = mean_absolute_error(y_val[mask], preds[mask])
            per_bin[bin_name] = {"count": int(mask.sum()), "mae": round(bin_mae, 3)}
            log.info(f"  {bin_name}: MAE={bin_mae:.3f} (n={mask.sum()})")

    # Save models
    tfidf_path = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
    xgb_path   = os.path.join(MODEL_DIR, "text_severity_xgb.json")
    with open(tfidf_path, "wb") as f:
        pickle.dump(tfidf, f)
    model.save_model(xgb_path)
    log.info(f"Saved: {tfidf_path}\nSaved: {xgb_path}")

    EVAL_RESULTS["text_severity"] = {
        "train_size": int(X_tr.shape[0]),
        "val_size": int(X_val.shape[0]),
        "tfidf_features": int(X.shape[1]),
        "mae": round(mae, 4),
        "rmse": round(rmse, 4),
        "r2": round(r2, 4),
        "cv_mae_mean": round(-cv_scores.mean(), 4),
        "cv_mae_std": round(cv_scores.std(), 4),
        "per_bin": per_bin
    }

    return mae, r2


# ─────────────────────────────────────────────────────────────
# PHASE 3 — CVE-Derived Numerical XGBoost (replaces synthetic)
# ─────────────────────────────────────────────────────────────

# Critical keywords that indicate high-severity threats
_CRITICAL_PATTERNS = re.compile(
    r'(remote code execution|arbitrary code|buffer overflow|heap overflow'
    r'|stack overflow|use.after.free|privilege escalation|authentication bypass'
    r'|sql injection|command injection|code injection|rce|root access'
    r'|zero.day|0.day|unauthenticated|pre.auth)',
    re.IGNORECASE
)

_NETWORK_PATTERNS = re.compile(
    r'(network|http|https|tcp|udp|dns|smtp|ssh|ftp|ssl|tls'
    r'|remote|server|client|request|packet|socket|port|web)',
    re.IGNORECASE
)

_ENTITY_PATTERNS = re.compile(
    r'(CVE-\d{4}-\d+|CWE-\d+|[A-Z][a-z]+(?:SQL|XSS|CSRF|RCE|LFI|RFI))',
    re.IGNORECASE
)

def _extract_numerical_features_from_cve(text):
    """Extract 5 numerical features from a CVE description.
    
    These features match the schema used by ml_engine._extract_features():
      0: text_length      — proxy for threat complexity
      1: entity_count     — number of CVE/CWE/technical references
      2: keyword_severity — heuristic severity score (0-10) from critical keywords
      3: has_critical      — binary: contains RCE, auth bypass, etc.
      4: has_network       — binary: contains network/web indicators
    """
    text_length = len(text)
    entity_count = len(_ENTITY_PATTERNS.findall(text))
    has_critical = 1.0 if _CRITICAL_PATTERNS.search(text) else 0.0
    has_network = 1.0 if _NETWORK_PATTERNS.search(text) else 0.0

    # Heuristic severity: count critical keyword matches and scale 0-10
    critical_matches = len(_CRITICAL_PATTERNS.findall(text))
    keyword_severity = min(10.0, critical_matches * 2.5 + (has_network * 1.5))

    return [text_length, entity_count, keyword_severity, has_critical, has_network]


def train_numerical_xgboost(records):
    """Train the 5-feature numerical XGBoost on CVE-derived features.
    
    This replaces the synthetic baseline_training() in ml_engine.py with
    a model trained on real CVE descriptions mapped to their CVSS scores.
    """
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
    import xgboost as xgb

    log.info(f"Training numerical XGBoost on {len(records)} CVE-derived features…")

    X_rows = []
    y_scores = []
    for rec in records:
        features = _extract_numerical_features_from_cve(rec["text"])
        X_rows.append(features)
        y_scores.append(rec["score"])

    X = np.array(X_rows, dtype=float)
    y = np.array(y_scores, dtype=float)
    X = np.clip(X, 0, None)

    X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=0.15, random_state=42)

    model = xgb.XGBRegressor(
        objective="reg:squarederror",
        n_estimators=200,
        max_depth=4,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.8,
        min_child_weight=3,
        reg_alpha=0.05,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    model.fit(X_tr, y_tr, verbose=False)

    preds = np.clip(model.predict(X_val), 0, 10)
    mae  = mean_absolute_error(y_val, preds)
    rmse = np.sqrt(mean_squared_error(y_val, preds))
    r2   = r2_score(y_val, preds)

    log.info(f"Numerical XGBoost — MAE: {mae:.3f} | RMSE: {rmse:.3f} | R²: {r2:.3f}")

    # Feature importance
    importances = model.feature_importances_
    feature_names = ["text_length", "entity_count", "keyword_severity", "has_critical", "has_network"]
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
        log.info(f"  Feature '{name}': importance = {imp:.4f}")

    # ==============================================================
    # FIX: Train Text Isolation Forest on the same CVE features
    # ==============================================================
    from sklearn.ensemble import IsolationForest
    import pickle
    log.info(f"Training Text Isolation Forest on {len(X)} CVE records…")
    
    # We set contamination to ~15% to flag the most complex/critical CVEs as anomalous
    text_iforest = IsolationForest(
        n_estimators=300,
        contamination=0.15,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )
    text_iforest.fit(X)
    
    # Save the new text isolation forest
    text_iforest_path = os.path.join(MODEL_DIR, "text_isolation_forest.pkl")
    with open(text_iforest_path, "wb") as f:
        pickle.dump(text_iforest, f)
    log.info(f"Saved Text Isolation Forest → {text_iforest_path}")

    # Save XGBoost
    xgb_path = os.path.join(MODEL_DIR, "xgboost_severity.json")
    model.save_model(xgb_path)
    log.info(f"Saved Numerical XGBoost → {xgb_path}")

    EVAL_RESULTS["numerical_xgboost"] = {
        "train_size": int(X_tr.shape[0]),
        "val_size": int(X_val.shape[0]),
        "mae": round(mae, 4),
        "rmse": round(rmse, 4),
        "r2": round(r2, 4),
        "feature_importance": {n: round(float(i), 4) for n, i in zip(feature_names, importances)}
    }

    return mae, r2


# ─────────────────────────────────────────────────────────────
# PHASE 4 — Expand Threat Keywords from ATT&CK STIX
# ─────────────────────────────────────────────────────────────

TACTIC_TO_CATEGORY = {
    "initial-access":        "web_attack",
    "execution":             "malware",
    "persistence":           "persistence",
    "privilege-escalation":  "privilege_escalation",
    "defense-evasion":       "malware",
    "credential-access":     "credential_attack",
    "discovery":             "network_attack",
    "lateral-movement":      "lateral_movement",
    "collection":            "data_exfiltration",
    "command-and-control":   "command_control",
    "exfiltration":          "data_exfiltration",
    "impact":                "impact",
}

STOPWORDS = {
    "the","a","an","and","or","is","in","of","to","for","with","that","this",
    "are","as","by","be","it","at","from","on","can","may","also","which",
    "use","used","via","using","such","these","have","has","its","into","when",
    "often","other","use","their","through","both","more","if","then","not",
    "all","any","been","each","after","about","will","would","should","could",
    "adversaries","attacker","attackers","threat","malicious","actor",
    "system","systems","access","data","based","include","may",
}

def extract_attack_keywords(stix_data):
    """Extract top discriminative keywords per threat category from ATT&CK descriptions."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from collections import defaultdict

    log.info("Extracting keywords from MITRE ATT&CK STIX…")

    cat_docs = defaultdict(list)
    technique_count = 0
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name", "")
        desc = obj.get("description", "")
        if not desc:
            continue
        for phase in obj.get("kill_chain_phases", []):
            tactic = phase.get("phase_name", "")
            cat    = TACTIC_TO_CATEGORY.get(tactic)
            if cat:
                clean = re.sub(r'\[.*?\]\(.*?\)', '', desc)
                clean = re.sub(r'#{1,6}\s*', '', clean)
                clean = re.sub(r'\*+', '', clean)
                cat_docs[cat].append(f"{name} {clean}")
                technique_count += 1

    log.info(f"ATT&CK: {technique_count} technique-tactic pairs across {len(cat_docs)} categories")

    expanded = {}
    all_docs  = []
    doc_labels = []
    for cat, docs in cat_docs.items():
        for d in docs:
            all_docs.append(d)
            doc_labels.append(cat)

    tfidf = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        min_df=2,
        stop_words="english",
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z]{2,}\b",
    )
    X = tfidf.fit_transform(all_docs)
    vocab = {v: k for k, v in tfidf.vocabulary_.items()}

    cats = sorted(set(doc_labels))
    for cat in cats:
        idxs = [i for i, l in enumerate(doc_labels) if l == cat]
        cat_matrix = X[idxs]
        scores_arr = np.asarray(cat_matrix.sum(axis=0)).flatten()
        top_indices = scores_arr.argsort()[::-1][:60]
        keywords = []
        for idx in top_indices:
            word = vocab.get(idx, "")
            tokens = word.split()
            if (len(word) > 3
                    and all(t not in STOPWORDS for t in tokens)
                    and not any(c.isdigit() for c in word)):
                keywords.append(word.lower())
            if len(keywords) >= 40:
                break
        expanded[cat] = keywords
        log.info(f"  {cat}: {len(keywords)} keywords extracted")

    out_path = os.path.join(DATA_DIR, "attack_keywords.json")
    with open(out_path, "w") as f:
        json.dump(expanded, f, indent=2)
    log.info(f"Saved expanded keywords → {out_path}")

    EVAL_RESULTS["attack_keywords"] = {
        "total_keywords": sum(len(v) for v in expanded.values()),
        "categories": len(expanded),
        "technique_pairs": technique_count
    }

    return expanded


# ─────────────────────────────────────────────────────────────
# PHASE 5 — Retrain Isolation Forest on NSL-KDD
# ─────────────────────────────────────────────────────────────

NSL_COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

def train_nslkdd_classifier(data_path):
    import xgboost as xgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix

    log.info("Loading NSL-KDD dataset for supervised training…")
    rows = []
    with open(data_path) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 42:
                rows.append(parts[:42])

    records = []
    for r in rows:
        try:
            records.append(dict(zip(NSL_COLS, r)))
        except:
            pass

    log.info(f"NSL-KDD: {len(records)} records loaded")

    X_rows, y_labels = [], []
    for rec in records:
        try:
            src_bytes        = min(float(rec["src_bytes"]), 1e6) / 1e6 * 1500
            failed_logins    = min(float(rec["num_failed_logins"]) + float(rec["num_compromised"]), 20)
            dst_bytes_score  = min(float(rec["dst_bytes"]) / 100000.0 * 10, 10)
            has_root         = float(rec["root_shell"]) or float(rec["su_attempted"])
            logged_in        = float(rec["logged_in"])
            label            = rec["label"].strip().strip("'\"")
            X_rows.append([src_bytes, failed_logins, dst_bytes_score, has_root, logged_in])
            y_labels.append(0 if label == "normal" else 1)
        except:
            pass

    X = np.array(X_rows, dtype=float)
    y = np.array(y_labels, dtype=int)
    X = np.clip(X, 0, None)

    X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    log.info("Training Supervised NSL-KDD XGBoost Classifier…")
    model = xgb.XGBClassifier(
        objective="binary:logistic",
        n_estimators=500,
        max_depth=5,
        learning_rate=0.1,
        random_state=42,
        n_jobs=-1,
        verbosity=0
    )
    model.fit(X_tr, y_tr)

    preds = model.predict(X_val)
    report = classification_report(y_val, preds, target_names=["Normal", "Attack"], output_dict=True)
    log.info("\n" + classification_report(y_val, preds, target_names=["Normal", "Attack"]))

    cm = confusion_matrix(y_val, preds)
    tn, fp, fn, tp = cm.ravel()
    
    model_path = os.path.join(MODEL_DIR, "nsl_kdd_classifier.json")
    model.save_model(model_path)
    log.info(f"Saved NSL-KDD Classifier → {model_path}")

    EVAL_RESULTS["nsl_kdd_classifier"] = {
        "total_samples": len(y),
        "attack_recall": round(report["Attack"]["recall"], 4),
        "attack_precision": round(report["Attack"]["precision"], 4),
        "attack_f1": round(report["Attack"]["f1-score"], 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    }

    return report["Attack"]["f1-score"], cm


# ─────────────────────────────────────────────────────────────
# PHASE 6 — CICIDS 2017 Enhanced Anomaly Detection (Kaggle)
# ─────────────────────────────────────────────────────────────

def train_cicids_classifier(cicids_dir):
    import pandas as pd
    import xgboost as xgb
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split

    log.info("Loading CICIDS 2017 data for supervised training…")
    dfs = []
    for f in sorted(os.listdir(cicids_dir)):
        if f.endswith('.csv'):
            try:
                df = pd.read_csv(os.path.join(cicids_dir, f), low_memory=False, encoding='utf-8')
                dfs.append(df)
            except Exception as e:
                log.warning(f"  Could not read {f}: {e}")

    if not dfs: return None, None
    data = pd.concat(dfs, ignore_index=True)
    data.columns = data.columns.str.strip()
    label_col = next((c for c in data.columns if 'label' in c.lower()), None)
    if label_col is None: return None, None

    data['is_attack'] = (data[label_col].str.strip() != 'BENIGN').astype(int)
    numeric_cols = data.select_dtypes(include=[np.number]).columns.tolist()
    feature_cols = [c for c in numeric_cols if c != 'is_attack']
    data[feature_cols] = data[feature_cols].replace([np.inf, -np.inf], np.nan)
    valid_cols = [c for c in feature_cols if data[c].isna().mean() < 0.5]

    X = data[valid_cols].fillna(0).values
    y = data['is_attack'].values

    if len(X) > 100000:
        rng = np.random.RandomState(42)
        idx = rng.choice(len(X), size=100000, replace=False)
        X, y = X[idx], y[idx]

    X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_tr)
    X_val = scaler.transform(X_val)

    log.info("Training Supervised CICIDS XGBoost Classifier…")
    model = xgb.XGBClassifier(n_estimators=300, max_depth=5, learning_rate=0.1, n_jobs=-1)
    model.fit(X_tr, y_tr)

    preds = model.predict(X_val)
    report = classification_report(y_val, preds, target_names=["Benign", "Attack"], output_dict=True)
    log.info("\n" + classification_report(y_val, preds, target_names=["Benign", "Attack"]))

    cm = confusion_matrix(y_val, preds)
    tn, fp, fn, tp = cm.ravel()
    
    model_path = os.path.join(MODEL_DIR, "cicids_classifier.json")
    model.save_model(model_path)
    with open(os.path.join(MODEL_DIR, "cicids_scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(MODEL_DIR, "cicids_features.json"), "w") as f:
        json.dump(valid_cols, f)

    EVAL_RESULTS["cicids_classifier"] = {
        "total_samples": len(y),
        "attack_recall": round(report["Attack"]["recall"], 4) if "Attack" in report else 0,
        "attack_precision": round(report["Attack"]["precision"], 4) if "Attack" in report else 0,
        "attack_f1": round(report["Attack"]["f1-score"], 4) if "Attack" in report else 0,
        "features": len(valid_cols)
    }
    return report["Attack"]["f1-score"] if "Attack" in report else 0, cm


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*65)
    print("  autoMITRE Enhanced Training Pipeline v2")
    print("="*65)

    # Phase 1: Download all datasets
    print("\n[Phase 1] Downloading datasets…")
    print("-"*65)
    nvd_records  = load_cve_data(max_results=50000)
    stix_data    = fetch_attack_stix()
    nslkdd_path  = fetch_nslkdd()
    cicids_dir   = fetch_cicids_2017()

    # Phase 2: TextSeverityClassifier (NVD CVE — expanded)
    print(f"\n[Phase 2] Training TextSeverityClassifier on {len(nvd_records)} CVEs…")
    print("-"*65)
    if len(nvd_records) < 100:
        print("  WARNING: Too few NVD records — skipping TextSeverity training")
        text_mae, text_r2 = None, None
    else:
        text_mae, text_r2 = train_text_severity(nvd_records)

    # Phase 3: Numerical XGBoost (CVE-derived, replaces synthetic)
    print(f"\n[Phase 3] Training Numerical XGBoost on CVE-derived features…")
    print("-"*65)
    if len(nvd_records) < 100:
        print("  WARNING: Too few records — skipping Numerical XGBoost training")
        num_mae, num_r2 = None, None
    else:
        num_mae, num_r2 = train_numerical_xgboost(nvd_records)

    # Phase 4: ATT&CK Keywords
    print("\n[Phase 4] Extracting ATT&CK Technique Keywords…")
    print("-"*65)
    expanded_kw = extract_attack_keywords(stix_data)

    # Phase 5: NSL-KDD XGBoost Classifier
    print("\n[Phase 5] Training Supervised Classifier on NSL-KDD…")
    print("-"*65)
    nsl_f1, nsl_cm = train_nslkdd_classifier(nslkdd_path)

    # Phase 6: CICIDS 2017 XGBoost Classifier
    cicids_f1 = None
    if cicids_dir:
        print("\n[Phase 6] Training Supervised Classifier on CICIDS 2017…")
        print("-"*65)
        cicids_f1, cicids_cm = train_cicids_classifier(cicids_dir)
    else:
        print("\n[Phase 6] Skipped — CICIDS 2017 not available")

    # Save evaluation report
    report_path = os.path.join(DATA_DIR, "training_report.json")
    with open(report_path, "w") as f:
        json.dump(EVAL_RESULTS, f, indent=2)
    log.info(f"Evaluation report saved → {report_path}")

    # Summary
    print("\n" + "="*65)
    print("  TRAINING COMPLETE — v2 Enhanced Pipeline")
    print("="*65)
    if text_mae is not None:
        print(f"  TextSeverityClassifier    MAE={text_mae:.3f}  R²={text_r2:.3f}")
    if num_mae is not None:
        print(f"  Numerical XGBoost         MAE={num_mae:.3f}  R²={num_r2:.3f}")
    print(f"  ATT&CK Keywords           {sum(len(v) for v in expanded_kw.values())} keywords / {len(expanded_kw)} categories")
    print(f"  Anomaly Classifier (NSL-KDD)  F1-Score={nsl_f1*100:.1f}%")
    if cicids_f1 is not None:
        print(f"  Anomaly Classifier (CICIDS)   F1-Score={cicids_f1*100:.1f}%")
    else:
        print(f"  Anomaly Classifier (CICIDS)   Skipped")
    print(f"\n  Models saved to: backend/data/models/")
    print(f"  Evaluation report: backend/data/training_report.json")
    print("="*65)
