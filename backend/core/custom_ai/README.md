# AutoMITRE AI Models — Complete Package

## Model Accuracy Summary

| Model | Metric | Accuracy |
|-------|--------|----------|
| ThreatClassifier | 13 threat categories | **100.00%** |
| FrameworkMapper — ATT&CK | 13 techniques | **100.00%** |
| FrameworkMapper — D3FEND | 11 techniques | **100.00%** |
| FrameworkMapper — NIST | 13 controls | **100.00%** |
| FrameworkMapper — OWASP | 13 requirements | **100.00%** |
| LogAnomalyDetector | Malicious vs Benign | **100.00%** |
| PcapAnalyzer | 8 traffic types | **99.89%** |
| ThreatPredictor — Next Threat | 8 categories | **100.00%** |
| ThreatPredictor — Risk Trend | 3 classes | **92.27%** |
| SeverityScorer | Critical/High/Med/Low | **85.44%** |

**Average across all metrics: 97.76%**

---

## Project Structure

```
automitre/
├── models/
│   ├── ai_models.py              # Model class definitions
│   ├── train_fast.py             # Fast training runner
│   ├── train_improved.py         # Improved dataset + retrain
│   ├── threat_classifier.pkl     # Trained model
│   ├── severity_scorer.pkl       # Trained model
│   ├── framework_mapper.pkl      # Trained model (4 frameworks)
│   ├── log_anomaly_detector.pkl  # Trained model
│   ├── pcap_analyzer.pkl         # Trained model
│   ├── threat_predictor.pkl      # Trained model
│   └── training_summary.json     # Accuracy summary
├── data/
│   ├── dataset_generator.py      # Synthetic data generator
│   ├── threat_classification.csv
│   ├── framework_mapping.csv
│   ├── severity_scoring.csv
│   ├── threat_prediction.csv
│   ├── pcap_features.csv
│   ├── log_analysis.csv
│   └── dataset_guide.json        # Real dataset recommendations
├── api/
│   └── automitre_api.py          # Unified analyzer + FastAPI routes
└── tests/
    └── test_models.py            # Full test suite
```

---

## Quick Integration

```python
from api.automitre_api import AutoMITREAnalyzer

analyzer = AutoMITREAnalyzer(models_dir="./models")

# Analyze threat text
result = analyzer.analyze({
    "type": "text",
    "content": "Ransomware LockBit encrypting files across 50 hosts"
})
# → threat_category: Impact, severity: Critical, ATT&CK: T1486

# Analyze log entry
result = analyzer.analyze({
    "type": "log",
    "content": "SQL injection attempt detected in parameter id: ' OR 1=1--"
})
# → is_malicious: True, confidence: 99.8%

# Analyze PCAP features
result = analyzer.analyze({
    "type": "pcap",
    "features": {
        "pkt_len_mean": 55, "pkt_rate": 50000, "flow_duration": 0.01,
        "dst_port_entropy": 0.05, "payload_entropy": 0.5,
        "syn_flag_ratio": 0.95, "bytes_per_second": 50000000,
        "unique_dst_ips": 2, "failed_conn_ratio": 0.85, "avg_ttl": 50
    }
})
# → traffic_type: DDoS, is_malicious: True

# Predict next threats
result = analyzer.analyze({
    "type": "prediction",
    "features": {
        "hist_command_n_control": 40, "active_cves": 12,
        "patch_compliance_pct": 62, "threat_intel_score": 0.88, ...
    }
})
# → next_likely_threat: Command & Control, risk_trend: Increasing

# Export to STIX 2.1
stix = analyzer.export_stix(result)

# Export to SIEM-compatible JSON (Splunk/QRadar/Elastic/Wazuh)
siem_event = analyzer.export_siem_json(result)
```

---

## FastAPI Integration

Copy the routes from `api/automitre_api.py` → `FASTAPI_ROUTES` string
into your `main.py`, or use this minimal example:

```python
from fastapi import FastAPI
from api.automitre_api import AutoMITREAnalyzer

app = FastAPI()
analyzer = AutoMITREAnalyzer()

@app.post("/api/analyze")
async def analyze(request: dict):
    return analyzer.analyze(request)
```

---

## Recommended Real Datasets (Production)

For production-level accuracy on real-world cybersecurity data,
replace the synthetic training data with:

### Threat Classification & NLP
- **CICIDS2017/2018** — Canadian Institute Intrusion Detection Dataset
- **UNSW-NB15** — Network traffic with 9 real attack categories
- **NSL-KDD** — Classic network intrusion benchmark
- **CTI Corpus** — Cybersecurity threat intelligence NLP dataset
- **MITRE ATT&CK STIX** — https://github.com/mitre/cti (free)

### Framework Mapping
- **MITRE ATT&CK Enterprise JSON** — https://attack.mitre.org/resources/
- **MITRE D3FEND Ontology** — https://d3fend.mitre.org/
- **NVD CVE Database** — https://nvd.nist.gov/ (free API)

### PCAP / Network Traffic
- **PCAP-ISCX dataset** — Labeled network captures
- **CTU-13** — Botnet traffic dataset
- **CIC-DDoS2019** — DDoS attack traffic

### Log Analysis
- **Loghub** — HDFS, Windows, Linux log datasets
- **CERT Insider Threat** — Insider threat logs

### Threat Prediction
- **VERIS Community Database** — Incident patterns over time
- **CISA KEV** — Known Exploited Vulnerabilities catalog
- **AlienVault OTX** — Real threat intelligence feeds (free API)

---

## Re-training

```bash
# Generate fresh datasets
python3 data/dataset_generator.py

# Train all models
python3 models/train_fast.py
python3 models/train_improved.py

# Run test suite
python3 tests/test_models.py
```

---

## Model Details

### 1. ThreatClassifier
- **Algorithm**: Ensemble (LinearSVC + ExtraTrees + LogisticRegression)
- **Features**: TF-IDF ngrams (1-3), 20,000 features
- **Classes**: 13 MITRE ATT&CK tactic categories
- **Training data**: 5,993 labeled threat descriptions

### 2. FrameworkMapper
- **Algorithm**: Ensemble (LinearSVC + ExtraTrees) per framework
- **Outputs**: ATT&CK technique + D3FEND + NIST 800-53 + OWASP ASVS
- **Training data**: 5,200 samples with deterministic framework labels

### 3. SeverityScorer
- **Algorithm**: Ensemble (LinearSVC + ExtraTrees + LogisticRegression)
- **Classes**: Critical / High / Medium / Low
- **Training data**: 6,000 samples with severity labels

### 4. PcapAnalyzer
- **Algorithm**: Ensemble (RandomForest + ExtraTrees) on numerical features
- **Features**: 10 network traffic features extracted from PCAP
- **Classes**: Normal, DDoS, Port Scan, Brute Force, C2 Beacon,
  Data Exfiltration, Lateral Movement, DNS Tunneling

### 5. LogAnomalyDetector
- **Algorithm**: Ensemble (LinearSVC + ExtraTrees + LogisticRegression)
- **Features**: TF-IDF on log text
- **Classes**: Malicious / Benign (binary)

### 6. ThreatPredictor
- **Algorithm**: Ensemble (RandomForest + ExtraTrees) on historical features
- **Sub-models**: next_likely_threat (8 classes) + risk_trend (3 classes)
- **Features**: Historical threat counts + environment metrics
