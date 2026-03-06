"""
AutoMITRE AI REST API
=====================
Drop-in Python module for integrating all 6 AI models into
the AutoMITRE FastAPI/Flask backend.

Usage:
    from api.automitre_api import AutoMITREAnalyzer
    analyzer = AutoMITREAnalyzer()
    result = analyzer.analyze({"type": "text", "content": "..."})
"""

import sys
import json
import joblib
import numpy as np
from pathlib import Path
from datetime import datetime

MODELS_DIR = Path(__file__).parent.parent.parent / "models" / "custom"


class AutoMITREAnalyzer:
    """
    Unified analyzer — loads all 6 trained models and exposes
    a clean .analyze() interface ready for REST API integration.
    """

    def __init__(self, models_dir: str = None):
        if models_dir:
            self.models_dir = Path(models_dir)
        else:
            self.models_dir = MODELS_DIR

        self._models = {}
        self._load_all()

    def _load_all(self):
        """Load all 6 trained models from disk."""
        model_files = {
            "threat_classifier": "threat_classifier.pkl",
            "severity_scorer": "severity_scorer.pkl",
            "log_detector": "log_anomaly_detector.pkl",
            "pcap_analyzer": "pcap_analyzer.pkl",
            "framework_mapper": "framework_mapper.pkl",
            "threat_predictor": "threat_predictor.pkl",
        }
        for key, fname in model_files.items():
            path = self.models_dir / fname
            if path.exists():
                self._models[key] = joblib.load(path)
            else:
                print(f"  WARNING: {fname} not found at {path}")

        print(f"✓ AutoMITRE: {len(self._models)}/6 models loaded")

    # ─────────────────────────────────────────────────────────────────────
    # Core inference methods
    # ─────────────────────────────────────────────────────────────────────

    def classify_threat(self, text: str) -> dict:
        """Classify threat type from natural language text."""
        m = self._models["threat_classifier"]
        pred = m["pipeline"].predict([text])[0]
        proba = m["pipeline"].predict_proba([text])[0]
        label = m["le"].inverse_transform([pred])[0]
        confidence = float(max(proba))
        top_cats = sorted(
            zip(m["le"].classes_, proba), key=lambda x: -x[1]
        )[:5]
        return {
            "threat_category": label,
            "confidence": round(confidence, 3),
            "top_categories": [
                {"category": c, "probability": round(float(p), 3)}
                for c, p in top_cats
            ],
        }

    def score_severity(self, text: str) -> dict:
        """Predict severity level from text."""
        m = self._models["severity_scorer"]
        pred = m["pipeline"].predict([text])[0]
        proba = m["pipeline"].predict_proba([text])[0]
        label = m["le"].inverse_transform([pred])[0]
        return {
            "severity": label,
            "severity_probabilities": {
                cls: round(float(p), 3)
                for cls, p in zip(m["le"].classes_, proba)
            },
        }

    def map_frameworks(self, text: str) -> dict:
        """Map threat text to all 4 cybersecurity frameworks."""
        m = self._models["framework_mapper"]
        result = {}
        proba_map = {}
        for key, pipe in m["pipelines"].items():
            pred = pipe.predict([text])[0]
            label = m["encoders"][key].inverse_transform([pred])[0]
            result[key] = label
            try:
                proba = pipe.predict_proba([text])[0]
                proba_map[key] = {
                    cls: round(float(p), 3)
                    for cls, p in zip(m["encoders"][key].classes_, proba)
                }
            except Exception:
                pass

        return {
            "mitre_attck": {
                "technique_id": result.get("attck"),
                "confidence_scores": proba_map.get("attck", {}),
            },
            "mitre_d3fend": result.get("d3fend"),
            "nist_800_53": result.get("nist"),
            "owasp_asvs": result.get("owasp"),
        }

    def detect_log_anomaly(self, log_text: str) -> dict:
        """Detect if a log entry is malicious or benign."""
        m = self._models["log_detector"]
        pred = m["pipeline"].predict([log_text])[0]
        proba = m["pipeline"].predict_proba([log_text])[0]
        label = m["le"].inverse_transform([pred])[0]
        confidence = float(max(proba))
        is_malicious = label == "Malicious"

        result = {
            "is_malicious": is_malicious,
            "label": label,
            "confidence": round(confidence, 3),
        }
        if is_malicious:
            result["threat_analysis"] = self.analyze_text(log_text)
        return result

    def analyze_pcap_features(self, features: dict) -> dict:
        """
        Classify network traffic from extracted PCAP features.
        
        Required features:
            pkt_len_mean, pkt_rate, flow_duration, dst_port_entropy,
            payload_entropy, syn_flag_ratio, bytes_per_second,
            unique_dst_ips, failed_conn_ratio, avg_ttl
        """
        m = self._models["pcap_analyzer"]
        feat_names = m["features"]
        X = np.array([[features.get(f, 0.0) for f in feat_names]])
        
        pred = m["pipeline"].predict(X)[0]
        proba = m["pipeline"].predict_proba(X)[0]
        label = m["le"].inverse_transform([pred])[0]
        is_malicious = label != "Normal"

        result = {
            "traffic_type": label,
            "is_malicious": is_malicious,
            "confidence": round(float(max(proba)), 3),
            "all_probabilities": dict(
                sorted(
                    zip(m["le"].classes_, [round(float(p), 3) for p in proba]),
                    key=lambda x: -x[1]
                )
            ),
        }
        if is_malicious:
            result["threat_analysis"] = self.analyze_text(
                f"{label} network attack detected"
            )
        return result

    def predict_threats(self, historical_features: dict) -> dict:
        """
        Predict next likely threat and risk trend from historical data.
        """
        m = self._models["threat_predictor"]
        fcols = m["feature_cols"]
        X = np.array([[historical_features.get(f, 0) for f in fcols]])

        threat_pred = m["pipeline_threat"].predict(X)[0]
        trend_pred = m["pipeline_trend"].predict(X)[0]
        threat_proba = m["pipeline_threat"].predict_proba(X)[0]

        next_threat = m["le_threat"].inverse_transform([threat_pred])[0]
        risk_trend = m["le_trend"].inverse_transform([trend_pred])[0]

        ranking = sorted(
            zip(m["le_threat"].classes_, threat_proba),
            key=lambda x: -x[1]
        )

        return {
            "next_likely_threat": next_threat,
            "risk_trend": risk_trend,
            "top_3_threats": [
                {"threat": t, "probability": round(float(p), 3)}
                for t, p in ranking[:3]
            ],
            "confidence": round(float(max(threat_proba)), 3),
        }

    # ─────────────────────────────────────────────────────────────────────
    # Composite analysis pipelines
    # ─────────────────────────────────────────────────────────────────────

    def analyze_text(self, text: str) -> dict:
        """Full text analysis pipeline (classify + severity + framework map)."""
        threat = self.classify_threat(text)
        severity = self.score_severity(text)
        frameworks = self.map_frameworks(text)

        return {
            **threat,
            **severity,
            "framework_mappings": frameworks,
        }

    def analyze(self, input_data: dict) -> dict:
        """
        Master entrypoint — routes to the correct analysis pipeline.
        
        input_data format:
            {"type": "text", "content": "threat description..."}
            {"type": "log", "content": "log line..."}
            {"type": "pcap", "features": {...}}
            {"type": "prediction", "features": {...}}
            {"type": "hash", "content": "md5/sha256 hash"}
            {"type": "json_report", "content": {...}}  # from TMT/IriusRisk
        """
        input_type = input_data.get("type", "text")
        timestamp = datetime.utcnow().isoformat() + "Z"

        try:
            if input_type == "text":
                result = self.analyze_text(input_data["content"])

            elif input_type == "log":
                result = self.detect_log_anomaly(input_data["content"])

            elif input_type == "pcap":
                result = self.analyze_pcap_features(input_data["features"])

            elif input_type == "prediction":
                result = self.predict_threats(input_data["features"])

            elif input_type == "hash":
                # Stub: in production, call VirusTotal API then analyze result
                result = {
                    "hash": input_data["content"],
                    "note": "In production: submit to VirusTotal API and analyze returned threat name",
                    "mock_analysis": self.analyze_text(
                        f"Malware sample with hash {input_data['content'][:16]}... detected"
                    )
                }

            elif input_type == "json_report":
                # Parse TMT/IriusRisk JSON and analyze each threat
                report = input_data.get("content", {})
                threats = report.get("threats", [report]) if isinstance(report, dict) else report
                results = []
                for item in (threats if isinstance(threats, list) else [threats]):
                    desc = item.get("description", item.get("name", str(item)))
                    results.append(self.analyze_text(str(desc)))
                result = {"report_analysis": results, "threat_count": len(results)}

            else:
                result = {"error": f"Unknown input type: {input_type}"}

        except Exception as e:
            result = {"error": str(e), "input_type": input_type}

        return {
            "input_type": input_type,
            "timestamp": timestamp,
            "analysis": result,
        }

    def export_stix(self, analysis_result: dict) -> dict:
        """
        Export analysis result as STIX 2.1-compatible structure.
        In production, use the stix2 library for full STIX bundle generation.
        """
        analysis = analysis_result.get("analysis", {})
        threat_cat = analysis.get("threat_category", "Unknown")
        severity = analysis.get("severity", "Medium")
        frameworks = analysis.get("framework_mappings", {})

        stix_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--automitre-{hash(str(analysis_result)) % 10**10:010d}",
            "created": analysis_result.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"AutoMITRE: {threat_cat}",
            "description": f"AI-detected threat: {threat_cat} | Severity: {severity}",
            "indicator_types": ["malicious-activity"],
            "confidence": int(analysis.get("confidence", 0.8) * 100),
            "labels": [threat_cat.lower().replace(" ", "-"), severity.lower()],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": threat_cat.lower().replace(" ", "-"),
                }
            ],
            "extensions": {
                "mitre-attck": frameworks.get("mitre_attck", {}).get("technique_id"),
                "mitre-d3fend": frameworks.get("mitre_d3fend"),
                "nist-800-53": frameworks.get("nist_800_53"),
                "owasp-asvs": frameworks.get("owasp_asvs"),
            },
        }
        return stix_indicator

    def export_siem_json(self, analysis_result: dict) -> dict:
        """
        Export analysis in SIEM-compatible JSON format
        (Splunk/QRadar/Elastic/Wazuh compatible).
        """
        analysis = analysis_result.get("analysis", {})
        frameworks = analysis.get("framework_mappings", {})

        return {
            "@timestamp": analysis_result.get("timestamp"),
            "event": {
                "kind": "alert",
                "category": "threat",
                "type": analysis_result.get("input_type"),
                "severity": analysis.get("severity", "Medium"),
                "outcome": "detected",
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": frameworks.get("mitre_attck", {}).get("technique_id"),
                    "name": analysis.get("threat_category"),
                },
                "tactic": {
                    "name": analysis.get("threat_category"),
                },
            },
            "rule": {
                "name": f"AutoMITRE:{analysis.get('threat_category','')}",
                "category": "threat-intel",
                "confidence": analysis.get("confidence", 0.0),
            },
            "labels": {
                "d3fend": frameworks.get("mitre_d3fend"),
                "nist": frameworks.get("nist_800_53"),
                "owasp": frameworks.get("owasp_asvs"),
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI route definitions (paste into your main.py)
# ─────────────────────────────────────────────────────────────────────────────

FASTAPI_ROUTES = '''
# ── AutoMITRE FastAPI Integration ──────────────────────────────────────────

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from api.automitre_api import AutoMITREAnalyzer

app = FastAPI(title="AutoMITRE AI API", version="1.0.0")
analyzer = AutoMITREAnalyzer()

class AnalysisRequest(BaseModel):
    type: str  # text | log | pcap | prediction | hash | json_report
    content: Optional[str] = None
    features: Optional[Dict[str, Any]] = None

@app.post("/api/analyze")
async def analyze(request: AnalysisRequest):
    """Master analysis endpoint — routes to correct model pipeline."""
    result = analyzer.analyze(request.dict())
    return result

@app.post("/api/analyze/text")
async def analyze_text(text: str):
    return analyzer.analyze_text(text)

@app.post("/api/analyze/log")
async def analyze_log(log: str):
    return analyzer.detect_log_anomaly(log)

@app.post("/api/analyze/pcap")
async def analyze_pcap(features: Dict[str, float]):
    return analyzer.analyze_pcap_features(features)

@app.post("/api/predict")
async def predict_threats(features: Dict[str, float]):
    return analyzer.predict_threats(features)

@app.post("/api/export/stix")
async def export_stix(request: AnalysisRequest):
    result = analyzer.analyze(request.dict())
    return analyzer.export_stix(result)

@app.post("/api/export/siem")
async def export_siem(request: AnalysisRequest):
    result = analyzer.analyze(request.dict())
    return analyzer.export_siem_json(result)

@app.get("/api/health")
async def health():
    return {"status": "ok", "models_loaded": len(analyzer._models)}
'''

if __name__ == "__main__":
    print("AutoMITRE API — Quick Test")
    print("="*50)
    
    analyzer = AutoMITREAnalyzer()
    
    # Test full pipeline
    test_cases = [
        {"type": "text", "content": "Ransomware LockBit encrypting files across 50 corporate hosts"},
        {"type": "log", "content": "SQL injection attempt detected in parameter id: ' OR 1=1--"},
        {"type": "pcap", "features": {
            "pkt_len_mean": 55, "pkt_rate": 50000, "flow_duration": 0.01,
            "dst_port_entropy": 0.05, "payload_entropy": 0.5,
            "syn_flag_ratio": 0.95, "bytes_per_second": 50000000,
            "unique_dst_ips": 2, "failed_conn_ratio": 0.85, "avg_ttl": 50
        }},
        {"type": "prediction", "features": {
            "hist_command_n_control": 40, "hist_exfiltration": 30,
            "hist_privilege_escalation": 5, "hist_lateral_movement": 8,
            "hist_persistence": 3, "hist_defense_evasion": 6,
            "hist_credential_access": 12, "hist_discovery": 9,
            "days_since_last_incident": 3, "active_cves": 12,
            "patch_compliance_pct": 62, "threat_intel_score": 0.88,
        }},
    ]
    
    for tc in test_cases:
        result = analyzer.analyze(tc)
        print(f"\n  [{tc['type'].upper()}]")
        print(json.dumps(result, indent=4))
        
        # Test STIX export for text analysis
        if tc["type"] == "text":
            stix = analyzer.export_stix(result)
            print("\n  STIX 2.1 Export:")
            print(json.dumps(stix, indent=4))
            siem = analyzer.export_siem_json(result)
            print("\n  SIEM JSON Export:")
            print(json.dumps(siem, indent=4))
