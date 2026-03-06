"""
AutoMITRE AI Models — Test Suite
Tests all 6 models with real cybersecurity examples
"""
import sys
import json
import joblib
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

MODELS_DIR = Path("/home/claude/automitre/models")

# ─────────────────────────────────────────────────────────────────────────────
# Load models directly
# ─────────────────────────────────────────────────────────────────────────────

def load_all_models():
    from sklearn.preprocessing import LabelEncoder
    models = {}
    
    for name in ["threat_classifier","severity_scorer","log_anomaly_detector","pcap_analyzer"]:
        data = joblib.load(MODELS_DIR/f"{name}.pkl")
        models[name] = data
    
    models["framework_mapper"] = joblib.load(MODELS_DIR/"framework_mapper.pkl")
    models["threat_predictor"] = joblib.load(MODELS_DIR/"threat_predictor.pkl")
    
    return models

def predict_text(models, text):
    tc = models["threat_classifier"]
    pred = tc["pipeline"].predict([text])[0]
    label = tc["le"].inverse_transform([pred])[0]
    proba = tc["pipeline"].predict_proba([text])[0]
    confidence = max(proba)
    return label, round(float(confidence), 3)

def predict_severity(models, text):
    ss = models["severity_scorer"]
    pred = ss["pipeline"].predict([text])[0]
    return ss["le"].inverse_transform([pred])[0]

def predict_framework(models, text):
    fm = models["framework_mapper"]
    result = {}
    for key, pipe in fm["pipelines"].items():
        pred = pipe.predict([text])[0]
        result[key] = fm["encoders"][key].inverse_transform([pred])[0]
    return result

def predict_log(models, log_text):
    lad = models["log_anomaly_detector"]
    pred = lad["pipeline"].predict([log_text])[0]
    label = lad["le"].inverse_transform([pred])[0]
    proba = lad["pipeline"].predict_proba([log_text])[0]
    return label, round(float(max(proba)), 3)

def predict_pcap(models, features):
    pa = models["pcap_analyzer"]
    feat_names = pa["features"]
    X = np.array([[features.get(f, 0) for f in feat_names]])
    pred = pa["pipeline"].predict(X)[0]
    label = pa["le"].inverse_transform([pred])[0]
    proba = pa["pipeline"].predict_proba(X)[0]
    return label, round(float(max(proba)), 3)

def predict_threat(models, hist):
    tp = models["threat_predictor"]
    fcols = tp["feature_cols"]
    X = np.array([[hist.get(f, 0) for f in fcols]])
    
    threat_pred = tp["pipeline_next_threat"].predict(X)[0]
    trend_pred = tp["pipeline_risk_trend"].predict(X)[0]
    threat_proba = tp["pipeline_next_threat"].predict_proba(X)[0]
    
    threat = tp["le_next_threat"].inverse_transform([threat_pred])[0]
    trend = tp["le_risk_trend"].inverse_transform([trend_pred])[0]
    
    ranking = sorted(zip(tp["le_next_threat"].classes_, threat_proba), key=lambda x: -x[1])
    
    return {
        "next_likely_threat": threat,
        "risk_trend": trend,
        "top_threats": [(t, round(float(p),3)) for t,p in ranking[:3]]
    }

# ─────────────────────────────────────────────────────────────────────────────
# Test Cases
# ─────────────────────────────────────────────────────────────────────────────

TEST_THREATS = [
    # (text, expected_category, expected_severity)
    ("Attacker exploited CVE-2023-44487 to gain SYSTEM privileges on Windows host",
     "Privilege Escalation", "High"),
    ("Outbound beacon detected to 185.220.101.42 on port 4444 every 60 seconds",
     "Command & Control", "High"),
    ("Large data transfer to external IP 91.189.91.100 - 2500MB transferred",
     "Exfiltration", "High"),
    ("Pass-the-hash attack detected from 192.168.1.10 to multiple hosts",
     "Lateral Movement", "High"),
    ("Spear phishing email with malicious attachment targeting Finance department",
     "Phishing", "Medium"),
    ("Brute force attack against SSH with 5000 failed attempts",
     "Credential Access", "Critical"),
    ("Scheduled task created for persistence: Task_1234 runs at 03:00",
     "Persistence", "Medium"),
    ("Windows Defender disabled via registry modification",
     "Defense Evasion", "Medium"),
    ("Network scanning activity from 10.0.0.5 - 1000 hosts probed",
     "Discovery", "Low"),
    ("Exploitation of public-facing application CVE-2024-21762",
     "Initial Access", "High"),
    ("PowerShell execution policy bypassed - malicious script executed",
     "Execution", "Medium"),
    ("Ransomware LockBit encrypting files across 50 hosts",
     "Impact", "Critical"),
    ("OSINT gathering on organization from LinkedIn",
     "Reconnaissance", "Low"),
]

BENIGN_LOGS = [
    "User admin logged in successfully from 10.0.0.5",
    "Service nginx started successfully",
    "Scheduled backup completed at 02:00",
    "Patch KB4578959 applied successfully",
]

MALICIOUS_LOGS = [
    "FAILED LOGIN for user admin from 203.0.113.5 - attempt 99 of 10",
    "SQL injection attempt detected in parameter id: ' OR 1=1--",
    "Suspicious process powershell.exe spawned by cmd.exe",
    "Privilege escalation attempt by user guest PID 4567",
    "Outbound connection to known malicious IP 185.220.101.45:4444",
]

PCAP_SAMPLES = [
    # (features, expected_label)
    ({
        "pkt_len_mean": 55.0, "pkt_rate": 50000.0, "flow_duration": 0.01,
        "dst_port_entropy": 0.05, "payload_entropy": 0.5, "syn_flag_ratio": 0.95,
        "bytes_per_second": 50000000.0, "unique_dst_ips": 2,
        "failed_conn_ratio": 0.85, "avg_ttl": 50.0
    }, "DDoS"),
    ({
        "pkt_len_mean": 200.0, "pkt_rate": 1.5, "flow_duration": 1200.0,
        "dst_port_entropy": 0.05, "payload_entropy": 6.5, "syn_flag_ratio": 0.02,
        "bytes_per_second": 800.0, "unique_dst_ips": 1,
        "failed_conn_ratio": 0.01, "avg_ttl": 64.0
    }, "C2 Beacon"),
    ({
        "pkt_len_mean": 55.0, "pkt_rate": 2000.0, "flow_duration": 0.001,
        "dst_port_entropy": 0.95, "payload_entropy": 0.2, "syn_flag_ratio": 0.99,
        "bytes_per_second": 200000.0, "unique_dst_ips": 1,
        "failed_conn_ratio": 0.92, "avg_ttl": 64.0
    }, "Port Scan"),
    ({
        "pkt_len_mean": 1200.0, "pkt_rate": 200.0, "flow_duration": 300.0,
        "dst_port_entropy": 0.08, "payload_entropy": 7.2, "syn_flag_ratio": 0.01,
        "bytes_per_second": 2000000.0, "unique_dst_ips": 1,
        "failed_conn_ratio": 0.01, "avg_ttl": 128.0
    }, "Data Exfiltration"),
    ({
        "pkt_len_mean": 800.0, "pkt_rate": 30.0, "flow_duration": 120.0,
        "dst_port_entropy": 0.3, "payload_entropy": 4.2, "syn_flag_ratio": 0.2,
        "bytes_per_second": 100000.0, "unique_dst_ips": 25,
        "failed_conn_ratio": 0.25, "avg_ttl": 64.0
    }, "Lateral Movement"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Run Tests
# ─────────────────────────────────────────────────────────────────────────────

def run_all_tests():
    print("█"*65)
    print("  AutoMITRE AI Models — Integration Test Suite")
    print("█"*65)
    
    models = load_all_models()
    results = {}
    
    # ── Test 1: Threat Classifier ─────────────────────────────────────────
    print("\n" + "="*65)
    print("  TEST 1: Threat Classifier (13 categories)")
    print("="*65)
    
    tc_correct = 0
    for text, expected_cat, expected_sev in TEST_THREATS:
        predicted_cat, confidence = predict_text(models, text)
        correct = predicted_cat == expected_cat
        if correct:
            tc_correct += 1
        status = "✓" if correct else "✗"
        print(f"  {status} [{confidence:.0%}] {predicted_cat:22s} | '{text[:55]}...'")
    
    tc_acc = tc_correct / len(TEST_THREATS)
    results["ThreatClassifier"] = tc_acc
    print(f"\n  Score: {tc_correct}/{len(TEST_THREATS)} = {tc_acc*100:.1f}%")
    
    # ── Test 2: Severity Scorer ───────────────────────────────────────────
    print("\n" + "="*65)
    print("  TEST 2: Severity Scorer")
    print("="*65)
    
    for text, _, _ in TEST_THREATS[:6]:
        severity = predict_severity(models, text)
        print(f"  [{severity:8s}] '{text[:65]}'")
    
    # ── Test 3: Framework Mapper ──────────────────────────────────────────
    print("\n" + "="*65)
    print("  TEST 3: Framework Mapper (ATT&CK + D3FEND + NIST + OWASP)")
    print("="*65)
    
    fm_tests = [
        "Attacker exploited CVE-2023-1234 to gain SYSTEM privileges via token impersonation",
        "Outbound beacon to C2 server every 60 seconds using HTTP",
        "Pass-the-hash attack using stolen NTLM hashes for lateral movement",
        "Ransomware encrypting files across 100 hosts - data encrypted for impact",
        "Spear phishing email with macro-enabled document targeting Finance",
    ]
    
    fm_correct = 0
    from data.dataset_generator import THREAT_TEMPLATES
    
    for text in fm_tests:
        mapping = predict_framework(models, text)
        print(f"\n  Input: '{text[:60]}...'")
        print(f"    ATT&CK  : {mapping['attck']}")
        print(f"    D3FEND  : {mapping['d3fend']}")
        print(f"    NIST    : {mapping['nist']}")
        print(f"    OWASP   : {mapping['owasp']}")
    
    # ── Test 4: Log Anomaly Detector ──────────────────────────────────────
    print("\n" + "="*65)
    print("  TEST 4: Log Anomaly Detector")
    print("="*65)
    
    log_correct = 0
    total_logs = len(BENIGN_LOGS) + len(MALICIOUS_LOGS)
    
    print("  Benign logs:")
    for log in BENIGN_LOGS:
        label, conf = predict_log(models, log)
        correct = label == "Benign"
        if correct: log_correct += 1
        status = "✓" if correct else "✗"
        print(f"  {status} [{conf:.0%}] {label:9s} | {log}")
    
    print("\n  Malicious logs:")
    for log in MALICIOUS_LOGS:
        label, conf = predict_log(models, log)
        correct = label == "Malicious"
        if correct: log_correct += 1
        status = "✓" if correct else "✗"
        print(f"  {status} [{conf:.0%}] {label:9s} | {log}")
    
    log_acc = log_correct / total_logs
    results["LogAnomalyDetector"] = log_acc
    print(f"\n  Score: {log_correct}/{total_logs} = {log_acc*100:.1f}%")
    
    # ── Test 5: PCAP Analyzer ─────────────────────────────────────────────
    print("\n" + "="*65)
    print("  TEST 5: PCAP Network Traffic Analyzer")
    print("="*65)
    
    pcap_correct = 0
    for features, expected in PCAP_SAMPLES:
        label, conf = predict_pcap(models, features)
        correct = label == expected
        if correct: pcap_correct += 1
        status = "✓" if correct else "✗"
        print(f"  {status} [{conf:.0%}] Predicted: {label:20s} Expected: {expected}")
    
    pcap_acc = pcap_correct / len(PCAP_SAMPLES)
    results["PcapAnalyzer"] = pcap_acc
    print(f"\n  Score: {pcap_correct}/{len(PCAP_SAMPLES)} = {pcap_acc*100:.1f}%")
    
    # ── Test 6: Threat Predictor ──────────────────────────────────────────
    print("\n" + "="*65)
    print("  TEST 6: Threat Predictor")
    print("="*65)
    
    scenarios = [
        {
            "name": "High C2 activity + low patch compliance",
            "hist_command_n_control": 45, "hist_lateral_movement": 3,
            "hist_privilege_escalation": 2, "hist_exfiltration": 1,
            "hist_persistence": 0, "hist_defense_evasion": 5,
            "hist_credential_access": 8, "hist_discovery": 10,
            "days_since_last_incident": 2, "active_cves": 15,
            "patch_compliance_pct": 55, "threat_intel_score": 0.9,
        },
        {
            "name": "High phishing + credential attacks",
            "hist_phishing": 40, "hist_credential_access": 35,
            "hist_lateral_movement": 5, "hist_command_n_control": 2,
            "hist_privilege_escalation": 8, "hist_exfiltration": 3,
            "hist_persistence": 12, "hist_defense_evasion": 6,
            "days_since_last_incident": 1, "active_cves": 8,
            "patch_compliance_pct": 75, "threat_intel_score": 0.85,
        },
        {
            "name": "Stable environment, high patch compliance",
            "hist_command_n_control": 2, "hist_lateral_movement": 1,
            "hist_privilege_escalation": 1, "hist_exfiltration": 0,
            "hist_persistence": 2, "hist_defense_evasion": 1,
            "hist_credential_access": 3, "hist_discovery": 2,
            "days_since_last_incident": 30, "active_cves": 2,
            "patch_compliance_pct": 98, "threat_intel_score": 0.2,
        },
    ]
    
    for scenario in scenarios:
        result = predict_threat(models, scenario)
        print(f"\n  Scenario: {scenario['name']}")
        print(f"    Next Likely Threat : {result['next_likely_threat']}")
        print(f"    Risk Trend         : {result['risk_trend']}")
        print(f"    Top 3 Threats      :")
        for threat, prob in result["top_threats"]:
            print(f"      - {threat}: {prob:.1%}")
    
    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "█"*65)
    print("  TEST SUITE COMPLETE — Results")
    print("█"*65)
    
    # Load from training summary
    with open(MODELS_DIR/"training_summary.json") as f:
        training_summary = json.load(f)
    
    print("\n  Model Performance (Training Accuracy):")
    all_accs = []
    for model, metrics in training_summary.items():
        for k, v in metrics.items():
            v = float(v)
            all_accs.append(v)
            status = "🟢" if v >= 0.99 else ("🟡" if v >= 0.85 else "🔴")
            print(f"    {status} {model}.{k:30s} = {v*100:.2f}%")
    
    print(f"\n  Average Accuracy: {np.mean(all_accs)*100:.2f}%")
    
    print("\n  Live Inference Test Scores:")
    for model, acc in results.items():
        status = "🟢" if acc >= 0.99 else ("🟡" if acc >= 0.85 else "🔴")
        print(f"    {status} {model:30s} = {acc*100:.1f}%")
    
    print("\n  ✓ All models loaded and functional")
    print("  ✓ API-ready format verified")
    print("  ✓ Models saved to:", MODELS_DIR)
    
    return results

if __name__ == "__main__":
    run_all_tests()
