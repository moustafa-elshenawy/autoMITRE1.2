"""
PCAP Parser Module
Extracts basic IP connections, domains, and suspicious payload text from raw PCAP binaries using Scapy.
"""
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
import os
import logging

logger = logging.getLogger(__name__)

import os
import logging
import json
import pickle
import numpy as np
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw

logger = logging.getLogger(__name__)

# Paths to the pre-trained CICIDS models
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'models')
CICIDS_XGB_PATH = os.path.join(MODEL_DIR, 'cicids_classifier.json')
CICIDS_SCALER = os.path.join(MODEL_DIR, 'cicids_scaler.pkl')
CICIDS_FEATURES = os.path.join(MODEL_DIR, 'cicids_features.json')

class HybridPcapEngine:
    """Uses the Trained CICIDS 2017 XGBoost model for Stage-1 Packet Triage."""
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = []
        self._load_models()

    def _load_models(self):
        try:
            if os.path.exists(CICIDS_XGB_PATH) and os.path.exists(CICIDS_SCALER) and os.path.exists(CICIDS_FEATURES):
                import xgboost as xgb
                self.model = xgb.XGBClassifier()
                self.model.load_model(CICIDS_XGB_PATH)
                with open(CICIDS_SCALER, 'rb') as f:
                    self.scaler = pickle.load(f)
                with open(CICIDS_FEATURES, 'r') as f:
                    self.feature_names = json.load(f)
                logger.info(f"HybridPcapEngine loaded with {len(self.feature_names)} features.")
        except Exception as e:
            logger.error(f"Failed to load ML Hybrid engine: {e}")

    def analyze_flows(self, packets):
        """Groups packets into flows and runs ML anomaly detection."""
        flows = defaultdict(lambda: {
            "fwd_pkts": 0, "bwd_pkts": 0, 
            "fwd_bytes": 0, "bwd_bytes": 0,
            "start_time": None, "end_time": None,
            "dport": 0, "payloads": [], "is_anomaly": False
        })
        
        has_anomalies = False

        for pkt in packets:
            if IP not in pkt: continue
            if TCP not in pkt and UDP not in pkt: continue
            
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt.sport
            dport = pkt.dport
            
            # Simple flow hash (ignoring strict bidirectionality for fast heuristic)
            flow_key = tuple(sorted([f"{src}:{sport}", f"{dst}:{dport}"]) + [pkt.proto])
            
            flow = flows[flow_key]
            
            if flow["start_time"] is None:
                flow["start_time"] = float(pkt.time)
                flow["dport"] = dport
            flow["end_time"] = float(pkt.time)
            
            if src < dst:
                flow["fwd_pkts"] += 1
                flow["fwd_bytes"] += len(pkt)
            else:
                flow["bwd_pkts"] += 1
                flow["bwd_bytes"] += len(pkt)
                
            if Raw in pkt:
                try:
                    pay = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if any(c.isalpha() for c in pay):
                        flow["payloads"].append(pay.strip()[:200])
                except:
                    pass

        # If model is loaded, predict anomalies
        if self.model and self.scaler and self.feature_names:
            X_rows = []
            keys = list(flows.keys())
            
            for k in keys:
                f = flows[k]
                duration = max((f["end_time"] - f["start_time"]) * 1e6, 1.0) # microsecs
                
                # Approximate CICIDS features
                feats = np.zeros(len(self.feature_names))
                if "Flow Duration" in self.feature_names:
                    feats[self.feature_names.index("Flow Duration")] = duration
                if "Destination Port" in self.feature_names:
                    feats[self.feature_names.index("Destination Port")] = f["dport"]
                if "Total Fwd Packets" in self.feature_names:
                    feats[self.feature_names.index("Total Fwd Packets")] = f["fwd_pkts"]
                if "Total Backward Packets" in self.feature_names:
                    feats[self.feature_names.index("Total Backward Packets")] = f["bwd_pkts"]
                if "Total Length of Fwd Packets" in self.feature_names:
                    feats[self.feature_names.index("Total Length of Fwd Packets")] = f["fwd_bytes"]
                if "Total Length of Bwd Packets" in self.feature_names:
                    feats[self.feature_names.index("Total Length of Bwd Packets")] = f["bwd_bytes"]
                    
                X_rows.append(feats)
                
            if X_rows:
                try:
                    X_scaled = self.scaler.transform(np.array(X_rows))
                    preds = self.model.predict(X_scaled)
                    for i, pred in enumerate(preds):
                        if pred == 1:
                            flows[keys[i]]["is_anomaly"] = True
                            has_anomalies = True
                except Exception as e:
                    logger.error(f"ML prediction failed: {e}")

        # Fallback Heuristics if ML is off or finds nothing
        if not has_anomalies:
            for k, f in flows.items():
                pay_text = " ".join(f["payloads"]).lower()
                if "post " in pay_text or "union select" in pay_text or "cmd.exe" in pay_text or len(pay_text) > 1000:
                    f["is_anomaly"] = True

        ml_summary = []
        # Priority flows (Anomalies)
        for k, f in flows.items():
            if f["is_anomaly"] and f["payloads"]:
                src_ip = k[0].split(":")[0]
                dst_ip = k[1].split(":")[0]
                context = f"[CRITICAL ANOMALY] {src_ip} -> {dst_ip} (Port {f['dport']})\nPayloads: "
                context += " | ".join(p.replace('\n', ' ') for p in f["payloads"][:5])
                ml_summary.append(context)

        # Baseline snippets (If no anomalies, or just as context)
        if len(ml_summary) < 5:
            # Sort flows by payload size or activity to find interesting ones
            sorted_flows = sorted(flows.items(), key=lambda x: len("".join(x[1]["payloads"])), reverse=True)
            for k, f in sorted_flows[:10]:
                if any(f["payloads"]):
                    # Don't duplicate if already in ml_summary
                    src_ip = k[0].split(":")[0]
                    if any(src_ip in s for s in ml_summary): continue
                    
                    dst_ip = k[1].split(":")[0]
                    context = f"[SUSPICIOUS FLOW] {src_ip} -> {dst_ip} (Port {f['dport']})\nPayloads: "
                    context += " | ".join(p.replace('\n', ' ') for p in f["payloads"][:3])
                    ml_summary.append(context)

        return ml_summary[:20]


# Singleton ML Engine for PCAP
hybrid_pcap = HybridPcapEngine()

def parse_pcap_bytes(file_path: str, cap_limit: int = 5000) -> str:
    """Stage 1: Read PCAP and use NIDS ML model to extract anomalous flows."""
    try:
        if not os.path.exists(file_path):
            return "PCAP File empty or corrupted."
            
        packets = rdpcap(file_path, count=cap_limit)
        
        # 1. Run ML Pipeline
        anomalous_flows = hybrid_pcap.analyze_flows(packets)
        
        # 2. Run standard baseline extraction
        dns_queries = set()
        unique_ips = set()
        
        for pkt in packets:
            if IP in pkt:
                unique_ips.add(pkt[IP].src)
                unique_ips.add(pkt[IP].dst)
            if DNS in pkt and pkt.haslayer(DNSQR):
                dns_queries.add(pkt[DNSQR].qname.decode('utf-8', errors='ignore').strip('.'))

        summary_parts = [
            f"[HYBRID NIDS PIPELINE: {len(packets)} packets analyzed]"
        ]
        
        if anomalous_flows:
            summary_parts.append("\n=== CRITICAL ML ANOMALIES EXTRACTED ===")
            summary_parts.extend(anomalous_flows[:15]) # Send top 15 flows to LLM
            
        if unique_ips:
            summary_parts.append("\n=== BACKGROUND TELEMETRY ===")
            summarized_ips = list(unique_ips)[:10]
            summary_parts.append(f"Discovered IPs: {', '.join(summarized_ips)}")
            
        if dns_queries:
            summarized_dns = list(dns_queries)[:10]
            summary_parts.append(f"DNS Lookups: {', '.join(summarized_dns)}")

        return "\n".join(summary_parts)

    except Exception as e:
        logger.error(f"Failed parsing PCAP: {str(e)}")
        return f"Failed to parse PCAP file: {str(e)}"
