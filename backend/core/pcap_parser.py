"""
PCAP Parser Module
Extracts basic IP connections, domains, and suspicious payload text from raw PCAP binaries using Scapy.
"""
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
import os
import logging

logger = logging.getLogger(__name__)

def parse_pcap_bytes(file_path: str, cap_limit: int = 1500) -> str:
    """Read a pcap file using scapy and generate a heuristic summary for the LLM pipeline."""
    try:
        if not os.path.exists(file_path):
            return "PCAP File empty or corrupted."
            
        packets = rdpcap(file_path, count=cap_limit)
        
        unique_ips = set()
        suspicious_payloads = []
        dns_queries = set()
        
        for pkt in packets:
            # IP Tracking
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                # Skip massive local noise if possible, but keep it simple for now
                if not (src.startswith("127.") or src.startswith("192.168.")):
                    unique_ips.add(src)
                if not (dst.startswith("127.") or dst.startswith("192.168.")):
                    unique_ips.add(dst)
            
            # DNS Tracking
            if DNS in pkt and pkt.haslayer(DNSQR):
                query = pkt[DNSQR].qname.decode('utf-8', errors='ignore').strip('.')
                dns_queries.add(query)
                
            # HTTP / Raw Payload Tracking
            if Raw in pkt and (TCP in pkt or UDP in pkt):
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Very rudimentary heuristic for interesting payloads
                    lower_pay = payload.lower()
                    if "http" in lower_pay or "get " in lower_pay or "post " in lower_pay or "user-agent" in lower_pay:
                        # Grab the first line of the HTTP request to avoid flooding the context
                        first_line = payload.splitlines()[0] if payload else ""
                        if first_line and len(first_line) > 5 and first_line not in suspicious_payloads:
                            suspicious_payloads.append(first_line)
                            
                except Exception:
                    continue

        summary_parts = [
            f"[PCAP TELEMETRY EXTRACTED ({len(packets)} packets analyzed)]"
        ]
        
        if unique_ips:
            summary_parts.append(f"\nDiscovered External IPs:\n- " + "\n- ".join(list(unique_ips)[:15]))
            
        if dns_queries:
            summary_parts.append(f"\nDiscovered DNS Queries:\n- " + "\n- ".join(list(dns_queries)[:15]))
            
        if suspicious_payloads:
            summary_parts.append(f"\nSuspicious Raw Payloads (HTTP/Cleartext):\n- " + "\n- ".join(suspicious_payloads[:10]))

        final_summary = "\n".join(summary_parts)
        if len(final_summary.strip()) < 50:
            final_summary += "\nNo significant external IPs, DNS, or Cleartext Payloads were extracted from this PCAP."
            
        return final_summary

    except Exception as e:
        logger.error(f"Failed parsing PCAP: {str(e)}")
        return f"Failed to parse PCAP file due to structural errors or unrecognized binary format: {str(e)}"
