from scapy.all import IP, TCP, wrpcap, Ether
import time
import random

packets = []

# Normal Flow
dst_ip = "192.168.1.100"
src_ip = "10.0.0.5"
sport = 12345
dport = 80

# Simulate a normal flow (few packets, small payload)
for i in range(5):
    pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S" if i==0 else "A")
    if i == 2:
        pkt = pkt / "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packets.append(pkt)

# Malicious Flow (SQLi payload, triggers fallback or ML anomaly)
src_ip_mal = "45.33.22.11"
sport_mal = 54321

# Massive payload flow to trigger anomalies or SQLi to trigger fallback
for i in range(10):
    pkt = Ether()/IP(src=src_ip_mal, dst=dst_ip)/TCP(sport=sport_mal, dport=dport, flags="S" if i==0 else "A")
    if i == 1:
        pkt = pkt / "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin' UNION SELECT * FROM users--&password=foo"
    packets.append(pkt)

wrpcap("test_sqli.pcap", packets)
print("Created test_sqli.pcap")
