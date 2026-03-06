"""
AutoMITRE Dataset Generator
Generates high-quality synthetic cybersecurity datasets for training all AI models.
In production, replace/augment with real datasets listed in DATASET_GUIDE below.
"""

import random
import json
import pandas as pd
from pathlib import Path
from sklearn.utils import shuffle
import numpy as np

random.seed(42)
np.random.seed(42)

# =============================================================================
# REAL DATASET RECOMMENDATIONS (for production 99%+ accuracy)
# =============================================================================
DATASET_GUIDE = {
    "threat_classification": [
        "CICIDS2017/2018 - Canadian Institute for Cybersecurity Intrusion Detection",
        "NSL-KDD - Network intrusion detection benchmark",
        "UNSW-NB15 - Network traffic with 9 attack categories",
        "MITRE ATT&CK STIX data - https://github.com/mitre/cti",
        "CTI Corpus - Threat intelligence NLP dataset",
        "SecureNLP - Cybersecurity NER dataset",
        "MalwareBazaar - Malware samples and metadata"
    ],
    "framework_mapping": [
        "MITRE ATT&CK Enterprise JSON (https://attack.mitre.org/resources/attack-data-and-tools/)",
        "MITRE D3FEND ontology (https://d3fend.mitre.org/)",
        "NIST NVD CVE database (https://nvd.nist.gov/)",
        "OWASP ASVS controls (https://owasp.org/www-project-application-security-verification-standard/)",
        "NVD-CWE mappings for CVE to technique correlation"
    ],
    "threat_prediction": [
        "VERIS Community Database - Incident patterns over time",
        "CISA KEV (Known Exploited Vulnerabilities) catalog",
        "Shodan historical scan data",
        "AlienVault OTX threat intelligence feeds",
        "VirusTotal public reports (API)"
    ],
    "pcap_analysis": [
        "PCAP-ISCX dataset",
        "CTU-13 botnet dataset",
        "CIC-DDoS2019",
        "CAIDA anonymized traces"
    ],
    "log_analysis": [
        "HDFS log dataset (Loghub)",
        "Windows event log dataset",
        "Linux syslog dataset (Loghub)",
        "CERT Insider Threat dataset"
    ]
}

# =============================================================================
# MITRE ATT&CK Techniques (subset - real ones)
# =============================================================================
ATTCK_TECHNIQUES = {
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1068": "Exploitation for Privilege Escalation",
    "T1055": "Process Injection",
    "T1053": "Scheduled Task/Job",
    "T1021": "Remote Services",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1057": "Process Discovery",
    "T1012": "Query Registry",
    "T1105": "Ingress Tool Transfer",
    "T1071": "Application Layer Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1486": "Data Encrypted for Impact",
    "T1190": "Exploit Public-Facing Application",
    "T1566": "Phishing",
    "T1133": "External Remote Services",
    "T1110": "Brute Force",
    "T1003": "OS Credential Dumping",
    "T1027": "Obfuscated Files or Information",
    "T1562": "Impair Defenses",
    "T1070": "Indicator Removal",
    "T1046": "Network Service Discovery",
    "T1018": "Remote System Discovery",
    "T1135": "Network Share Discovery",
}

THREAT_CATEGORIES = [
    "Privilege Escalation", "Lateral Movement", "Exfiltration",
    "Command & Control", "Persistence", "Defense Evasion",
    "Credential Access", "Discovery", "Execution", "Initial Access",
    "Impact", "Reconnaissance", "Resource Development"
]

SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low"]

MITRE_TACTICS = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact"
]

D3FEND_TECHNIQUES = [
    "D3-PA: Process Analysis", "D3-NTF: Network Traffic Filtering",
    "D3-MH: Message Hardening", "D3-UAP: User Account Permissions",
    "D3-EHB: Executable Hardening", "D3-NI: Network Isolation",
    "D3-SCP: System Call Filtering", "D3-FCA: File Content Analysis",
    "D3-DNR: DNS Denylisting", "D3-PH: Platform Hardening",
    "D3-UAP: User Account Policies", "D3-EDL: Endpoint Detection Logging"
]

NIST_CONTROLS = [
    "AC-2", "AC-3", "AC-6", "AC-17", "AU-2", "AU-6", "CA-7",
    "CM-2", "CM-6", "IA-2", "IA-5", "IR-4", "IR-5", "RA-5",
    "SC-7", "SC-8", "SI-3", "SI-4", "SI-7", "SA-11"
]

OWASP_REQS = [
    "V1.1", "V2.1", "V2.2", "V3.1", "V4.1", "V5.1", "V6.1",
    "V7.1", "V8.1", "V9.1", "V10.1", "V11.1", "V12.1", "V14.1"
]

# =============================================================================
# Threat Text Templates
# =============================================================================
THREAT_TEMPLATES = {
    "Privilege Escalation": [
        "Attacker exploited CVE-{cve} to gain SYSTEM privileges on Windows host",
        "Unauthorized privilege escalation detected via {method} on {host}",
        "Process {proc} attempted to escalate privileges using token impersonation",
        "Sudo misconfiguration exploited to gain root access on Linux server",
        "Local privilege escalation via unquoted service path vulnerability",
        "Kernel exploit used to bypass privilege restrictions on endpoint",
    ],
    "Command & Control": [
        "Outbound beacon detected to {ip} on port {port} every {interval} seconds",
        "DNS tunneling activity observed - {domain} queried {n} times in {time}",
        "HTTP POST requests to suspicious C2 infrastructure at {domain}",
        "Encrypted C2 communication over HTTPS to {ip}:{port}",
        "Cobalt Strike beacon activity identified from {host}",
        "ICMP-based command and control tunnel detected",
    ],
    "Exfiltration": [
        "Large data transfer to external IP {ip} - {size}MB transferred",
        "Sensitive files accessed and compressed before transfer via FTP",
        "Cloud storage exfiltration detected to unauthorized {service} bucket",
        "Email-based exfiltration - {n} emails with attachments sent externally",
        "Data exfiltration over DNS - TXT records containing encoded data",
        "Unusual outbound traffic spike indicating data theft attempt",
    ],
    "Lateral Movement": [
        "Pass-the-hash attack detected from {src} to {dst}",
        "RDP lateral movement from {src} to multiple hosts in subnet",
        "SMB share enumeration and access from compromised host",
        "WMI remote execution used for lateral movement",
        "SSH key abuse for unauthorized lateral movement across servers",
        "Kerberoasting attack targeting service accounts",
    ],
    "Phishing": [
        "Spear phishing email with malicious attachment targeting {dept} department",
        "Credential harvesting page mimicking {service} login portal",
        "Business email compromise (BEC) attempt targeting finance team",
        "Macro-enabled Office document delivered via phishing campaign",
        "Whaling attack targeting executive accounts with fake invoice",
        "SMS phishing (smishing) campaign targeting mobile users",
    ],
    "Credential Access": [
        "Brute force attack against {service} with {n} failed attempts",
        "LSASS memory dump detected - credential theft in progress",
        "Keylogger installed capturing user credentials on {host}",
        "Password spray attack targeting {n} accounts in Active Directory",
        "Mimikatz execution detected - pass-the-hash credential theft",
        "SAM database accessed for offline password cracking",
    ],
    "Persistence": [
        "Scheduled task created for persistence: {taskname} runs at {time}",
        "Registry run key modified for persistent malware execution",
        "New service {svcname} installed for persistent backdoor access",
        "Startup folder modified with malicious shortcut for persistence",
        "Boot record modification detected for rootkit persistence",
        "DLL hijacking used to maintain persistent access",
    ],
    "Defense Evasion": [
        "Windows Defender disabled via registry modification",
        "Log files cleared on {n} hosts to remove forensic evidence",
        "Obfuscated PowerShell commands detected - base64 encoded payload",
        "Process hollowing detected - legitimate process {proc} injected",
        "Timestomping detected - file modification times altered",
        "AMSI bypass technique used to evade script scanning",
    ],
    "Discovery": [
        "Network scanning activity from {src} - {n} hosts probed",
        "Active Directory enumeration using BloodHound tool",
        "Port scanning detected targeting internal subnets",
        "SNMP enumeration used to map network topology",
        "WMI queries used for system information gathering",
        "DNS zone transfer attempted on {domain}",
    ],
    "Initial Access": [
        "Exploitation of public-facing application CVE-{cve}",
        "Valid credentials used from dark web to access VPN",
        "Supply chain compromise via malicious {software} update",
        "Drive-by download via malicious advertising network",
        "Hardware-based attack via compromised USB device",
        "Watering hole attack targeting industry-specific website",
    ],
    "Execution": [
        "PowerShell execution policy bypassed - malicious script executed",
        "WMI subscription used to execute payload on system start",
        "Malicious macro executed in {document} Office file",
        "Regsvr32 used to execute malicious DLL - squiblydoo technique",
        "Mshta.exe executing remote HTA file for code execution",
        "Certutil used to download and decode malicious payload",
    ],
    "Impact": [
        "Ransomware {name} encrypting files across {n} hosts",
        "Destructive malware wiping MBR on critical systems",
        "DDoS attack targeting {service} with {gbps} Gbps traffic",
        "Database deletion attack - {n} critical tables dropped",
        "Industrial control system sabotage detected",
        "Cryptojacking malware consuming {pct}% CPU resources",
    ],
    "Reconnaissance": [
        "OSINT gathering on organization from {source}",
        "Social media reconnaissance targeting {n} employees",
        "Job posting analysis for technology stack enumeration",
        "WHOIS and DNS reconnaissance on {domain}",
        "Shodan scanning detected probing exposed services",
        "Certificate transparency logs searched for subdomains",
    ],
}

def random_fill(template):
    return template.format(
        cve=f"{random.randint(2018,2024)}-{random.randint(1000,99999)}",
        method=random.choice(["DLL injection","token impersonation","UAC bypass","kernel exploit"]),
        host=f"WORKSTATION-{random.randint(1,200)}",
        proc=random.choice(["svchost.exe","lsass.exe","explorer.exe","cmd.exe","powershell.exe"]),
        ip=f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        port=random.choice([80,443,4444,8080,8443,1337,31337]),
        interval=random.choice([30,60,120,300,600]),
        domain=f"{''.join(random.choices('abcdefghijklmnop',k=8))}.{''.join(random.choices('abcdefgh',k=4))}.com",
        n=random.randint(10,10000),
        time=f"{random.randint(0,23):02d}:{random.randint(0,59):02d}",
        size=random.randint(50,5000),
        service=random.choice(["Microsoft 365","Google","Dropbox","OneDrive","SSH","RDP","SMTP"]),
        src=f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
        dst=f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
        dept=random.choice(["Finance","HR","Engineering","Executive","Operations"]),
        taskname=f"Task_{random.randint(1000,9999)}",
        svcname=f"svc_{random.randint(100,999)}",
        gbps=random.uniform(1,500),
        pct=random.randint(50,100),
        document=f"invoice_{random.randint(100,999)}.docx",
        name=random.choice(["LockBit","BlackCat","REvil","Conti","Maze","Ryuk"]),
        source=random.choice(["LinkedIn","GitHub","Twitter","company website","Shodan"]),
        software=random.choice(["SolarWinds","Kaseya","npm package","Python library"]),
        gbps2=random.uniform(1,100),
        interval2=random.randint(10,600),
    )

def generate_threat_classification_dataset(n_samples=5000):
    """Generate dataset for threat type classification"""
    records = []
    categories = list(THREAT_TEMPLATES.keys())
    samples_per_class = n_samples // len(categories)

    for category in categories:
        templates = THREAT_TEMPLATES[category]
        for _ in range(samples_per_class):
            template = random.choice(templates)
            try:
                text = random_fill(template)
            except KeyError:
                text = template
            records.append({
                "text": text,
                "threat_category": category,
                "severity": random.choice(SEVERITY_LEVELS),
                "confidence": round(random.uniform(0.75, 0.99), 3),
            })

    df = pd.DataFrame(records)
    return shuffle(df, random_state=42).reset_index(drop=True)

def generate_framework_mapping_dataset(n_samples=4000):
    """Generate dataset for MITRE ATT&CK / D3FEND / NIST / OWASP mapping"""
    records = []
    techniques = list(ATTCK_TECHNIQUES.items())
    
    category_to_techniques = {
        "Privilege Escalation": ["T1068", "T1055", "T1053"],
        "Command & Control": ["T1071", "T1041", "T1105"],
        "Exfiltration": ["T1041", "T1071", "T1027"],
        "Lateral Movement": ["T1021", "T1078", "T1055"],
        "Phishing": ["T1566", "T1078", "T1059"],
        "Credential Access": ["T1003", "T1110", "T1078"],
        "Persistence": ["T1053", "T1078", "T1059"],
        "Defense Evasion": ["T1027", "T1562", "T1070"],
        "Discovery": ["T1082", "T1083", "T1046"],
        "Initial Access": ["T1190", "T1133", "T1566"],
        "Execution": ["T1059", "T1053", "T1055"],
        "Impact": ["T1486", "T1562", "T1041"],
        "Reconnaissance": ["T1082", "T1046", "T1018"],
    }

    for _ in range(n_samples):
        category = random.choice(list(THREAT_TEMPLATES.keys()))
        tech_ids = category_to_techniques.get(category, ["T1059"])
        tech_id = random.choice(tech_ids)
        tech_name = ATTCK_TECHNIQUES.get(tech_id, "Unknown Technique")
        
        templates = THREAT_TEMPLATES[category]
        template = random.choice(templates)
        try:
            text = random_fill(template)
        except KeyError:
            text = template

        records.append({
            "text": text,
            "threat_category": category,
            "attck_technique_id": tech_id,
            "attck_technique_name": tech_name,
            "d3fend_technique": random.choice(D3FEND_TECHNIQUES),
            "nist_control": random.choice(NIST_CONTROLS),
            "owasp_requirement": random.choice(OWASP_REQS),
            "tactic": random.choice(MITRE_TACTICS),
        })

    df = pd.DataFrame(records)
    return shuffle(df, random_state=42).reset_index(drop=True)

def generate_severity_scoring_dataset(n_samples=5000):
    """Generate dataset for severity/risk scoring"""
    records = []
    categories = list(THREAT_TEMPLATES.keys())

    severity_map = {
        "Impact": "Critical",
        "Credential Access": "Critical",
        "Exfiltration": "High",
        "Lateral Movement": "High",
        "Command & Control": "High",
        "Privilege Escalation": "High",
        "Initial Access": "High",
        "Persistence": "Medium",
        "Defense Evasion": "Medium",
        "Execution": "Medium",
        "Discovery": "Low",
        "Reconnaissance": "Low",
        "Phishing": "Medium",
    }

    for _ in range(n_samples):
        category = random.choice(categories)
        templates = THREAT_TEMPLATES[category]
        template = random.choice(templates)
        try:
            text = random_fill(template)
        except KeyError:
            text = template

        base_severity = severity_map.get(category, "Medium")
        # Add some noise for realism
        if random.random() < 0.15:
            sev_idx = SEVERITY_LEVELS.index(base_severity)
            sev_idx = max(0, min(3, sev_idx + random.choice([-1, 1])))
            severity = SEVERITY_LEVELS[sev_idx]
        else:
            severity = base_severity

        cvss_base = {"Critical": 9.0, "High": 7.5, "Medium": 5.0, "Low": 2.5}[severity]
        cvss_score = round(cvss_base + random.uniform(-0.9, 0.9), 1)
        cvss_score = max(0.1, min(10.0, cvss_score))

        records.append({
            "text": text,
            "threat_category": category,
            "severity": severity,
            "cvss_score": cvss_score,
            "exploitability": round(random.uniform(0.5, 1.0), 2),
            "impact_score": round(random.uniform(0.3, 1.0), 2),
            "affected_assets": random.randint(1, 500),
        })

    df = pd.DataFrame(records)
    return shuffle(df, random_state=42).reset_index(drop=True)

def generate_prediction_dataset(n_samples=3000):
    """Generate dataset for threat prediction/trend analysis"""
    records = []
    categories = list(THREAT_TEMPLATES.keys())

    for i in range(n_samples):
        # Simulate historical threat counts per category
        history = {cat: random.randint(0, 50) for cat in categories[:8]}
        
        # Predict next most likely category based on weighted history
        weights = list(history.values())
        total = sum(weights) + 1
        probs = [w/total for w in weights]
        next_threat = random.choices(list(history.keys()), weights=probs)[0]

        records.append({
            **{f"hist_{k.lower().replace(' ','_').replace('&','n')}": v 
               for k, v in history.items()},
            "days_since_last_incident": random.randint(0, 90),
            "active_cves": random.randint(0, 20),
            "patch_compliance_pct": random.randint(50, 100),
            "threat_intel_score": round(random.uniform(0.1, 1.0), 2),
            "next_likely_threat": next_threat,
            "risk_trend": random.choice(["Increasing", "Stable", "Decreasing"]),
        })

    df = pd.DataFrame(records)
    return shuffle(df, random_state=42).reset_index(drop=True)

def generate_pcap_features_dataset(n_samples=5000):
    """Generate network traffic feature dataset (simulates PCAP extracted features)"""
    records = []
    
    attack_types = [
        "Normal", "DDoS", "Port Scan", "Brute Force",
        "C2 Beacon", "Data Exfiltration", "Lateral Movement", "DNS Tunneling"
    ]

    for _ in range(n_samples):
        label = random.choice(attack_types)

        if label == "Normal":
            pkt_len_mean = random.uniform(200, 1400)
            pkt_rate = random.uniform(1, 100)
            flow_duration = random.uniform(0.1, 300)
            dst_port_entropy = random.uniform(0.1, 0.5)
            payload_entropy = random.uniform(3.5, 5.5)
            syn_flag_ratio = random.uniform(0.0, 0.05)
            bytes_per_second = random.uniform(100, 100000)
            unique_dst_ips = random.randint(1, 10)
            failed_conn_ratio = random.uniform(0.0, 0.05)
            avg_ttl = random.uniform(55, 128)

        elif label == "DDoS":
            pkt_len_mean = random.uniform(40, 200)
            pkt_rate = random.uniform(5000, 100000)
            flow_duration = random.uniform(0.001, 5)
            dst_port_entropy = random.uniform(0.0, 0.2)
            payload_entropy = random.uniform(0.1, 2.0)
            syn_flag_ratio = random.uniform(0.7, 1.0)
            bytes_per_second = random.uniform(1000000, 100000000)
            unique_dst_ips = random.randint(1, 3)
            failed_conn_ratio = random.uniform(0.6, 1.0)
            avg_ttl = random.uniform(40, 64)

        elif label == "Port Scan":
            pkt_len_mean = random.uniform(40, 80)
            pkt_rate = random.uniform(100, 10000)
            flow_duration = random.uniform(0.0001, 0.01)
            dst_port_entropy = random.uniform(0.8, 1.0)
            payload_entropy = random.uniform(0.0, 1.0)
            syn_flag_ratio = random.uniform(0.9, 1.0)
            bytes_per_second = random.uniform(1000, 500000)
            unique_dst_ips = random.randint(1, 5)
            failed_conn_ratio = random.uniform(0.7, 1.0)
            avg_ttl = random.uniform(55, 128)

        elif label == "Brute Force":
            pkt_len_mean = random.uniform(60, 200)
            pkt_rate = random.uniform(50, 500)
            flow_duration = random.uniform(1, 60)
            dst_port_entropy = random.uniform(0.0, 0.1)
            payload_entropy = random.uniform(2.0, 4.5)
            syn_flag_ratio = random.uniform(0.4, 0.8)
            bytes_per_second = random.uniform(500, 50000)
            unique_dst_ips = random.randint(1, 2)
            failed_conn_ratio = random.uniform(0.5, 0.9)
            avg_ttl = random.uniform(55, 128)

        elif label == "C2 Beacon":
            pkt_len_mean = random.uniform(100, 500)
            pkt_rate = random.uniform(0.1, 5)
            flow_duration = random.uniform(60, 3600)
            dst_port_entropy = random.uniform(0.0, 0.15)
            payload_entropy = random.uniform(5.5, 7.5)
            syn_flag_ratio = random.uniform(0.0, 0.1)
            bytes_per_second = random.uniform(10, 5000)
            unique_dst_ips = random.randint(1, 3)
            failed_conn_ratio = random.uniform(0.0, 0.05)
            avg_ttl = random.uniform(55, 128)

        elif label == "Data Exfiltration":
            pkt_len_mean = random.uniform(800, 1500)
            pkt_rate = random.uniform(10, 1000)
            flow_duration = random.uniform(60, 3600)
            dst_port_entropy = random.uniform(0.0, 0.2)
            payload_entropy = random.uniform(6.0, 8.0)
            syn_flag_ratio = random.uniform(0.0, 0.05)
            bytes_per_second = random.uniform(100000, 10000000)
            unique_dst_ips = random.randint(1, 3)
            failed_conn_ratio = random.uniform(0.0, 0.02)
            avg_ttl = random.uniform(55, 128)

        elif label == "Lateral Movement":
            pkt_len_mean = random.uniform(200, 1000)
            pkt_rate = random.uniform(5, 200)
            flow_duration = random.uniform(1, 300)
            dst_port_entropy = random.uniform(0.2, 0.6)
            payload_entropy = random.uniform(3.0, 6.0)
            syn_flag_ratio = random.uniform(0.1, 0.4)
            bytes_per_second = random.uniform(1000, 500000)
            unique_dst_ips = random.randint(5, 50)
            failed_conn_ratio = random.uniform(0.1, 0.4)
            avg_ttl = random.uniform(55, 128)

        elif label == "DNS Tunneling":
            pkt_len_mean = random.uniform(200, 800)
            pkt_rate = random.uniform(1, 100)
            flow_duration = random.uniform(60, 7200)
            dst_port_entropy = random.uniform(0.0, 0.05)
            payload_entropy = random.uniform(6.5, 8.0)
            syn_flag_ratio = random.uniform(0.0, 0.02)
            bytes_per_second = random.uniform(100, 50000)
            unique_dst_ips = random.randint(1, 2)
            failed_conn_ratio = random.uniform(0.0, 0.05)
            avg_ttl = random.uniform(55, 128)

        records.append({
            "pkt_len_mean": round(pkt_len_mean, 2),
            "pkt_rate": round(pkt_rate, 4),
            "flow_duration": round(flow_duration, 4),
            "dst_port_entropy": round(dst_port_entropy, 4),
            "payload_entropy": round(payload_entropy, 4),
            "syn_flag_ratio": round(syn_flag_ratio, 4),
            "bytes_per_second": round(bytes_per_second, 2),
            "unique_dst_ips": unique_dst_ips,
            "failed_conn_ratio": round(failed_conn_ratio, 4),
            "avg_ttl": round(avg_ttl, 1),
            "label": label,
        })

    df = pd.DataFrame(records)
    return shuffle(df, random_state=42).reset_index(drop=True)

def generate_log_analysis_dataset(n_samples=4000):
    """Generate system/application log dataset for anomaly detection"""
    records = []

    log_templates = {
        "Malicious": [
            "FAILED LOGIN for user {user} from {ip} - attempt {n} of {max}",
            "Unauthorized access to {resource} denied for user {user}",
            "SQL injection attempt detected in parameter {param}: {payload}",
            "XSS payload detected in {field}: {payload}",
            "File {file} accessed outside permitted directory",
            "Privilege escalation attempt by user {user} PID {pid}",
            "Outbound connection to known malicious IP {ip}:{port}",
            "Suspicious process {proc} spawned by {parent}",
            "Registry key {key} modified by unauthorized process",
            "Encrypted payload detected in {proto} traffic to {ip}",
        ],
        "Benign": [
            "User {user} logged in successfully from {ip}",
            "File {file} read by process {proc} PID {pid}",
            "Service {svc} started successfully",
            "Scheduled backup completed at {time}",
            "Network connection established to {ip}:{port}",
            "Configuration file {file} loaded successfully",
            "User {user} password changed successfully",
            "Patch {patch} applied successfully",
            "Outbound HTTPS connection to {domain}",
            "System health check passed - all services nominal",
        ]
    }

    for _ in range(n_samples // 2):
        for label in ["Malicious", "Benign"]:
            template = random.choice(log_templates[label])
            try:
                log_text = template.format(
                    user=f"user{random.randint(1,500)}",
                    ip=f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                    n=random.randint(1,100),
                    max=random.randint(3,10),
                    resource=random.choice(["/etc/passwd","/admin","C:\\Windows\\System32","database"]),
                    param=random.choice(["id","username","search","query","cmd"]),
                    payload=random.choice(["' OR 1=1--","<script>alert(1)</script>","../../../etc/passwd",";ls -la"]),
                    field=random.choice(["input","comment","username","search"]),
                    file=f"/var/log/{random.choice(['auth','syslog','kern'])}.log",
                    pid=random.randint(100,99999),
                    parent=random.choice(["svchost.exe","bash","python3","cmd.exe"]),
                    port=random.randint(1,65535),
                    proc=random.choice(["ps","ls","cmd","powershell","python"]),
                    key=r"HKLM\Software\Run",
                    proto=random.choice(["HTTP","DNS","ICMP","TCP"]),
                    svc=random.choice(["nginx","apache","sshd","mysql"]),
                    time=f"{random.randint(0,23):02d}:{random.randint(0,59):02d}",
                    patch=f"KB{random.randint(1000000,9999999)}",
                    domain=f"{''.join(random.choices('abcdefgh',k=6))}.com",
                )
            except KeyError:
                log_text = template

            records.append({
                "log_text": log_text,
                "label": label,
                "log_level": random.choice(["INFO","WARNING","ERROR","CRITICAL"] if label=="Malicious" else ["INFO","DEBUG","INFO"]),
                "event_count_1h": random.randint(1, 1000) if label=="Malicious" else random.randint(1, 50),
            })

    df = pd.DataFrame(records)
    return shuffle(df, random_state=42).reset_index(drop=True)

if __name__ == "__main__":
    print("Generating AutoMITRE training datasets...")
    
    datasets = {
        "threat_classification": generate_threat_classification_dataset(6000),
        "framework_mapping": generate_framework_mapping_dataset(5000),
        "severity_scoring": generate_severity_scoring_dataset(6000),
        "threat_prediction": generate_prediction_dataset(4000),
        "pcap_features": generate_pcap_features_dataset(6000),
        "log_analysis": generate_log_analysis_dataset(5000),
    }

    DATA_DIR = Path(__file__).parent.parent.parent / "data" / "training_data"
    DATA_DIR.mkdir(exist_ok=True, parents=True)

    for name, df in datasets.items():
        path = DATA_DIR / f"{name}.csv"
        df.to_csv(path, index=False)
        print(f"  ✓ {name}: {len(df)} samples → {path}")

    with open(DATA_DIR / "dataset_guide.json", "w") as f:
        json.dump(DATASET_GUIDE, f, indent=2)

    print("\nDataset generation complete!")
    print(json.dumps({k: len(v) for k, v in datasets.items()}, indent=2))
