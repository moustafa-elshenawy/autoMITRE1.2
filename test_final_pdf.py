import sys
import os
sys.path.append('/Users/shno/Desktop/autoMITRE1.2/backend')
from core.pdf_generator import generate_pdf_report
from pypdf import PdfReader

# mock data that is long enough to cause problems if columns fail
long_text = "The detected ransomware activity indicates a well planned and executed attack. The initial vector appears to be a SQL injection attempt on the login portal, which likely exploited using the CVE-2024-1234 vulnerability. This allowed the attackers to gain access to the internal network and execute Mimikatz credential dumping to obtain sensitive credentials. PowerShell execution with a base64 encoded payload was observed, suggesting the use of a living off the land (LOTL) technique to maintain a low profile. The attackers then leveraged RDP " * 10

threats = [{"title": "Ransomware Campaign", "risk_score": {"severity": "Critical", "score": 9.7}, "description": long_text, "mitigations": [{"title":"Mit 1", "description":"Desc 1", "priority":"High"}]}]

pdf_io = generate_pdf_report(threats, "executive")
with open("test_final.pdf", "wb") as f:
    f.write(pdf_io.getvalue())
    
reader = PdfReader("test_final.pdf")
print("Total pages generated:", len(reader.pages))
