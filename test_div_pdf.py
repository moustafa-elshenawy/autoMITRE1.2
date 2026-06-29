import sys, io
sys.path.append('backend')
from xhtml2pdf import pisa

html = """
<html>
<style>
  @page { size: a4 portrait; margin: 1.5cm; }
  body { font-family: Helvetica, Arial, sans-serif; font-size: 10pt; color: #333333; line-height: 1.5; }
  .threat-card {
      border: 1px solid #cbd5e1;
      border-radius: 4px;
      margin-bottom: 15pt;
      padding: 12pt;
      background-color: #ffffff;
  }
  .threat-header {
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 8pt;
      margin-bottom: 8pt;
  }
  .threat-title {
      font-size: 12pt;
      font-weight: bold;
      color: #0f172a;
  }
  .severity-badge {
      font-weight: bold;
      color: #dc2626;
      font-size: 10pt;
  }
  .threat-description {
      color: #475569;
      text-align: justify;
  }
</style>
<body>
    <div class="threat-card">
        <div class="threat-header">
            <div class="threat-title">Ransomware Campaign: SQL Injection, Lateral Movement, and Data Exfiltration</div>
            <div class="severity-badge">Severity: Critical (9.7/10)</div>
        </div>
        <div class="threat-description">
            The detected ransomware activity indicates a well-planned and executed attack. The initial vector appears to be a SQL injection attempt on the login portal, which likely exploited using the CVE-2024-1234 vulnerability. This allowed the attackers to gain access to the internal network and execute Mimikatz credential dumping to obtain sensitive credentials. PowerShell execution with a base64-encoded payload was observed, suggesting the use of a living-off-the-land (LOTL) technique to maintain a low profile.
        </div>
    </div>
</body>
</html>
"""

with open("test_div.pdf", "wb") as f:
    pisa.CreatePDF(io.StringIO(html), f)
