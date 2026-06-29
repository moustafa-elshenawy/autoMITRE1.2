import sys, io
sys.path.append('backend')
from xhtml2pdf import pisa
from pypdf import PdfReader

html = """
<html>
<style>
  @page { size: a4 portrait; margin: 1cm; }
  table { width: 100%; border-collapse: collapse; }
  th, td { border: 1px solid black; padding: 5pt; word-wrap: break-word; }
</style>
<body>
    <table>
        <pdf:col width="120pt"/>
        <pdf:col width="80pt"/>
        <pdf:col width="300pt"/>
        <tr>
            <th>Threat Title</th>
            <th>Severity</th>
            <th>Description</th>
        </tr>
        <tr>
            <td>Ransomware Campaign: SQL Injection, Lateral Movement, and Data Exfiltration</td>
            <td>Critical (9.7/10)</td>
            <td>The detected ransomware activity indicates a well-planned and executed attack. The initial vector appears to be a SQL injection attempt on the login portal, which likely exploited using the CVE-2024-1234 vulnerability. This allowed the attackers to gain access to the internal network and execute Mimikatz credential dumping to obtain sensitive credentials. PowerShell execution with a base64-encoded payload was observed, suggesting the use of a living-off-the-land (LOTL) technique to maintain a low profile. The attackers then</td>
        </tr>
    </table>
</body>
</html>
"""

with open("test_col.pdf", "wb") as f:
    pisa.CreatePDF(io.StringIO(html), f)
