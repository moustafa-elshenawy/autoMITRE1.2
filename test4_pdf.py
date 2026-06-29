import sys
import os
sys.path.append('/Users/shno/Desktop/autoMITRE1.2/backend')
from xhtml2pdf import pisa
import io

html = """<!DOCTYPE html>
<html>
<head>
<style>
  @page { size: a4 portrait; margin: 2cm; }
  body { font-family: Helvetica, sans-serif; font-size: 11pt; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid black; padding: 8pt; word-wrap: break-word; }
</style>
</head>
<body>
    <table>
        <pdf:col width="25%" />
        <pdf:col width="15%" />
        <pdf:col width="60%" />
        <thead>
        <tr>
            <th>Threat Title</th>
            <th>Severity</th>
            <th>Business Impact Statement</th>
        </tr>
        </thead>
        <tr>
            <td>Ransomware Campaign</td>
            <td>Critical</td>
            <td>The detected ransomware activity indicates a well planned and executed attack. The initial vector appears to be a SQL injection attempt on the login portal, which likely exploited using the CVE-2024-1234 vulnerability. This allowed the attackers to gain access to the internal network and execute Mimikatz credential dumping to obtain sensitive credentials. PowerShell execution with a base64 encoded payload was observed, suggesting the use of a living off the land (LOTL) technique to maintain a low profile. The attackers then leveraged RDP...</td>
        </tr>
    </table>
</body>
</html>"""
with open("test4_output.pdf", "wb") as f:
    pisa.CreatePDF(io.StringIO(html), f)
