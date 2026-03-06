import requests

payload = {
    "text": "An adversary used a spearphishing attachment containing a malicious macro to gain initial access, then used PowerShell to download a remote access trojan."
}

res = requests.post("http://localhost:8000/api/v2/analyze", json=payload)
print(res.json())
