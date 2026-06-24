import sys
import os
sys.path.insert(0, os.path.abspath('backend'))
from core.pipelines.json_pipeline import analyze_json_pipeline

text_content = '{"event_data": {"ProcessName": "mimikatz.exe", "CommandLine": "privilege::debug log sekurlsa::logonpasswords exit"}}'
res = analyze_json_pipeline(text_content)
print("Returned Techniques:")
for t in res.attack_techniques:
    print(f" - {t.id}: {t.confidence}")
