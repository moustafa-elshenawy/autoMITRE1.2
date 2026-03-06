import sys
import logging
logging.basicConfig(level=logging.INFO)
sys.path.append('/Users/shno/Desktop/autoMITRE1.2/backend')
from core.ai_threat_analyzer import analyze_threat
import json

res = analyze_threat({
    "normalized_text": "The attackers used mimikatz to dump credentials",
    "entities": []
})
print("Mapped Techniques:", len(res.attack_techniques))
for t in res.attack_techniques:
    print(t.id, t.name, t.confidence)
