import sys
sys.path.append('/Users/shno/Desktop/autoMITRE1.2/backend')
from core.secbert_classifier import secbert_clf

res = secbert_clf.predict_techniques("The attackers used mimikatz to dump credentials")
print(res)

from core.ai_threat_analyzer import calculate_confidence, THREAT_SIGNATURES
conf = calculate_confidence("The attackers used mimikatz to dump credentials", THREAT_SIGNATURES['credential_attack']['keywords'])
print("Heuristic confidence:", conf)
