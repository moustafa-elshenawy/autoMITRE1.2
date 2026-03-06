import sys
import logging
sys.path.append('/Users/shno/Desktop/autoMITRE1.2/backend')
from core.ai_threat_analyzer import classify_threats, get_attack_techniques
from core import technique_embedder

technique_embedder.precompute_technique_embeddings()

text = "The attackers used mimikatz to dump credentials"
tech_scores = classify_threats({'normalized_text': text, 'suggested_techniques': []})
print("tech_scores from classify_threats:", tech_scores)

semantic_scores = technique_embedder.batch_score_techniques(text, list(tech_scores.keys()))
print("semantic_scores:", semantic_scores)

res = get_attack_techniques(tech_scores, text)
print("\nFinal Results:")
for t in res:
    print(f"{t.id} {t.name}: {t.confidence} (Base: {tech_scores.get(t.id, 0)}, Sem: {semantic_scores.get(t.id, 0)})")
