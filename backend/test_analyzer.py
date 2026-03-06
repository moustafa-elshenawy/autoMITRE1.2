import asyncio
import logging
import json
from core.ai_threat_analyzer import analyze_threat

logging.basicConfig(level=logging.INFO)

def run_test():
    text1 = "An attacker sent a spearphishing email with a malicious attachment. Upon opening, it executed a script that dumped OS credentials and attempted to establish external command and control."
    text2 = "An attacker sent a spearphishing email with a malicious attachment. Upon opening, it executed a script that dumped OS credentials and attempted to establish external command and control. and then they encrypted the database"
    
    print("Testing Text 1...")
    result1 = analyze_threat({'normalized_text': text1})
    print("Score 1:", result1.risk_score.score)

    print("\nTesting Text 2...")
    result2 = analyze_threat({'normalized_text': text2})
    print("Score 2:", result2.risk_score.score)

if __name__ == "__main__":
    run_test()
