import logging
import sys
import os

# Configure logging to see pre-pruning logs
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Adjust import paths
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.pipelines import analyze_text_pipeline

text = "At 03:00 AM, the adversary breached the external gateway by exploiting a critical vulnerability in the public-facing web server. Upon gaining initial access, they executed a base64-encoded PowerShell script to silently disable local antivirus agents. The threat actor then deployed Mimikatz to extract domain administrator credentials directly from LSASS memory. Using these elevated privileges, they moved laterally via RDP to the primary database server. Ultimately, the attacker exfiltrated 500GB of sensitive financial data over an encrypted HTTPS C2 channel to evil-c2.attacker.com before deploying the Ryuk ransomware payload, which encrypted all host drives and dropped a text-based ransom note on the desktop."

def run_test():
    print("=== STARTING PIPELINE TEST ===")
    processed_input = {'normalized_text': text, 'entities': []}
    result = analyze_text_pipeline(processed_input, deep_analysis=True)
    
    print("\n=== PIPELINE RESULT ===")
    print(result.model_dump())

if __name__ == "__main__":
    run_test()
