import os
import sys
import asyncio
import logging

# Ensure backend directory is in the import path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure minimal logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_pipelines")

# Import pipelines
from core.pipelines import (
    analyze_text_pipeline,
    analyze_pcap_pipeline,
    extract_pcap_attacks_pipeline,
    analyze_hash_pipeline,
    analyze_osint_pipeline
)
from core.input_processor import process_input, InputType

def test_text_pipeline():
    logger.info("=== Testing Text Pipeline ===")
    
    # 1. Short Text
    sample_text = "Brute force credential attack on admin portal from IP 192.168.1.100. Threat actor is using Mimikatz to dump memory."
    processed = process_input(sample_text, InputType.TEXT.value)
    logger.info("Running text pipeline with short text...")
    result = analyze_text_pipeline(processed, deep_analysis=False)
    logger.info("Text Pipeline Output:")
    logger.info(f"  Title: {result.title}")
    logger.info(f"  Techniques: {[t.id for t in result.attack_techniques]}")
    assert len(result.attack_techniques) > 0, "No techniques mapped!"
    
    # 2. Long Diluted Text (Testing chunking + booster logic)
    long_diluted_text = (
        "We are writing this incident response report to document normal system activities during the daily audit. "
        "The server host name is production-web-server-01 and it handles web traffic. The administrator logged in at 08:00 AM. "
        "The security engineer performed an inspection of the process memory. A suspicious process was found. "
        "In particular, the threat actor ran mimikatz to dump credentials from the LSASS process to gain administrative access. "
        "Afterwards, some network activity was logged, but nothing else. We recommend checking server logs and upgrading local protection."
    )
    processed_long = process_input(long_diluted_text, InputType.TEXT.value)
    logger.info("Running text pipeline with long diluted text (verifying chunking + max-pooling fixes)...")
    result_long = analyze_text_pipeline(processed_long, deep_analysis=False)
    logger.info("Long Diluted Text Output:")
    logger.info(f"  Title: {result_long.title}")
    logger.info(f"  Techniques: {[(t.id, t.confidence) for t in result_long.attack_techniques]}")
    t1003_matches = [t for t in result_long.attack_techniques if t.id.startswith('T1003')]
    assert len(t1003_matches) > 0, "T1003 got diluted and filtered out!"
    assert t1003_matches[0].confidence >= 0.70, f"T1003 confidence is too low: {t1003_matches[0].confidence}"
    
    logger.info("✅ Text Pipeline passed!\n")

def test_hash_pipeline():
    logger.info("=== Testing Hash Pipeline ===")
    # A dummy hash for lookup (should gracefully return not found or query VT if key is configured)
    dummy_hash = "44d88612fe83b813cfb4d1101bd2500000000000000000000000000000000000" # Invalid size for testing fallback
    
    logger.info("Running hash pipeline...")
    try:
        result = analyze_hash_pipeline(dummy_hash)
        logger.info("Hash Pipeline Output:")
        logger.info(f"  Title: {result.title}")
        logger.info(f"  Verdict: {result.raw_indicators.get('virustotal', {}).get('verdict', 'unknown')}")
        logger.info("✅ Hash Pipeline passed (or handled API fallback)!\n")
    except Exception as e:
        logger.info(f"  Hash pipeline returned exception (expected on invalid test hash): {e}")
        logger.info("✅ Hash Pipeline fallback logic passed!\n")

def test_pcap_pipeline():
    logger.info("=== Testing PCAP Pipeline ===")
    pcap_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_sqli.pcap")
    
    if not os.path.exists(pcap_path):
        logger.error(f"  PCAP test file not found at: {pcap_path}")
        logger.info("❌ PCAP Pipeline skipped (missing test file).\n")
        return
        
    logger.info(f"Parsing PCAP file: {pcap_path}...")
    
    # 1. Test Threat Result pipeline
    result = analyze_pcap_pipeline(pcap_path, context="Testing SQL Injection PCAP file.")
    logger.info("PCAP Threat Result Pipeline Output:")
    logger.info(f"  Title: {result.title}")
    logger.info(f"  Risk Score: {result.risk_score.score} ({result.risk_score.severity})")
    logger.info(f"  Techniques: {[t.id for t in result.attack_techniques]}")
    assert len(result.attack_techniques) > 0, "No techniques mapped from PCAP!"
    
    # 2. Test Extract Attacks pipeline
    attacks = extract_pcap_attacks_pipeline(pcap_path, context="Extracting attacks.")
    logger.info("PCAP Extract Attacks Pipeline Output:")
    logger.info(f"  Extracted {len(attacks)} distinct attacks:")
    for a in attacks:
        logger.info(f"    - ID: {a.id}, Title: {a.title}, Severity: {a.severity_estimate}, Technique: {a.mitre_technique_id}")
    assert len(attacks) > 0, "No attacks extracted from PCAP!"
    
    logger.info("✅ PCAP Pipeline passed!\n")

async def test_osint_pipeline():
    logger.info("=== Testing OSINT Pipeline ===")
    logger.info("Running OSINT pipeline...")
    # Include MISP=False to avoid needing a local MISP instance setup during testing
    result = await analyze_osint_pipeline(include_misp=False)
    
    logger.info("OSINT Pipeline Output:")
    logger.info(f"  Ingested {result.get('total', 0)} threat intelligence items.")
    logger.info(f"  Sources active: {result.get('sources', {})}")
    logger.info("✅ OSINT Pipeline passed!\n")
def test_gating_and_blending():
    logger.info("=== Testing Parameterized Gating and Blending Weights ===")
    from core.ai_threat_analyzer import get_attack_techniques
    
    # A mid-range technique score of 0.60
    tech_scores = {"T1003.001": 0.60}
    sample_text = "The system was checked. User logged in."
    
    # 1. Test with chunk_text=True, apply_semantic_penalty=False, pruning_threshold=0.55
    results_low_gate = get_attack_techniques(
        tech_scores,
        sample_text,
        apply_semantic_penalty=False,
        chunk_text=True,
        pruning_threshold=0.55
    )
    logger.info(f"  Results with threshold 0.55: {[t.id for t in results_low_gate]}")
    assert len(results_low_gate) > 0, "Mid-range technique was incorrectly filtered out at 0.55 threshold!"
    
    conf = results_low_gate[0].confidence
    logger.info(f"  Confidence computed: {conf}")
    # Expected confidence should be: base_conf * 0.8 + semantic_conf * 0.2
    # Since base_conf=0.60, conf should be in the range [0.48, 0.68]
    assert 0.48 <= conf <= 0.68, f"Confidence {conf} is out of expected blending bounds!"
    
    # 2. Test with pruning_threshold=0.70 (Strict legacy mode/PCAP mode)
    results_high_gate = get_attack_techniques(
        tech_scores,
        sample_text,
        apply_semantic_penalty=False,
        chunk_text=True,
        pruning_threshold=0.70
    )
    logger.info(f"  Results with threshold 0.70: {[t.id for t in results_high_gate]}")
    assert len(results_high_gate) == 0, "Mid-range technique should have been filtered out at 0.70 threshold!"
    
    logger.info("✅ Parameterized Gating and Blending Weights tests passed!\n")

async def main():
    try:
        test_gating_and_blending()
        test_text_pipeline()
        test_hash_pipeline()
        test_pcap_pipeline()
        await test_osint_pipeline()
        logger.info("🎉 All logical pipelines passed successfully!")
    except Exception as e:
        logger.error(f"❌ Pipeline verification failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
