import uuid
import os
import logging
from datetime import datetime
from typing import Dict, Any, List
import numpy as np

from models.schemas import (
    ATTACKTechnique, ThreatResult, RiskScore, SeverityLevel,
    ThreatEntity, MitigationStep, PredictedStep
)
from core.ai_threat_analyzer import (
    classify_threats, determine_severity, get_attack_techniques,
    generate_predictive_actions, generate_business_impact, get_mitigations,
    _get_threat_title, _clear_mps_cache, _merge_technique_tracks
)
from core.framework_mapper import map_to_defend, map_to_nist, map_to_owasp
from core.ml_engine import ml_engine
from core.intake_router import (
    route as _route_intake, ENGINE_DEEP_LEARNING, ENGINE_RAG, ENGINE_HYBRID,
)

logger = logging.getLogger("text_pipeline")

def analyze_text_pipeline(processed_input: Dict[str, Any], deep_analysis: bool = False,
                          pipeline_mode: str = "auto", apply_semantic_penalty: bool = False,
                          chunk_text: bool = True, bypass_semantic: bool = False,
                          pruning_threshold: float = 0.55) -> ThreatResult:
    """
    Orchestrates the threat analysis pipeline specifically for unstructured text CTI reports,
    advisories, and log fields.
    """
    text = processed_input.get('normalized_text', '')
    entities = processed_input.get('entities', [])

    # 1. Heuristic Baseline Scoring (Fast)
    technique_scores = classify_threats(processed_input, chunk_text=chunk_text)
    severity, likelihood, impact = determine_severity(text, list(technique_scores.keys()))
    
    # Calculate initial CVSS-inspired score (0-10)
    base_score = float(round((likelihood * 0.4 + impact * 0.6) * 2, 1))
    base_score = min(10.0, base_score)

    # 2. Industrial ML Ensemble (SecBERT + Phi-3.5)
    is_anomalous, final_score, deep_insights = ml_engine.evaluate_threat(processed_input, base_score, deep_analysis=deep_analysis, chunk_text=chunk_text)
    
    # 3. Dynamic Variance (Prevent "Clumping" at identical values like 6.6)
    if final_score is not None:
        text_factor = (len(text) % 100) / 200.0
        entity_factor = (len(entities) % 10) / 20.0
        variance = (text_factor + entity_factor) - 0.5 
        final_score = float(np.clip(final_score + variance, 0.0, 10.0))
        final_score = round(final_score, 1)
    
    # 4. Final Result Construction
    final_techniques_list = []
    if deep_analysis and deep_insights:
        raw_ttps = deep_insights.get("ttps", [])
        normalized_ttps = []
        seen_tids = set()
        
        for ttp in raw_ttps:
            if isinstance(ttp, str):
                tid = ttp
                ttp_dict = {"id": tid, "name": "Classified Technique", "confidence": 0.85, "verified": False, "evidence": ["AI Reasoning"]}
            else:
                tid = ttp.get("id")
                ttp_dict = ttp
                
            if tid and tid not in seen_tids:
                seen_tids.add(tid)
                normalized_ttps.append(ttp_dict)

        from core.ai_threat_analyzer import _ATTACK_LOOKUP
        for ttp in normalized_ttps:
            tid = ttp.get("id")
            name = ttp.get("name")
            tactic = ttp.get("tactic", "Multiple Tactics")
            
            if (not name or name == "Classified Technique") and tid in _ATTACK_LOOKUP:
                name = _ATTACK_LOOKUP[tid].get("name", name)
                tactic = _ATTACK_LOOKUP[tid].get("tactic", tactic)

            final_techniques_list.append(ATTACKTechnique(
                id=tid,
                name=name or "Classified Technique",
                tactic=tactic,
                confidence=float(round(ttp.get("confidence", 0.5), 2)),
                verified=ttp.get("verified", False),
                evidence=ttp.get("evidence", [])
            ))
    
    if not final_techniques_list:
        final_techniques_list = get_attack_techniques(
            technique_scores,
            text,
            apply_semantic_penalty=apply_semantic_penalty,
            chunk_text=chunk_text,
            bypass_semantic=bypass_semantic,
            pruning_threshold=pruning_threshold
        )

    # 5. Engine Selection via Intake Router
    routing_decision = _route_intake(text, pipeline_mode)
    engine = routing_decision["engine"]

    def _to_attack_techniques(techs):
        from core.ai_threat_analyzer import _ATTACK_LOOKUP
        out = []
        for t in techs:
            name = t.get("name")
            tactic = t.get("tactic", "Multiple Tactics")
            if (not name or name == "Classified Technique") and t["id"] in _ATTACK_LOOKUP:
                name = _ATTACK_LOOKUP[t["id"]].get("name", name)
                tactic = _ATTACK_LOOKUP[t["id"]].get("tactic", tactic)
            out.append(ATTACKTechnique(
                id=t["id"],
                name=name or "Classified Technique",
                tactic=tactic,
                confidence=float(round(t.get("confidence", 0.5), 2)),
                verified=t.get("verified", True),
                evidence=t.get("evidence", []),
            ))
        return out

    if engine == ENGINE_HYBRID:
        dl_techs: List[Dict[str, Any]] = []
        rag_techs: List[Dict[str, Any]] = []

        try:
            from core import dl_classifier
            dl_techs = dl_classifier.predict_techniques(text, chunk_text=chunk_text)
        except Exception as dl_err:
            logger.warning("Hybrid: DL track unavailable: %s", dl_err)
            routing_decision["dl_error"] = f"deep_learning_unavailable: {dl_err}"

        _clear_mps_cache()

        if os.getenv("AUTOMITRE_USE_RAG", "1") == "1":
            try:
                from core.threat_pipeline import map_log_to_attack_techniques
                rag_techs = map_log_to_attack_techniques(text)
            except Exception as rag_err:
                logger.warning("Hybrid: RAG track unavailable: %s", rag_err)
                routing_decision["rag_error"] = f"rag_unavailable: {rag_err}"
        else:
            routing_decision["rag_error"] = "rag_disabled (AUTOMITRE_USE_RAG=0)"

        merged = _merge_technique_tracks(dl_techs, rag_techs)
        if merged:
            final_techniques_list = _to_attack_techniques(merged)
        else:
            routing_decision["note"] = "Both hybrid tracks returned no techniques; kept baseline list."
        routing_decision["engine_used"] = ENGINE_HYBRID
        routing_decision["track_counts"] = {
            "deep_learning": len(dl_techs),
            "rag": len(rag_techs),
            "merged": len(merged),
        }

    if engine == ENGINE_DEEP_LEARNING:
        try:
            from core import dl_classifier
            dl_techs = dl_classifier.predict_techniques(text, chunk_text=chunk_text)
            if dl_techs:
                final_techniques_list = _to_attack_techniques(dl_techs)
            else:
                routing_decision["note"] = "DL classifier accepted no techniques; kept baseline list."
            routing_decision["engine_used"] = ENGINE_DEEP_LEARNING
        except Exception as dl_err:
            logger.warning("DL classifier unavailable, falling back to RAG: %s", dl_err)
            routing_decision["fallback"] = f"deep_learning_unavailable: {dl_err}"
            engine = ENGINE_RAG

    if engine == ENGINE_RAG and os.getenv("AUTOMITRE_USE_RAG", "1") == "1":
        try:
            from core.threat_pipeline import map_log_to_attack_techniques
            rag_techs = map_log_to_attack_techniques(text)
            if rag_techs:
                final_techniques_list = _to_attack_techniques(rag_techs)
            routing_decision["engine_used"] = ENGINE_RAG
        except Exception as rag_err:
            logger.warning("RAG pipeline unavailable, retaining legacy techniques: %s", rag_err)
            routing_decision.setdefault("fallback", f"rag_unavailable: {rag_err}")
            routing_decision["engine_used"] = "legacy"

    # Map score to standard SeverityLevel
    mapped_severity = SeverityLevel.LOW
    if final_score >= 9.0: mapped_severity = SeverityLevel.CRITICAL
    elif final_score >= 7.0: mapped_severity = SeverityLevel.HIGH
    elif final_score >= 4.0: mapped_severity = SeverityLevel.MEDIUM

    # 6. Mitigation & Prediction Generation
    final_tids = [t.id for t in final_techniques_list]
    deterministic_steps = generate_predictive_actions(final_tids, text, entities)
    
    ai_steps_raw = deep_insights.get("predicted_steps", []) if deep_insights else []
    ai_steps = []
    next_id = len(deterministic_steps) + 1
    for step in ai_steps_raw:
        if isinstance(step, dict) and 'title' in step and 'description' in step:
            ai_steps.append(PredictedStep(
                id=next_id,
                title=step['title'],
                description=step['description'],
                confidence=float(step.get('confidence', 0.8))
            ))
            next_id += 1
            
    final_predicted_steps = deterministic_steps + ai_steps

    result = ThreatResult(
        id=str(uuid.uuid4()),
        title=deep_insights.get("title") if deep_insights and deep_insights.get("title") != "Threat Detected" else _get_threat_title(final_tids, entities),
        timestamp=datetime.now().isoformat(),
        input_type=processed_input.get('input_type', 'text'),
        description=deep_insights.get("analysis", text[:300]) if deep_insights else text[:300],
        risk_score=RiskScore(
            score=float(round(final_score, 1)),
            severity=mapped_severity,
            likelihood=float(likelihood) if not is_anomalous else 0.8,
            impact=float(impact),
            business_impact=generate_business_impact(mapped_severity, final_tids)
        ),
        attack_techniques=final_techniques_list,
        defend_countermeasures=map_to_defend(final_tids),
        nist_controls=map_to_nist(final_tids),
        owasp_items=map_to_owasp(final_tids),
        mitigations=get_mitigations(final_tids),
        predicted_steps=final_predicted_steps,
        entities=[(e if isinstance(e, ThreatEntity) else ThreatEntity(type=e.get('type', 'indicator'), value=e.get('value', ''))) for e in entities],
        raw_indicators={
            "technique_ids": final_tids,
            "is_anomaly": bool(is_anomalous),
            "deep_extraction": deep_insights.get("terms", []) if deep_insights else [],
            "technical_dive": deep_insights.get("analysis", "") if deep_insights else "",
            "llm_summary": deep_insights.get("summary", "") if deep_insights else "",
            "routing_decision": routing_decision
        }
    )
    return result
