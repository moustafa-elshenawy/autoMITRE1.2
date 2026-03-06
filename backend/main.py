"""
autoMITRE — Main FastAPI Application
Autonomous AI-Driven Cyber Threat Intelligence Platform
"""
from dotenv import load_dotenv
load_dotenv()  # Load .env before any other imports read os.environ

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes.analysis import router as analysis_router
from api.routes.export import router as export_router
from api.routes.intelligence import router as intelligence_router
from api.routes.auth import router as auth_router
from api.routes.users import router as users_router
from api.routes.settings import router as settings_router
from database.config import engine, Base
import contextlib

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables on startup if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(
    title="autoMITRE API",
    description="AI-Driven Cyber Threat Intelligence Platform with MITRE ATT&CK, D3FEND, NIST SP 800-53, and OWASP mapping",
    version="1.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(settings_router)
app.include_router(analysis_router)
app.include_router(export_router)
app.include_router(intelligence_router)

# ── Custom V2 AI Engine Integration ──
try:
    from core.custom_ai.automitre_api import AutoMITREAnalyzer
    from pydantic import BaseModel
    from typing import Optional, Dict, Any
    
    analyzer = AutoMITREAnalyzer()
    
    class AnalysisRequest(BaseModel):
        type: str  # text | log | pcap | prediction | hash | json_report
        content: Optional[str] = None
        features: Optional[Dict[str, Any]] = None
        
    @app.post("/api/v2/analyze")
    async def analyze_v2(request: AnalysisRequest):
        res = analyzer.analyze(request.dict())
        
        # Map V2 output to Frontend expected structure
        if "analysis" in res and "error" not in res.get("analysis", {}):
            a = res["analysis"]
            
            # Extract framework mappings specifically formatted for the React tabs
            attack = []
            attck_id = None
            tech_name = "Classified Technique"
            mitigations = []
            
            if "framework_mappings" in a and "mitre_attck" in a["framework_mappings"]:
                m = a["framework_mappings"]["mitre_attck"]
                attck_id = m.get("technique_id", "Unknown")
                
                # Retrieve genuine names and mitigations natively
                try:
                    from core.ai_threat_analyzer import get_attack_techniques, get_mitigations
                    if attck_id and attck_id != "Unknown":
                        db_techs = get_attack_techniques({attck_id: 1.0}, a.get('threat_category', 'Unknown'))
                        if db_techs:
                            tech_name = db_techs[0].name
                        
                        m_objs = get_mitigations([attck_id])
                        if m_objs:
                            mitigations = [
                                {
                                    "title": m_item.title, 
                                    "priority": m_item.priority, 
                                    "effort": m_item.effort, 
                                    "description": m_item.description
                                } for m_item in m_objs
                            ]
                except Exception as e:
                    pass

                attack.append({
                    "id": attck_id,
                    "name": tech_name,
                    "tactic": m.get("tactic", "Unknown"),
                    "confidence": a.get("confidence", 0)
                })
                
            defend = []
            if "framework_mappings" in a and "mitre_d3fend" in a["framework_mappings"]:
                defend.append({
                    "id": a["framework_mappings"]["mitre_d3fend"].split(":")[0],
                    "name": a["framework_mappings"]["mitre_d3fend"],
                    "category": "Defensive",
                    "description": "Suggested countermeasure based on threat profile."
                })
                
            nist = []
            if "framework_mappings" in a and "nist_800_53" in a["framework_mappings"]:
                nist.append({
                    "id": a["framework_mappings"]["nist_800_53"],
                    "name": "NIST Control",
                    "family": a["framework_mappings"]["nist_800_53"].split("-")[0] if "-" in a["framework_mappings"]["nist_800_53"] else "General",
                    "description": "Mapped security control required to mitigate threat."
                })
                
            owasp = []
            if "framework_mappings" in a and "owasp_asvs" in a["framework_mappings"]:
                owasp.append({
                    "id": a["framework_mappings"]["owasp_asvs"],
                    "name": "Verification Requirement",
                    "type": "Application Security",
                    "description": "ASVS standard for secure software development."
                })
                
            entities = []
            if a.get("top_categories"):
                for cat in a["top_categories"]:
                    entities.append({"type": "category", "value": f"{cat['category']} ({int(cat['probability']*100)}%)"})

            # Fallback if no specific mitigations found visually
            if not mitigations:
                mitigations = [
                    {"title": "Review AI Classification", "priority": "High", "effort": "Low", "description": "Review the custom ML pipeline output to confirm malicious behavior."}
                ]

            # Build standardized final response
            threat_result = {
                "title": f"Custom AI Analysis: {a.get('threat_category', 'Threat Detected')}",
                "description": f"Ensemble AI classified this event with {a.get('confidence', 0)*100:.1f}% confidence. Top category: {a.get('threat_category', 'Unknown')}.",
                "risk_score": {
                    "score": 9.5 if a.get("severity") == "Critical" else 7.5 if a.get("severity") == "High" else 5.0 if a.get("severity") == "Medium" else 2.5,
                    "severity": a.get("severity", "Medium"),
                    "business_impact": "Requires immediate review based on AI prediction." if a.get("severity") in ["High", "Critical"] else "Monitor for escalation."
                },
                "entities": entities,
                "attack_techniques": attack,
                "defend_countermeasures": defend,
                "nist_controls": nist,
                "owasp_items": owasp,
                "mitigations": mitigations
            }
            return {"success": True, "threat_result": threat_result}
        else:
            return {"success": False, "error": res.get("analysis", {}).get("error", "Unknown ML error")}
            
    @app.post("/api/v2/analyze/text")
    async def analyze_text_v2(text: str):
        # We wrap the direct string call in our AnalysisRequest object so it hits the mapping logic
        req = AnalysisRequest(type="text", content=text)
        return await analyze_v2(req)
        
    @app.post("/api/v2/analyze/pcap")
    async def analyze_pcap_v2(features: Dict[str, float]):
        return analyzer.analyze_pcap_features(features)
        
    @app.post("/api/v2/export/stix")
    async def export_stix_v2(request: AnalysisRequest):
        res = analyzer.analyze(request.dict())
        return analyzer.export_stix(res)
        
except Exception as e:
    import logging
    logging.error(f"Failed to load Custom V2 Analyzer: {e}")



@app.get("/")
async def root():
    return {
        "name": "autoMITRE",
        "version": "1.2.0",
        "description": "AI-Driven Cyber Threat Intelligence Platform",
        "docs": "/docs",
        "status": "operational"
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "autoMITRE API"}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": str(exc), "detail": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
