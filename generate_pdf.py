import sys
import asyncio
sys.path.append('/Users/shno/Desktop/autoMITRE1.2/backend')
from database.config import SessionLocal
from database.crud import get_recent_threats
from core.pdf_generator import generate_pdf_report

async def generate():
    async with SessionLocal() as db:
        db_threats = await get_recent_threats(db, limit=100)
        
        real_threats = []
        for record in db_threats:
            real_threats.append({
                "id": record.id,
                "title": record.title,
                "description": record.description,
                "timestamp": str(record.timestamp),
                "confidence": 100,
                "risk_score": {"score": record.risk_score, "severity": record.severity},
                "attack_techniques": [
                    {"id": t.technique_id, "name": t.name, "tactic": t.tactic, "description": t.description}
                    for t in record.techniques
                ],
                "mitigations": [
                    {
                        "title": m.title, 
                        "description": m.description,
                        "priority": getattr(m, 'priority', 'Medium'),
                        "iac_snippet": getattr(m, 'iac_snippet', ''),
                        "iac_type": getattr(m, 'iac_type', '')
                    }
                    for m in record.mitigations
                ],
                "defend_countermeasures": record.defend_json if getattr(record, 'defend_json', None) else [],
                "nist_controls": record.nist_json if getattr(record, 'nist_json', None) else [],
                "owasp_items": record.owasp_json if getattr(record, 'owasp_json', None) else []
            })
            
        pdf_bytes = generate_pdf_report(real_threats, "executive")
        out_path = "/Users/shno/Desktop/autoMITRE_Executive_Report_Generated.pdf"
        with open(out_path, "wb") as f:
            f.write(pdf_bytes.getvalue())
        print("Done!", out_path)

asyncio.run(generate())
