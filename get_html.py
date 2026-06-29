import sys, asyncio
sys.path.append('backend')
from database.config import SessionLocal
from database.crud import get_recent_threats
from jinja2 import Environment, FileSystemLoader
import os

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "backend", "templates")
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

async def run():
    async with SessionLocal() as db:
        t = await get_recent_threats(db, limit=100)
        
        real_threats = []
        for record in t:
            real_threats.append({
                "id": record.id,
                "title": record.title,
                "description": record.description,
                "timestamp": str(record.timestamp),
                "risk_score": {"score": record.risk_score, "severity": record.severity},
                "mitigations": [
                    {
                        "title": m.title, 
                        "description": m.description,
                        "priority": getattr(m, 'priority', 'Medium'),
                    }
                    for m in record.mitigations
                ]
            })
            
        template = env.get_template("executive.html")
        html_out = template.render(
            threats=real_threats,
            report_date="June 29, 2026",
            total_threats=len(real_threats)
        )
        with open("generated_test.html", "w") as f:
            f.write(html_out)

asyncio.run(run())
