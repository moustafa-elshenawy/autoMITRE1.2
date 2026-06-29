import sys, asyncio
sys.path.append('backend')
from database.config import SessionLocal
from database.crud import get_recent_threats

async def run():
    async with SessionLocal() as db:
        t = await get_recent_threats(db, limit=100)
        for i, threat in enumerate(t):
            print(f"Threat {i}: Title: {threat.title} | Desc len: {len(threat.description)}")

asyncio.run(run())
