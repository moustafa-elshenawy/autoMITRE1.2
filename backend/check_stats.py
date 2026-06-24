import asyncio
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from database.config import async_session
from sqlalchemy import select
from database.models import ThreatRecord, ThreatTechnique
import datetime

async def main():
    async with async_session() as db:
        result = await db.execute(select(ThreatRecord))
        threats = result.scalars().all()
        
        now = datetime.datetime.utcnow()
        seven_days_ago = now - datetime.timedelta(days=7)
        fourteen_days_ago = now - datetime.timedelta(days=14)
        
        this_week_count = 0
        last_week_count = 0
        
        for t in threats:
            if t.timestamp:
                try:
                    t_date = datetime.datetime.fromisoformat(t.timestamp)
                    if t_date >= seven_days_ago:
                        this_week_count += 1
                    elif t_date >= fourteen_days_ago:
                        last_week_count += 1
                except Exception as e:
                    pass
                    
        print(f"Total: {len(threats)}")
        print(f"This week: {this_week_count}, Last week: {last_week_count}")
        if last_week_count > 0:
            trend = ((this_week_count - last_week_count) / last_week_count) * 100
        elif this_week_count > 0:
            trend = 100
        else:
            trend = 0
        print(f"Trend: {round(trend)}")

if __name__ == "__main__":
    asyncio.run(main())
