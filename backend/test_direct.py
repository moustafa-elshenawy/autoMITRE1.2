import asyncio
from database.config import SessionLocal
from sqlalchemy import select
from database.models import User, ThreatRecord
import datetime

async def main():
    async with SessionLocal() as db:
        result = await db.execute(select(User).filter(User.username.ilike('%shno%')))
        user = result.scalars().first()
        if not user:
            print("User shno not found")
            return
            
        print(f"User found: {user.username} (ID: {user.id})")
        
        now = datetime.datetime.utcnow()
        seven = now - datetime.timedelta(days=7)
        fourteen = now - datetime.timedelta(days=14)
        
        threats_query = select(ThreatRecord).where(ThreatRecord.user_id == user.id, ThreatRecord.group_id == None)
        r2 = await db.execute(threats_query)
        threats = r2.scalars().all()
        
        print(f"Total threats for user: {len(threats)}")
        
        this_w = 0
        last_w = 0
        for t in threats:
            if t.timestamp:
                try:
                    ts_clean = t.timestamp.replace('Z', '+00:00') if t.timestamp.endswith('Z') else t.timestamp
                    t_date = datetime.datetime.fromisoformat(ts_clean).replace(tzinfo=None)
                    if t_date >= seven:
                        this_w += 1
                    elif t_date >= fourteen:
                        last_w += 1
                except Exception as e:
                    print(e)
                    pass
        print(f"This week: {this_w}, Last week: {last_w}")
        
        if last_w > 0:
            trend = ((this_w - last_w) / last_w) * 100
        elif this_w > 0:
            trend = 100
        else:
            trend = 0
            
        print(f"Trend: {trend}")
        
if __name__ == "__main__":
    asyncio.run(main())
