import sqlite3
import datetime

conn = sqlite3.connect('backend/automitre.db')
c = conn.cursor()
c.execute("SELECT timestamp FROM threat_records")
threats = c.fetchall()

now = datetime.datetime.utcnow()
seven = now - datetime.timedelta(days=7)
fourteen = now - datetime.timedelta(days=14)

this_w = 0
last_w = 0
fails = 0

for (ts,) in threats:
    try:
        t_date = datetime.datetime.fromisoformat(ts)
        if t_date >= seven:
            this_w += 1
        elif t_date >= fourteen:
            last_w += 1
    except Exception as e:
        fails += 1

print(f"this: {this_w}, last: {last_w}, fails: {fails}")
if last_w > 0:
    trend = ((this_w - last_w) / last_w) * 100
elif this_w > 0:
    trend = 100
else:
    trend = 0
print(f"trend: {trend}")

