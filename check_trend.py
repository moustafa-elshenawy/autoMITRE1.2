import sqlite3
import datetime

conn = sqlite3.connect('backend/automitre.db')
c = conn.cursor()
c.execute("SELECT timestamp FROM threat_records")
threats = c.fetchall()

now = datetime.datetime.utcnow()
seven_days_ago = now - datetime.timedelta(days=7)
fourteen_days_ago = now - datetime.timedelta(days=14)

this_week_count = 0
last_week_count = 0

for (ts,) in threats:
    if ts:
        try:
            # Handle some formats having 'Z'
            if ts.endswith('Z'):
                ts = ts[:-1]
            t_date = datetime.datetime.fromisoformat(ts)
            if t_date >= seven_days_ago:
                this_week_count += 1
            elif t_date >= fourteen_days_ago:
                last_week_count += 1
        except Exception as e:
            print(f"Error parsing {ts}: {e}")

print(f"Total: {len(threats)}")
print(f"This week: {this_week_count}")
print(f"Last week: {last_week_count}")
if last_week_count > 0:
    trend = ((this_week_count - last_week_count) / last_week_count) * 100
elif this_week_count > 0:
    trend = 100
else:
    trend = 0
print(f"Trend: {trend}")

