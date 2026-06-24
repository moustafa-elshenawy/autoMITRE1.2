import asyncio
from main import app
from fastapi.testclient import TestClient

client = TestClient(app)

response = client.post("/api/auth/login", data={"username": "admin", "password": "Admin@1234!"})
if response.status_code == 200:
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    res = client.get("/api/dashboard/stats?view=personal", headers=headers)
    print("STATS:")
    print(res.json())
    
    res2 = client.get("/api/dashboard/activity?view=personal", headers=headers)
    print("ACTIVITY:")
    print(res2.json())
else:
    print("Login failed:", response.text)
