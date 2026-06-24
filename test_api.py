import requests
import json
import sqlite3

# login to get token
login_data = {
    "username": "admin",
    "password": "Admin@1234!"
}
r = requests.post("http://127.0.0.1:8001/api/auth/login", data=login_data)
token = r.json().get("access_token")
print(token)

headers = {"Authorization": f"Bearer {token}"}
r2 = requests.get("http://127.0.0.1:8001/api/dashboard/stats?view=personal", headers=headers)
print(json.dumps(r2.json(), indent=2))
