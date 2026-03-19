import httpx
import sys

API_URL = "http://localhost:8000"

def test_extraction():
    # 1. Register or Login to get Token
    auth_data = {
        "username": "testuser",
        "password": "testpassword123"
    }
    
    # Try login first
    r = httpx.post(f"{API_URL}/api/auth/token", data=auth_data)
    
    if r.status_code != 200:
        # Try register
        reg_data = {
            "email": "test@example.com",
            "username": "testuser",
            "full_name": "Test User",
            "password": "testpassword123"
        }
        print("Registering new user...")
        httpx.post(f"{API_URL}/api/auth/register", json=reg_data)
        r = httpx.post(f"{API_URL}/api/auth/token", data=auth_data)
        
    if r.status_code != 200:
        print(f"Auth failed: {r.text}")
        return
        
    token = r.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Hit the extraction endpoint
    print("Uploading file to extraction endpoint...")
    with open("test_sqli.pcap", "rb") as f:
        files = {"file": ("test_sqli.pcap", f, "application/vnd.tcpdump.pcap")}
        r = httpx.post(
            f"{API_URL}/api/analyze/extract-attacks",
            headers=headers,
            files=files,
            timeout=120.0
        )
        
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text}")

if __name__ == "__main__":
    test_extraction()
