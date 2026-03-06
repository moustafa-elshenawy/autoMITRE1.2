import asyncio
import httpx
from core.osint_client import RUNTIME_CONFIG, OTX_BASE, OTX_API_KEY

async def main():
    key = RUNTIME_CONFIG.get("otx_api_key") or OTX_API_KEY
    limit = 500
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{OTX_BASE}/pulses/subscribed",
            headers={"X-OTX-API-KEY": key},
            params={"limit": limit},
            timeout=15.0,
        )
        data = resp.json()
        pulses = data.get("results", [])
        print(f"Requested {limit}, got {len(pulses)} pulses")
        if "next" in data:
            print(f"Has next page: {data['next']}")

asyncio.run(main())
