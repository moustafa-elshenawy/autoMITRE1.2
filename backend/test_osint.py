import asyncio
from core.osint_client import fetch_all_osint

async def main():
    print("Fetching OSINT...")
    res = await fetch_all_osint()
    sources = {}
    for item in res.get("items", []):
        src = item["source"]
        sources[src] = sources.get(src, 0) + 1
    
    print("\nResults by Source:")
    for k, v in sources.items():
        print(f"{k}: {v}")
        
    print(f"\nTotal Items: {len(res.get('items', []))}")

asyncio.run(main())
