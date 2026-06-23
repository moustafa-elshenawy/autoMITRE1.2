from typing import Dict, Any
from core.osint_client import fetch_all_osint

async def analyze_osint_pipeline(include_misp: bool = True) -> Dict[str, Any]:
    """
    Orchestrates the OSINT feed ingestion and deduplication.
    """
    return await fetch_all_osint(include_misp=include_misp)
