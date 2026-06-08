"""
logger.py — Structured logging system
Every request is saved as a JSON line in the log file.
We also query a free API to geolocate each IP address.
"""

import json
import os
import httpx
from json import JSONDecodeError
from datetime import datetime, timezone
from honeypot.config import settings


def ensure_log_file_exists():
    """Create the log directory and file if they don't exist."""
    os.makedirs(os.path.dirname(settings.LOG_FILE), exist_ok=True)
    if not os.path.exists(settings.LOG_FILE):
        open(settings.LOG_FILE, "w", encoding="utf-8").close()


async def geolocate_ip(ip: str) -> dict:
    """
    Query ip-api.com to get geographic info about an IP address.
    Returns a dict with country, city, lat/lon, ISP.
    Falls back to empty values if the request fails.
    """
    # Don't geolocate localhost (used during development)
    if ip in ("127.0.0.1", "::1", "testclient"):
        return {
            "country": "Local",
            "country_code": "LO",
            "city": "localhost",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "local",
        }

    try:
        url = settings.GEO_API.format(ip=ip)
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(url)
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country":      data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "??"),
                    "city":         data.get("city", "Unknown"),
                    "lat":          data.get("lat", 0.0),
                    "lon":          data.get("lon", 0.0),
                    "isp":          data.get("isp", "Unknown"),
                }
    except (httpx.HTTPError, JSONDecodeError, ValueError, TypeError):
        pass  # Never crash because of a failed geo lookup

    return {
        "country": "Unknown",
        "country_code": "??",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown",
    }


async def log_request(
    ip: str,
    endpoint: str,
    method: str,
    user_agent: str,
    api_key_tried: str,
    payload: dict,
    threat_level: str,
    categories: list[str],
    detected_patterns: list[str],
):
    """
    Build a structured log entry and append it to the JSONL log file.
    Each line in the file is a valid, self-contained JSON object.
    """
    ensure_log_file_exists()

    # Get geographic info for this IP
    geo = await geolocate_ip(ip)

    # Build the full log entry
    entry = {
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "ip":                 ip,
        "country":            geo["country"],
        "country_code":       geo["country_code"],
        "city":               geo["city"],
        "lat":                geo["lat"],
        "lon":                geo["lon"],
        "isp":                geo["isp"],
        "endpoint":           endpoint,
        "method":             method,
        "user_agent":         user_agent,
        "api_key_tried":      api_key_tried,
        "threat_level":       threat_level,
        "categories":         categories,
        "detected_patterns":  detected_patterns,
        "payload_size":       len(json.dumps(payload)),
        "payload":            payload,
    }

    # Append to JSONL file (one JSON object per line)
    with open(settings.LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    # Also print to console so we can see attacks in real time
    icon_map = {
        "low": "🟡",
        "medium": "🟠",
        "high": "🔴",
        "critical": "💀",
    }
    icon = icon_map.get(threat_level, "⚪")
    print(
        f"{icon} [{entry['timestamp']}] {ip} "
        f"({geo['country']}) -> {endpoint} | {categories}"
    )
