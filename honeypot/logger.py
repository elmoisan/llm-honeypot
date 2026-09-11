"""
logger.py — Structured logging system
Every request is saved as a JSON line in the log file.
We also query a free API to geolocate each IP address.
"""

import json
import os
from datetime import datetime, timezone
from json import JSONDecodeError

import httpx

from honeypot.config import settings


def _log_dir() -> str:
    """Return the directory for the active log file, defaulting to the CWD."""
    return os.path.dirname(settings.LOG_FILE) or "."


def rotate_log_if_needed(
    log_path: str,
    max_bytes: int = 5_000_000,
    backup_count: int = 3,
):
    """Rotate the JSONL log file when it grows beyond the configured size."""
    if not os.path.exists(log_path):
        return

    if os.path.getsize(log_path) <= max_bytes:
        return

    for index in range(backup_count - 1, 0, -1):
        src = f"{log_path}.{index}"
        dst = f"{log_path}.{index + 1}"
        if os.path.exists(src):
            os.replace(src, dst)

    os.replace(log_path, f"{log_path}.1")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("")


def ensure_log_file_exists():
    """Create the log directory and file if they don't exist."""
    log_dir = _log_dir()
    os.makedirs(log_dir, exist_ok=True)
    if not os.path.exists(settings.LOG_FILE):
        with open(settings.LOG_FILE, "w", encoding="utf-8") as f:
            f.write("")
    rotate_log_if_needed(
        settings.LOG_FILE,
        settings.LOG_MAX_BYTES,
        settings.LOG_BACKUP_COUNT,
    )


async def geolocate_ip(ip: str) -> dict:
    """
    Query a geolocation service for geographic info about an IP address.
    It retries a few times and falls back to empty values if the lookup fails.
    """
    if ip in ("127.0.0.1", "::1", "testclient", "unknown"):
        return {
            "country": "Local",
            "country_code": "LO",
            "city": "localhost",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "local",
        }

    for _ in range(2):
        try:
            url = settings.GEO_API.format(ip=ip)
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.get(url)
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "??"),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "isp": data.get("isp", "Unknown"),
                    }
        except (httpx.HTTPError, JSONDecodeError, ValueError, TypeError):
            continue

    return {
        "country": "Unknown",
        "country_code": "??",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown",
    }


def _safe_console_summary(
    ip: str,
    country: str,
    endpoint: str,
    categories: list[str],
) -> str:
    """Keep console output concise without leaking raw metadata."""
    return f"{ip} ({country}) -> {endpoint} | {categories}"


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

    geo = await geolocate_ip(ip)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "country": geo["country"],
        "country_code": geo["country_code"],
        "city": geo["city"],
        "lat": geo["lat"],
        "lon": geo["lon"],
        "isp": geo["isp"],
        "endpoint": endpoint,
        "method": method,
        "user_agent": user_agent,
        "api_key_tried": api_key_tried,
        "threat_level": threat_level,
        "categories": categories,
        "detected_patterns": detected_patterns,
        "payload_size": len(json.dumps(payload)),
        "payload": payload,
    }

    with open(settings.LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    icon_map = {
        "low": "🟡",
        "medium": "🟠",
        "high": "🔴",
        "critical": "💀",
    }
    icon = icon_map.get(threat_level, "⚪")
    console_line = _safe_console_summary(
        ip,
        geo["country"],
        endpoint,
        categories,
    )
    print(f"{icon} [{entry['timestamp']}] {console_line}")
