"""Runtime configuration for the honeypot service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


VALID_ENV_KEYS = {
    "HOST",
    "PORT",
    "DEBUG",
    "LOG_DIR",
    "LOG_FILE",
    "GEO_API",
    "RATE_LIMIT_PER_MINUTE",
    "LOG_MAX_BYTES",
    "LOG_BACKUP_COUNT",
}


# Load environment variables from a local .env file when present.
load_dotenv()


def _validate_dotenv_file() -> None:
    """Guard against undocumented or stale variables in the project .env."""
    dotenv_path = Path(".env")
    if not dotenv_path.exists():
        return

    with dotenv_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key = line.split("=", 1)[0].strip()
            if key and key not in VALID_ENV_KEYS:
                raise RuntimeError(
                    f"Unsupported .env variable '{key}' on line "
                    f"{line_number}. Allowed keys: "
                    f"{', '.join(sorted(VALID_ENV_KEYS))}"
                )


_validate_dotenv_file()


def _as_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: Optional[str], default: int, minimum: int = 0) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, parsed)


@dataclass(frozen=True)
class Settings:  # pylint: disable=too-few-public-methods
    """Configuration settings loaded from environment variables."""
    # pylint: disable=invalid-name
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    LOG_DIR: str = "logs"
    LOG_FILE: str = "logs/attacks.jsonl"
    GEO_API: str = "http://ip-api.com/json/{ip}"
    RATE_LIMIT_PER_MINUTE: int = 60
    LOG_MAX_BYTES: int = 5_000_000
    LOG_BACKUP_COUNT: int = 3


def _load_settings() -> Settings:
    host = os.getenv("HOST", "0.0.0.0")
    port = _as_int(os.getenv("PORT"), 8000, minimum=1)
    debug = _as_bool(os.getenv("DEBUG"), default=False)
    log_dir = os.getenv("LOG_DIR", "logs")
    log_file = os.getenv("LOG_FILE", os.path.join(log_dir, "attacks.jsonl"))
    geo_api = os.getenv("GEO_API", "http://ip-api.com/json/{ip}")
    rate_limit = _as_int(os.getenv("RATE_LIMIT_PER_MINUTE"), 60, minimum=1)
    log_max_bytes = _as_int(
        os.getenv("LOG_MAX_BYTES"),
        5_000_000,
        minimum=1_000,
    )
    log_backup_count = _as_int(
        os.getenv("LOG_BACKUP_COUNT"),
        3,
        minimum=1,
    )
    return Settings(
        HOST=host,
        PORT=port,
        DEBUG=debug,
        LOG_DIR=log_dir,
        LOG_FILE=log_file,
        GEO_API=geo_api,
        RATE_LIMIT_PER_MINUTE=rate_limit,
        LOG_MAX_BYTES=log_max_bytes,
        LOG_BACKUP_COUNT=log_backup_count,
    )


settings = _load_settings()
