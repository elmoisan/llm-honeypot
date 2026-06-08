"""Runtime configuration for the honeypot service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


def _as_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    LOG_DIR: str = "logs"
    LOG_FILE: str = "logs/attacks.jsonl"
    GEO_API: str = "http://ip-api.com/json/{ip}"


def _load_settings() -> Settings:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    debug = _as_bool(os.getenv("DEBUG"), default=False)
    log_dir = os.getenv("LOG_DIR", "logs")
    log_file = os.getenv("LOG_FILE", f"{log_dir}/attacks.jsonl")
    geo_api = os.getenv("GEO_API", "http://ip-api.com/json/{ip}")
    return Settings(
        HOST=host,
        PORT=port,
        DEBUG=debug,
        LOG_DIR=log_dir,
        LOG_FILE=log_file,
        GEO_API=geo_api,
    )


settings = _load_settings()
