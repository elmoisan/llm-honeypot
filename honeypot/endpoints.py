"""
endpoints.py — Fake LLM API routes.
These routes mimic OpenAI's API structure to attract and study attackers.
Each request is analyzed and logged.
They are then answered with a convincing fake response.

"""

import json
import os
from ipaddress import ip_address
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from honeypot.config import settings
from honeypot.detection import analyze, check_rate_limit
from honeypot.logger import log_request
from honeypot.responses import (
    fake_auth_error,
    fake_chat_response,
    fake_context_too_long_error,
    fake_embeddings_response,
    fake_invalid_request_error,
    fake_model_not_found_error,
    fake_models_response,
    fake_rate_limit_error,
)

router = APIRouter()


def _is_internal_ip(ip_value: Optional[str]) -> bool:
    """Treat private/loopback addresses as internal-only."""
    if not ip_value:
        return False
    try:
        addr = ip_address(ip_value)
    except ValueError:
        return False
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or str(addr) in {"127.0.0.1", "::1"}
    )


def _is_internal_request(request: Request) -> bool:
    """Allow internal-only access to monitoring endpoints such as /api/logs."""
    host = request.headers.get("host", "")
    if host:
        host_name = host.split(":", 1)[0].lower()
        if (
            host_name in {"localhost", "127.0.0.1", "::1"}
            or host_name.startswith("localhost.")
        ):
            return True

    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        for ip_value in forwarded.split(","):
            candidate = ip_value.strip()
            if _is_internal_ip(candidate):
                return True

    client_ip = request.client.host if request.client else None
    return _is_internal_ip(client_ip)


def _extract_ip(request: Request) -> str:
    """
    Extract the real client IP.
    X-Forwarded-For is checked first (set by proxies like nginx).
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    # request.client can be None (e.g. in tests or Unix sockets)
    if request.client is None:
        return "unknown"
    return request.client.host or "unknown"


def _extract_api_key(authorization: Optional[str]) -> str:
    """Extract the raw API key from the Authorization header."""
    if not authorization:
        return ""
    # Authorization header format: "Bearer sk-xxxx"
    return authorization.replace("Bearer ", "").strip()


def _rate_limit_details(ip: str) -> bool:
    """Return whether the IP has exceeded the configured rate limit."""
    limited, _ = check_rate_limit(
        ip=ip,
        limit_per_minute=settings.RATE_LIMIT_PER_MINUTE,
    )
    return limited


def _build_error_response(
    payload: dict,
    api_key: str,
    result,
    model_name: str = "gpt-4-turbo",
):
    """Choose error response based on request pattern and threat level."""
    if not api_key or len(api_key) < 12 or not api_key.startswith("sk-"):
        return fake_auth_error(), 401

    is_rate_limited = (
        "rate_limit_abuse" in result.categories
        or "rate_limit" in result.categories
    )
    if is_rate_limited:
        return fake_rate_limit_error(), 429

    requested_model = str(
        payload.get("model", model_name) or model_name
    )
    not_found_models = {
        "not-found-model",
        "unknown-model",
        "gpt-5",
        "model-does-not-exist",
    }
    if requested_model in not_found_models:
        return fake_model_not_found_error(requested_model), 404

    is_context_issue = (
        "context_too_long" in result.categories
        or (
            "prompt_injection" in result.categories
            and len(str(payload)) > 3000
        )
    )
    if is_context_issue:
        return fake_context_too_long_error(), 413

    if not payload or not isinstance(payload, dict):
        return fake_invalid_request_error(), 400

    return None, None


def _response_status_for_error(error_type: str) -> int:
    """Map error types to the HTTP status they usually trigger."""
    return {
        "invalid_api_key": 401,
        "rate_limit": 429,
        "model_not_found": 404,
        "context_too_long": 413,
        "invalid_request": 400,
    }.get(error_type, 400)


# IMPORTANT: keep specific routes registered before the catch-all.
# This prevents the catch-all from swallowing internal monitoring endpoints.

# ─── POST /v1/chat/completions

@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    """
    The main target. Mimics OpenAI's chat completion endpoint.
    This is the most attacked LLM endpoint on the internet.
    """
    ip = _extract_ip(request)
    api_key = _extract_api_key(authorization)
    user_agent = request.headers.get("User-Agent", "unknown")

    try:
        payload = await request.json()
    except (ValueError, json.JSONDecodeError):
        payload = {}

    rate_limited = _rate_limit_details(ip)
    result = analyze(
        payload, api_key, ip=ip, rate_limit_triggered=rate_limited
    )
    if rate_limited and result.threat_level not in {"high", "critical"}:
        result.threat_level = "medium"

    await log_request(
        ip=ip,
        endpoint="/v1/chat/completions",
        method="POST",
        user_agent=user_agent,
        api_key_tried=api_key,
        payload=payload,
        threat_level=result.threat_level,
        categories=result.categories,
        detected_patterns=result.detected_patterns,
    )

    messages = payload.get("messages", [])
    model_name = str(payload.get("model", "gpt-4-turbo") or "gpt-4-turbo")
    error_response, status_code = _build_error_response(
        payload, api_key, result, model_name
    )
    if error_response is not None:
        return JSONResponse(error_response, status_code=status_code)

    return JSONResponse(fake_chat_response(messages, model=model_name))


# ─── POST /v1/embeddings

@router.post("/v1/embeddings")
async def embeddings(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    """Mimics OpenAI's embeddings endpoint."""
    ip = _extract_ip(request)
    api_key = _extract_api_key(authorization)
    user_agent = request.headers.get("User-Agent", "unknown")

    try:
        payload = await request.json()
    except (ValueError, json.JSONDecodeError):
        payload = {}

    rate_limited = _rate_limit_details(ip)
    result = analyze(
        payload, api_key, ip=ip, rate_limit_triggered=rate_limited
    )
    if rate_limited and result.threat_level not in {"high", "critical"}:
        result.threat_level = "medium"

    await log_request(
        ip=ip,
        endpoint="/v1/embeddings",
        method="POST",
        user_agent=user_agent,
        api_key_tried=api_key,
        payload=payload,
        threat_level=result.threat_level,
        categories=result.categories,
        detected_patterns=result.detected_patterns,
    )

    input_text = payload.get("input", "")
    error_response, status_code = _build_error_response(
        payload, api_key, result, "text-embedding-3-small"
    )
    if error_response is not None:
        return JSONResponse(error_response, status_code=status_code)

    return JSONResponse(fake_embeddings_response(input_text))


# ─── GET /v1/models
@router.get("/v1/models")
async def list_models(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    """
    Mimics OpenAI's model listing endpoint.
    Frequently probed by scanners doing recon.
    """
    ip = _extract_ip(request)
    api_key = _extract_api_key(authorization)
    user_agent = request.headers.get("User-Agent", "unknown")

    rate_limited = _rate_limit_details(ip)
    result = analyze({}, api_key, ip=ip, rate_limit_triggered=rate_limited)
    if rate_limited and result.threat_level not in {"high", "critical"}:
        result.threat_level = "medium"

    await log_request(
        ip=ip,
        endpoint="/v1/models",
        method="GET",
        user_agent=user_agent,
        api_key_tried=api_key,
        payload={},
        threat_level=result.threat_level,
        categories=result.categories,
        detected_patterns=result.detected_patterns,
    )

    error_response, status_code = _build_error_response(
        {}, api_key, result, "gpt-4-turbo"
    )
    if error_response is not None:
        return JSONResponse(error_response, status_code=status_code)

    return JSONResponse(fake_models_response())


# ─── GET /api/logs — internal monitoring feed
# This endpoint is intentionally not part of the public API surface.
# Keep it internal-only and hidden from OpenAPI docs.
@router.get("/api/logs", include_in_schema=False)
async def get_logs(request: Request, limit: int = 200):
    """Return recent attack logs. Internal-only."""
    if not _is_internal_request(request):
        return JSONResponse(
            {"error": {"message": "Forbidden", "code": 403}},
            status_code=403,
        )

    entries = []

    if os.path.exists(settings.LOG_FILE):
        with open(settings.LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    entries.reverse()
    return JSONResponse({"attacks": entries[:limit], "total": len(entries)})


# ─── Catch-all: log unknown endpoint probes
# Keep this last so it cannot swallow internal endpoints like /api/logs.
@router.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def catch_all(
    request: Request,
    full_path: str,
    authorization: Optional[str] = Header(default=None),
):
    """
    Catches any URL that gets probed beyond the known endpoints.
    Scanners try hundreds of paths — we log them all.
    """
    ip = _extract_ip(request)
    api_key = _extract_api_key(authorization)
    user_agent = request.headers.get("User-Agent", "unknown")

    try:
        payload = await request.json()
    except (ValueError, json.JSONDecodeError):
        payload = {}

    rate_limited = _rate_limit_details(ip)
    result = analyze(
        payload, api_key, ip=ip, rate_limit_triggered=rate_limited
    )
    if rate_limited and result.threat_level not in {"high", "critical"}:
        result.threat_level = "medium"

    await log_request(
        ip=ip,
        endpoint=f"/{full_path}",
        method=request.method,
        user_agent=user_agent,
        api_key_tried=api_key,
        payload=payload,
        threat_level=result.threat_level,
        categories=result.categories or ["recon"],
        detected_patterns=(result.detected_patterns or ["unknown endpoint"]),
    )

    return JSONResponse(
        {"error": {"message": "Not found", "code": 404}},
        status_code=404,
    )
