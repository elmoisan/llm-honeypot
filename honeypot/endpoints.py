"""
endpoints.py — Fake LLM API routes
These routes mimic OpenAI's API structure.
Each request is analyzed, logged, then answered with a fake response.
"""

from json import JSONDecodeError
from fastapi import APIRouter, Request, Header
from fastapi.responses import JSONResponse
from typing import Optional

from honeypot.detection import analyze
from honeypot.logger import log_request
from honeypot.responses import (
    fake_chat_response,
    fake_embeddings_response,
    fake_models_response,
)

router = APIRouter()


def _extract_ip(request: Request) -> str:
    """
    Extract the real client IP.
    X-Forwarded-For is checked first (used when behind a proxy/nginx).
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client is None:
        return "unknown"
    return request.client.host or "unknown"


def _extract_api_key(authorization: Optional[str]) -> str:
    """Extract the raw API key from the Authorization header."""
    if not authorization:
        return ""
    # Authorization header format: "Bearer sk-xxxx"
    return authorization.replace("Bearer ", "").strip()


# ─── POST /v1/chat/completions ───────────────────────────────────────────────

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

    # Parse the request body (or use empty dict if malformed)
    try:
        payload = await request.json()
    except (JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        payload = {}

    # Run detection on the payload
    result = analyze(payload, api_key)

    # Log everything
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

    # Return a convincing fake response
    messages = payload.get("messages", [])
    return JSONResponse(fake_chat_response(messages))


# ─── POST /v1/embeddings ─────────────────────────────────────────────────────

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
    except (JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        payload = {}

    result = analyze(payload, api_key)

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
    return JSONResponse(fake_embeddings_response(input_text))


# ─── GET /v1/models ──────────────────────────────────────────────────────────

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

    result = analyze({}, api_key)

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

    return JSONResponse(fake_models_response())


# ─── Catch-all: log unknown endpoint probes ──────────────────────────────────

@router.api_route(
    "/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
)
async def catch_all(
    request: Request,
    full_path: str,
    authorization: Optional[str] = Header(default=None),
):
    """
    Catch any other URL that gets probed.
    Scanners try hundreds of paths — we log them all.
    """
    ip = _extract_ip(request)
    api_key = _extract_api_key(authorization)
    user_agent = request.headers.get("User-Agent", "unknown")

    try:
        payload = await request.json()
    except (JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        payload = {}
    analyze(payload, api_key)

    await log_request(
        ip=ip,
        endpoint=f"/{full_path}",
        method=request.method,
        user_agent=user_agent,
        api_key_tried=api_key,
        payload=payload,
        threat_level="low",
        categories=["recon"],
        detected_patterns=["unknown endpoint probe"],
    )

    return JSONResponse(
        {"error": {"message": "Not found", "code": 404}},
        status_code=404,
    )
