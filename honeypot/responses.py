"""
responses.py — Fake but realistic API responses
The attacker thinks they're talking to a real LLM.
We return convincing responses to keep them engaged and logging.
"""

import random
import string
import time
from typing import Optional


def _fake_id(prefix: str = "chatcmpl") -> str:
    """Generate a realistic-looking random ID."""
    chars = string.ascii_letters + string.digits
    suffix = "".join(random.choices(chars, k=10))
    return f"{prefix}-{suffix}"


def _fake_usage(
    prompt: Optional[int] = None,
    completion: Optional[int] = None,
) -> dict:
    """Simulate realistic token usage numbers."""
    p = prompt or random.randint(20, 200)
    c = completion or random.randint(10, 80)
    return {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}


# ─── /v1/chat/completions ────────────────────────────────────────────────────

# Pool of vague, safe-looking responses to rotate through
_CHAT_RESPONSES = [
    "I'm sorry, I'm not able to help with that.",
    "That request falls outside my current capabilities.",
    "I don't have access to that information.",
    "I'm unable to process that request at this time.",
    "Sorry, that's not something I can assist with.",
    "I can't provide that information.",
]


def fake_chat_response(messages: list) -> dict:
    """Return a realistic OpenAI-style chat completion response."""
    return {
        "id":      _fake_id("chatcmpl"),
        "object":  "chat.completion",
        "created": int(time.time()),
        "model":   "gpt-4-turbo",
        "choices": [
            {
                "index":         0,
                "message": {
                    "role":    "assistant",
                    "content": random.choice(_CHAT_RESPONSES),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": _fake_usage(len(str(messages)) // 4),
    }


# ─── /v1/embeddings ──────────────────────────────────────────────────────────

def fake_embeddings_response(input_text) -> dict:
    """Return a realistic embeddings response with random float values."""
    # Real embeddings are 1536-dimension float vectors
    vector = [round(random.uniform(-1.0, 1.0), 8) for _ in range(1536)]
    texts = input_text if isinstance(input_text, list) else [input_text]

    return {
        "object": "list",
        "data": [
            {"object": "embedding", "index": i, "embedding": vector}
            for i, _ in enumerate(texts)
        ],
        "model": "text-embedding-3-small",
        "usage": {
            "prompt_tokens": len(str(texts)) // 4,
            "total_tokens": len(str(texts)) // 4,
        },
    }


# ─── /v1/models ──────────────────────────────────────────────────────────────

def fake_models_response() -> dict:
    """Return a realistic list of available models."""
    return {
        "object": "list",
        "data": [
            {
                "id": "gpt-4-turbo",
                "object": "model",
                "created": 1712361441,
                "owned_by": "openai",
            },
            {
                "id": "gpt-4o",
                "object": "model",
                "created": 1715367049,
                "owned_by": "openai",
            },
            {
                "id": "gpt-3.5-turbo",
                "object": "model",
                "created": 1677610602,
                "owned_by": "openai",
            },
            {
                "id": "text-embedding-3-small",
                "object": "model",
                "created": 1705948997,
                "owned_by": "openai",
            },
        ],
    }


# ─── Error responses ─────────────────────────────────────────────────────────

def fake_auth_error() -> dict:
    """Returned when the API key is missing or invalid."""
    return {
        "error": {
            "message": (
                "Incorrect API key provided. You can find your API key at "
                "https://platform.openai.com/account/api-keys."
            ),
            "type":    "invalid_request_error",
            "param":   None,
            "code":    "invalid_api_key",
        }
    }


def fake_rate_limit_error() -> dict:
    """Returned to simulate rate limiting (keeps attackers guessing)."""
    return {
        "error": {
            "message": (
                "Rate limit reached for gpt-4-turbo. "
                "Please try again in 20s."
            ),
            "type":    "rate_limit_error",
            "param":   None,
            "code":    "rate_limit_exceeded",
        }
    }
