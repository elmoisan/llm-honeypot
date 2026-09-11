"""
main.py — Application entry point
Creates the FastAPI app, registers the routes, and starts the server.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from honeypot.config import settings
from honeypot.endpoints import router


# ─── Startup / shutdown events ───────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Runs once at startup and once at shutdown."""
    os.makedirs("logs", exist_ok=True)
    print("=" * 55)
    print("  🍯 LLM Honeypot — Active")
    print(f"  Listening on http://{settings.HOST}:{settings.PORT}")
    print(f"  Logs → {settings.LOG_FILE}")
    print("=" * 55)
    yield
    print("🛑 Honeypot shutting down.")


# ─── App creation ────────────────────────────────────────────────────────────

app = FastAPI(
    title="LLM Honeypot",
    version="0.1.0",
    # Hide the documentation endpoints in production so attackers cannot
    # enumerate the API surface.
    docs_url="/docs" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(
    _request: Request,
    exc: RequestValidationError,
):
    """Return a clean JSON payload for malformed requests."""
    return JSONResponse(
        status_code=400,
        content={
            "error": {
                "message": "Invalid request payload",
                "code": 400,
                "details": exc.errors(),
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    _request: Request, exc: StarletteHTTPException
):
    """Normalize HTTP exceptions to a JSON response."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"message": exc.detail, "code": exc.status_code}},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, exc: Exception):
    """Avoid exposing internal stack traces in production."""
    print(f"Unhandled application error: {type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": {"message": "Internal server error", "code": 500}},
    )


# Enable CORS only in development or when explicitly needed locally.
if settings.DEBUG:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Register all the fake LLM endpoints
app.include_router(router)


# ─── Run directly with: python -m honeypot.main ──────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "honeypot.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
