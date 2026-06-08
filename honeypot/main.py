"""
main.py — Application entry point
Creates the FastAPI app, registers the routes, and starts the server.
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

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
    # Hide the /docs page in production so we don't tip off attackers
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
    lifespan=lifespan,
)

# Allow cross-origin requests (needed if dashboard is on a different port)
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
