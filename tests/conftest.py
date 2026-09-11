"""
Shared test fixtures and configuration.
"""

import pytest
from fastapi.testclient import TestClient

from honeypot.main import app


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def mock_payload():
    """Sample LLM chat payload."""
    return {
        "model": "gpt-4-turbo",
        "messages": [{"role": "user", "content": "Hello"}],
        "temperature": 0.7,
    }


@pytest.fixture
def mock_auth_header():
    """Valid-looking API key header."""
    return "Bearer sk-abcdefghij1234567890"
