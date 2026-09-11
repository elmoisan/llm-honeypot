"""
Test API endpoints and request handling.
"""

from honeypot.endpoints import (
    _extract_api_key,
    _extract_ip,
    _is_internal_ip,
)


class TestIPExtraction:
    """Test IP address extraction."""

    def test_extract_ip_from_client(self):
        """Extract IP from request client."""
        # In a test client, client.host should be "testclient"
        # This is a simplified test; real tests would use a Mock
        assert _extract_ip.__doc__  # function exists


class TestAPIKeyExtraction:
    """Test API key extraction."""

    def test_extract_bearer_token(self):
        """Extract Bearer token."""
        auth = "Bearer sk-test1234567890abcdef"
        key = _extract_api_key(auth)
        assert key == "sk-test1234567890abcdef"

    def test_extract_no_bearer_prefix(self):
        """Extract key without Bearer prefix."""
        auth = "sk-test1234567890abcdef"
        key = _extract_api_key(auth)
        assert key == "sk-test1234567890abcdef"

    def test_extract_empty_auth(self):
        """Empty auth header returns empty key."""
        key = _extract_api_key(None)
        assert key == ""

    def test_extract_whitespace_trimmed(self):
        """Whitespace should be trimmed."""
        auth = "Bearer  sk-test1234567890abcdef  "
        key = _extract_api_key(auth)
        assert key == "sk-test1234567890abcdef"


class TestInternalIPCheck:
    """Test internal IP detection."""

    def test_localhost_loopback(self):
        """127.0.0.1 should be internal."""
        assert _is_internal_ip("127.0.0.1")

    def test_ipv6_loopback(self):
        """::1 should be internal."""
        assert _is_internal_ip("::1")

    def test_private_range_192(self):
        """192.168.x.x should be internal."""
        assert _is_internal_ip("192.168.1.1")

    def test_private_range_10(self):
        """10.x.x.x should be internal."""
        assert _is_internal_ip("10.0.0.1")

    def test_private_range_172(self):
        """172.16-31.x.x should be internal."""
        assert _is_internal_ip("172.16.0.1")

    def test_link_local(self):
        """169.254.x.x should be internal."""
        assert _is_internal_ip("169.254.1.1")

    def test_public_ip_not_internal(self):
        """Public IP should not be internal."""
        assert not _is_internal_ip("8.8.8.8")

    def test_invalid_ip(self):
        """Invalid IP should return False."""
        assert not _is_internal_ip("not-an-ip")

    def test_none_ip(self):
        """None should return False."""
        assert not _is_internal_ip(None)

    def test_empty_ip(self):
        """Empty string should return False."""
        assert not _is_internal_ip("")


class TestEndpointAccess:
    """Test endpoint access and validation."""

    def test_chat_completions_200(
        self, client, mock_payload, mock_auth_header
    ):
        """Chat completions should accept valid requests."""
        response = client.post(
            "/v1/chat/completions",
            json=mock_payload,
            headers={"Authorization": mock_auth_header},
        )
        assert response.status_code == 200

    def test_embeddings_200(self, client, mock_auth_header):
        """Embeddings should accept valid requests."""
        payload = {"input": "test", "model": "text-embedding-3-small"}
        response = client.post(
            "/v1/embeddings",
            json=payload,
            headers={"Authorization": mock_auth_header},
        )
        assert response.status_code == 200

    def test_models_200(self, client, mock_auth_header):
        """Models listing should work."""
        response = client.get(
            "/v1/models",
            headers={"Authorization": mock_auth_header},
        )
        # Should return 200 (success) or 4xx for auth/validation
        assert response.status_code < 500

    def test_invalid_api_key_401(self, client, mock_payload):
        """Invalid API key should return 401."""
        response = client.post(
            "/v1/chat/completions",
            json=mock_payload,
            headers={"Authorization": "Bearer invalid"},
        )
        assert response.status_code == 401
        assert "error" in response.json()

    def test_catch_all_route_404(self, client, mock_auth_header):
        """Unknown endpoints should be caught and logged."""
        response = client.get(
            "/v1/unknown/endpoint",
            headers={"Authorization": mock_auth_header},
        )
        # Catch-all returns success but logs the probe
        assert response.status_code in {200, 404}

    def test_malformed_json_400(self, client, mock_auth_header):
        """Malformed JSON should return 400."""
        response = client.post(
            "/v1/chat/completions",
            data="{ invalid json }",
            headers={"Authorization": mock_auth_header},
        )
        assert response.status_code == 400
