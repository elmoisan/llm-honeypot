"""
Test configuration validation and loading.
"""

import pytest

from honeypot.config import VALID_ENV_KEYS, settings, _as_bool, _as_int


class TestConfigValidation:
    """Test .env file validation."""

    def test_valid_env_keys(self):
        """Valid .env keys should pass."""
        expected_keys = {
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
        assert VALID_ENV_KEYS == expected_keys

    def test_settings_immutable(self):
        """Settings should be frozen (immutable)."""
        with pytest.raises(Exception):  # dataclass frozen raises
            settings.HOST = "127.0.0.1"

    def test_settings_defaults(self):
        """Settings should have sensible defaults."""
        assert settings.HOST == "0.0.0.0"
        assert settings.PORT == 8000
        assert settings.DEBUG is False
        assert settings.LOG_DIR == "logs"
        assert settings.RATE_LIMIT_PER_MINUTE == 60
        assert settings.LOG_MAX_BYTES == 5_000_000


class TestEnvironmentLoading:
    """Test environment variable loading."""

    def test_as_bool_true_variants(self):
        """Boolean conversion should handle variants."""
        assert _as_bool("1")
        assert _as_bool("true")
        assert _as_bool("True")
        assert _as_bool("TRUE")
        assert _as_bool("yes")
        assert _as_bool("on")

    def test_as_bool_false_variants(self):
        """False variants should convert to False."""
        assert not _as_bool("0")
        assert not _as_bool("false")
        assert not _as_bool("False")
        assert not _as_bool("no")
        assert not _as_bool("off")
        assert not _as_bool(None)

    def test_as_int_valid(self):
        """Integer conversion should work."""
        assert _as_int("100", 0) == 100
        assert _as_int("8000", 0) == 8000

    def test_as_int_invalid_fallback(self):
        """Invalid int should return default."""
        assert _as_int("not-a-number", 9000) == 9000
        assert _as_int(None, 8000) == 8000

    def test_as_int_minimum_bound(self):
        """Integer should respect minimum bound."""
        result = _as_int("-100", 1000, minimum=0)
        assert result == 0
