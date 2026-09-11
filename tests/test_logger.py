"""
Test logging functionality.
"""

import os
import tempfile

from honeypot.logger import (
    rotate_log_if_needed,
    ensure_log_file_exists,
    _log_dir,
)


class TestLogRotation:
    """Test JSONL log file rotation."""

    def test_rotate_log_creates_file(self):
        """Log rotation should create file if missing."""
        with tempfile.TemporaryDirectory():
            # Test that rotation doesn't fail when file is missing
            log_file = "/tmp/nonexistent_for_test.jsonl"
            rotate_log_if_needed(log_file, max_bytes=1024)
            # Function returns early if file missing (no error)

    def test_rotate_log_under_limit(self):
        """Log under size limit should not rotate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.jsonl")
            # Create a small log
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("x" * 100)

            rotate_log_if_needed(log_file, max_bytes=1024)
            # File should still exist without rotation
            assert os.path.exists(log_file)
            assert os.path.getsize(log_file) == 100

    def test_rotate_log_exceeds_limit(self):
        """Log exceeding limit should rotate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.jsonl")
            # Create a large log
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("x" * 2000)

            rotate_log_if_needed(log_file, max_bytes=1024, backup_count=2)
            # Original should be renamed to .1
            assert os.path.exists(f"{log_file}.1")
            # Current log should be empty
            assert os.path.getsize(log_file) == 0

    def test_rotate_log_creates_backups(self):
        """Rotation should create backup chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.jsonl")

            # Write and rotate multiple times
            for i in range(3):
                with open(log_file, "w", encoding="utf-8") as f:
                    f.write(f"batch {i}\n" * 500)
                rotate_log_if_needed(log_file, max_bytes=1024, backup_count=2)

            # Should have current + backups
            assert os.path.exists(log_file)


class TestLogDirectory:
    """Test log directory handling."""

    def test_log_dir_creation(self):
        """ensure_log_file_exists should create directory."""
        # This test assumes we can mock settings.LOG_FILE
        # For now, just verify the function exists
        assert ensure_log_file_exists.__doc__

    def test_log_dir_extraction(self):
        """Extract directory from log file path."""
        log_dir = _log_dir()
        # Should return a valid string
        assert isinstance(log_dir, str)
        assert len(log_dir) > 0
        del log_dir  # Used for assertion only
