"""Tests for the logger module."""

import sys
from pathlib import Path
import pytest


@pytest.fixture
def cleanup_logs():
    """Clean up test log files after each test."""
    yield
    # Clean up test log files
    log_dir = get_log_dir()
    for f in log_dir.glob("*.log*"):
        f.unlink()

from perihelion_auth_manager.audit.logger import get_log_dir


@pytest.fixture
def mock_home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


@pytest.mark.skipif(sys.platform == "win32",
                  reason="POSIX permissions not supported on Windows")
def test_get_log_dir_default(mock_home):
    """Test get_log_dir with default base_dir."""
    log_dir = get_log_dir()
    expected_path = mock_home / ".local" / "log"
    assert log_dir == expected_path.resolve()


def test_get_log_dir_custom_str():
    """Test get_log_dir with custom string path."""
    custom_path = "/test/custom/log"
    log_dir = get_log_dir(custom_path)
    assert log_dir == Path(custom_path).resolve()


def test_get_log_dir_custom_path():
    """Test get_log_dir with custom Path object."""
    custom_path = Path("/test/custom/log")
    log_dir = get_log_dir(custom_path)
    assert log_dir == custom_path.resolve()
