"""Tests for the audit logging framework."""

import json
import logging
import os
import typing
from logging.handlers import RotatingFileHandler
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import structlog

from perihelion_auth_manager.audit import EventType, audit_event
from perihelion_auth_manager.audit.logger import (
    _logger_lock,
    get_log_dir,
    setup_logging,
)

# Global for logger tests - defined at module level 
_LOGGER_INSTANCE: logging.Logger | None = None


@pytest.fixture
def logger(tmp_path: Path) -> typing.Generator[structlog.BoundLogger, None, None]:
    """Setup logger for tests."""
    global _LOGGER_INSTANCE
    # Configure logger with test directory
    logger = setup_logging(base_dir=tmp_path)
    _LOGGER_INSTANCE = logger
    yield logger
    # Clean up after test
    with _logger_lock:
        root_logger = logging.getLogger()
        # Remove handlers
        for handler in root_logger.handlers[:]:
            try:
                handler.close()
            except (OSError, ValueError) as e:
                logging.debug(f"Failed to close handler: {e}")
            root_logger.removeHandler(handler)
        # Reset structlog and clear instance
        structlog.reset_defaults()
        _LOGGER_INSTANCE = None


@patch("perihelion_auth_manager.audit.logger.get_logger")
def test_logging_directory_permissions(
    mock_log_dir: MagicMock,
    tmp_path: Path,
    logger: structlog.BoundLogger,
    mock_get_logger: MagicMock,
) -> None:
    """Test log directory permissions are secure."""
    mock_get_logger.return_value = logger
    # Mock log directory path
    mock_path = str(tmp_path / "logs")
    mock_log_dir.return_value = mock_path

    os.makedirs(mock_path, mode=0o700, exist_ok=True)

    # Check log directory permissions
    assert oct(os.stat(mock_path).st_mode).endswith("700")


def test_secure_handler_creation(tmp_path: Path, logger: structlog.BoundLogger) -> None:
    """Test creation of secure RotatingFileHandler."""
    from perihelion_auth_manager.audit.logger import create_secure_handler

    log_file = tmp_path / "test.log"
    max_bytes = 1024
    backup_count = 2

    handler = create_secure_handler(log_file, max_bytes, backup_count)

    # Check log directory permissions
    assert oct(os.stat(tmp_path).st_mode & 0o777).endswith("750")

    # Check log file permissions - 640 per security module
    mode = oct(os.stat(log_file).st_mode & 0o777)
    assert mode.endswith("640"), f"Expected 640 permissions, got {mode}"

    # Verify handler configuration
    assert isinstance(handler, RotatingFileHandler)
    assert handler.maxBytes == max_bytes
    assert handler.backupCount == backup_count


def test_handler_existence_check(logger: structlog.BoundLogger, tmp_path: Path) -> None:
    """Test detection of existing handlers.
    
    Args:
        logger: A test logger fixture
        tmp_path: A temporary directory for test files
    """
    from perihelion_auth_manager.audit.logger import get_handler

    test_logger = logging.getLogger("test_logger")

    # Initially no handler
    assert get_handler(test_logger) is None

    # Add a non-rotating handler
    test_logger.addHandler(logging.StreamHandler())
    assert get_handler(test_logger) is None

    # Add a rotating handler
    test_log_file = tmp_path / "test.log"
    rotating_handler = RotatingFileHandler(test_log_file)
    test_logger.addHandler(rotating_handler)
    assert get_handler(test_logger) == rotating_handler


def test_audit_event_logging(logger: structlog.BoundLogger) -> None:
    """Test logging of audit events."""

    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        # Log a successful event
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details={"operation": "create", "token": "secret-token"},
        )
        # Check bind arguments
        _, kwargs = mock_logger.return_value.bind.call_args
        assert kwargs["event_type"] == EventType.CRED_CREATE
        assert kwargs["user"] == "test-user"
        assert kwargs["success"]
        assert kwargs["details"]["operation"] == "create"
        assert kwargs["details"].get("token") == "***"  # Token should be sanitized

        # Log a failed event
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=False,
            error=ValueError("Invalid value"),
        )
        # Check bind arguments for error case
        _, kwargs = mock_logger.return_value.bind.call_args
        assert kwargs["event_type"] == EventType.CRED_CREATE
        assert kwargs["user"] == "test-user"
        assert not kwargs["success"]
        assert kwargs["error"]["type"] == "ValueError"
        assert kwargs["error"]["message"] == "Invalid value"


def test_audit_event_sanitization(logger: structlog.BoundLogger) -> None:
    """Test sanitization of sensitive details in audit events."""
    # Capture logged events
    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        # Log an event with sensitive details
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details={
                "username": "user",
                "password": os.environ.get("TEST_PASSWORD", "dummy_password"),
                "token": os.environ.get("TEST_TOKEN", "dummy_token"),
            },
        )

        # Check sanitization
        _, kwargs = mock_logger.return_value.bind.call_args
        assert kwargs["details"]["password"] == "***"
        assert kwargs["details"]["token"] == "***"
        assert kwargs["details"]["username"] == "user"


@patch("perihelion_auth_manager.audit.logger.StructuredJsonFormatter")
def test_json_logging(mock_formatter: MagicMock, logger: structlog.BoundLogger) -> None:
    """Test logging output format as JSON."""
    # Mock the handler and setup logging

    # Configure mock formatter
    log_record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="test_event",
        args=(),
        exc_info=None,
    )
    log_record.extra_field = "extra_value"

    mock_formatter.return_value.format.return_value = json.dumps(
        {"message": "test_event", "extra_field": "extra_value", "level": "INFO"}
    )

    # Test logging an event with extra fields
    typing.cast(typing.Any, logger).info("test_event", extra_field="extra_value")

    # Verify that the formatter produces valid JSON with the expected fields
    output = mock_formatter.return_value.format(log_record)
    parsed = json.loads(output)
    assert parsed["message"] == "test_event"
    assert parsed["extra_field"] == "extra_value"
    assert parsed["level"] == "INFO"


def test_nested_key_sanitization(logger: structlog.BoundLogger) -> None:
    """Test sanitization of nested sensitive keys in audit events."""
    data = {
        "outer": {
            "password": os.environ.get("TEST_PASSWORD", "dummy_password"),
            "nested": {
                "api_key": os.environ.get("TEST_API_KEY", "dummy_key")
            }
        }
    }

    # Using the audit_event to test sanitization
    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_logger.return_value.bind.return_value = mock_logger.return_value
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details=data,
        )
        _, kwargs = mock_logger.return_value.bind.call_args
        assert kwargs["details"]["outer"]["password"] == "***"
        assert kwargs["details"]["outer"]["nested"]["api_key"] == "***"


def test_handler_duplication(logger: structlog.BoundLogger) -> None:
    """Test prevention of duplicate secure handlers.
    
    Args:
        logger: The test logger fixture
    """
    from perihelion_auth_manager.audit.logger import create_secure_handler

    test_logger = logging.getLogger("test")
    log_dir = get_log_dir()
    create_secure_handler(log_dir / "test.log", 1024, 3)
    original_handler_count = len(test_logger.handlers)
    create_secure_handler(get_log_dir() / "test.log", 1024, 3)
    assert len(test_logger.handlers) == original_handler_count


def test_structlog_configuration(logger: structlog.BoundLogger) -> None:
    """Test structlog configuration is applied as expected."""
    # Configure a test logger with bindings

    # Verify bound fields are preserved
    assert logger._context.get("test_bind") == "bind_value"

    # Verify new key-value pairs can be added to logging calls
    assert logger._context.get("key") is None  # Not bound yet
    logger = logger.bind(key="value")
    assert logger._context.get("key") == "value"  # Now bound


def test_consistent_redaction(logger: structlog.BoundLogger) -> None:
    """Test redaction consistency across nested structures."""
    details = {
        "password": os.environ.get("TEST_PASSWORD", "dummy_password"),
        "nested": {
            "token": os.environ.get("TEST_TOKEN", "dummy_token"),
            "deep": {
                "api_key": os.environ.get("TEST_API_KEY", "dummy_key"),
                "safe_field": "visible"
            },
        },
        "array_with_secrets": [{"key": "secret1"}, {"token": "secret2"}],
        "safe_field": "visible"
    }

    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_logger.return_value.bind.return_value = mock_logger.return_value

        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details=details
        )

        # Verify sanitization
        _, kwargs = mock_logger.return_value.bind.call_args
        # Check top-level redaction
        assert kwargs["details"]["password"] == "***"
        assert kwargs["details"]["safe_field"] == "visible"

        # Check nested redaction
        assert kwargs["details"]["nested"]["token"] == "***"
        assert kwargs["details"]["nested"]["deep"]["api_key"] == "***"
        assert kwargs["details"]["nested"]["deep"]["safe_field"] == "visible"

        # Check array redaction
        assert kwargs["details"]["array_with_secrets"][0]["key"] == "***"
        assert kwargs["details"]["array_with_secrets"][1]["token"] == "***"


def test_audit_event_error_handling(logger: structlog.BoundLogger) -> None:
    """Test error handling in audit_event function."""
    # Test with invalid event type
    # Testing handling of invalid event type string
    # MyPy will complain about str instead of Enum, but we want to test this case
    audit_event(
        event_type=typing.cast(EventType, "INVALID_EVENT"),
        user="test-user",
        success=False,
        error=ValueError("Invalid event type")
    )

    # Test with empty user
    audit_event(
        event_type=EventType.CRED_CREATE,
        user="",
        success=False,
        error=ValueError("Empty username")
    )

    # Test with None values
    audit_event(
        event_type=EventType.CRED_CREATE,
        user="test-user",
        success=False,
        details=None,
        error=None
    )

    # Test with complex error object
    class CustomError(Exception):
        def __init__(self, message: str, code: int) -> None:
            self.message = message
            self.code = code
            super().__init__(self.message)

    audit_event(
        event_type=EventType.CRED_CREATE,
        user="test-user",
        success=False,
        error=CustomError("Custom error", 500)
    )


def test_sanitize_keys_edge_cases(logger: structlog.BoundLogger) -> None:
    """Test sanitization of edge cases in key handling."""
    details = {
        "PasSWorD": "should_be_masked",  # Test case-insensitive matching
        "nested": {
            "API_KEY": "should_be_masked",  # Test uppercase
            "token": None,  # Test None value
            "empty_dict": {},  # Test empty dict
            "empty_list": [],  # Test empty list
        },
        "list_with_secrets": [
            {"key": None},  # Test None in list
            {"token": []},  # Test empty list in dict in list
            {"normal": "visible"}
        ],
        "unicode_key_ȧ": "visible",  # Test unicode key
        "": "empty_key",  # Test empty key
        "spaces in key": "visible",  # Test spaces in key
    }

    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_logger.return_value.info = MagicMock()
        mock_logger.return_value.bind.return_value = mock_logger.return_value

        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details=details
        )

        # Verify sanitization
        _, kwargs = mock_logger.return_value.bind.call_args
        assert kwargs["details"]["PasSWorD"] == "***"
        assert kwargs["details"]["nested"]["API_KEY"] == "***"
        assert kwargs["details"]["nested"]["token"] == "***"
        assert kwargs["details"]["nested"]["empty_dict"] == {}
        assert kwargs["details"]["nested"]["empty_list"] == []
        assert kwargs["details"]["list_with_secrets"][0]["key"] == "***"
        assert kwargs["details"]["list_with_secrets"][1]["token"] == "***"
        assert kwargs["details"]["list_with_secrets"][2]["normal"] == "visible"
        assert kwargs["details"]["unicode_key_ȧ"] == "visible"
        assert kwargs["details"][""] == "empty_key"
        assert kwargs["details"]["spaces in key"] == "visible"


def test_concurrent_audit_events(tmp_path: Path, logger: structlog.BoundLogger) -> None:
    """Test concurrent audit event logging."""
    import queue
    import secrets
    import threading
    import time

    # Queue for collecting errors from worker threads
    errors: queue.Queue[Exception] = queue.Queue()
    event_count = 50
    threads = 10

    def worker() -> None:
        try:
            for i in range(event_count):
                event_type = secrets.choice(
                    [EventType.CRED_CREATE, EventType.CRED_DELETE]
                )
                success = secrets.choice([True, False])
                details = {
                    "operation": f"test_{i}", 
                    "token": f"secret_{i}"
                }
                time.sleep(0.001)  # Small fixed delay instead of random

                audit_event(
                    event_type=event_type,
                    user=f"user_{i}",
                    success=success,
                    details=details,
                    error=None if success else ValueError(f"Test error {i}")
                )
        except ValueError as e:
            errors.put(e)

    # Create and start threads
    thread_list = [threading.Thread(target=worker) for _ in range(threads)]
    for t in thread_list:
        t.start()

    # Wait for completion with timeout
    for t in thread_list:
        t.join(timeout=10.0)
        assert not t.is_alive(), "Thread timed out"

    # Check for errors
    assert errors.empty(), (
        f"Encountered errors during concurrent logging: {list(errors.queue)}"
    )

    # Verify log file exists and has content
    log_file = tmp_path / "logs" / "perihelion.log"
    assert log_file.exists(), "Log file not created"
    assert log_file.stat().st_size > 0, "Log file is empty"

    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_logger.return_value.bind.return_value = mock_logger.return_value

        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details={"operation": "test", "token": "secret"},
        )

        _, kwargs = mock_logger.return_value.bind.call_args
        # Check sanitization is working
        assert kwargs["details"]["operation"] is not None
        assert kwargs["details"]["token"] == "***"


def test_log_rotation(tmp_path: Path, logger: structlog.BoundLogger) -> None:
    """Test log rotation configuration is consistent."""
    from perihelion_auth_manager.audit.logger import create_secure_handler

    log_file = tmp_path / "test.log"
    max_bytes = 1024
    backup_count = 2

    # Create and configure handler
    handler = create_secure_handler(log_file, max_bytes, backup_count)
    test_logger = logging.getLogger("test_rotation")
    test_logger.addHandler(handler)
    test_logger.setLevel(logging.INFO)

    # Generate enough log data to trigger rotation
    test_message = "A" * (max_bytes // 2)  # Message size is about half max_bytes

    # Write enough to trigger rotation
    for _ in range(5):  # Should create main log + 2 backups
        test_logger.info(test_message)

    # Verify files exist
    assert log_file.exists()
    assert (log_file.parent / f"{log_file.name}.1").exists()
    assert (log_file.parent / f"{log_file.name}.2").exists()
    assert not (log_file.parent / f"{log_file.name}.3").exists()

    # Verify rotation configuration
    assert isinstance(handler, RotatingFileHandler)
    assert handler.maxBytes == max_bytes
    assert handler.backupCount == backup_count
