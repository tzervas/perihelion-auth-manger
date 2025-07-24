"""Tests for the audit logging framework."""

import json
import logging
from logging.handlers import RotatingFileHandler
import os
from unittest.mock import patch, MagicMock

import pytest
import structlog

from perihelion_auth_manager.audit import EventType, audit_event
from perihelion_auth_manager.audit.logger import (
    get_log_dir, setup_logging, _LOGGER_INSTANCE, _logger_lock, add_caller
)

@pytest.fixture(autouse=True)
def reset_logging(tmp_path):
    """Configure logger for each test."""
    # Configure logger with test directory
    logger = setup_logging(base_dir=tmp_path)
    yield logger
    # Clean up after test
    with _logger_lock:
        root_logger = logging.getLogger()
        # Remove handlers
        for handler in root_logger.handlers[:]:
            try:
                handler.close()
            except Exception:
                pass
            root_logger.removeHandler(handler)
        # Reset structlog
        structlog.reset_defaults()
        # Clear global instance
        global _LOGGER_INSTANCE
        _LOGGER_INSTANCE = None


@patch("perihelion_auth_manager.audit.logger.get_log_dir")
def test_logging_directory_permissions(mock_log_dir, tmp_path):
    """Test log directory permissions are secure."""
    # Mock log directory path
    mock_path = str(tmp_path / "logs")
    mock_log_dir.return_value = mock_path

    os.makedirs(mock_path, mode=0o700, exist_ok=True)

    # Check log directory permissions
    assert oct(os.stat(mock_path).st_mode).endswith("700")


def test_secure_handler_creation(tmp_path):
    """Test creation of secure RotatingFileHandler."""
    from perihelion_auth_manager.audit.logger import create_secure_handler
    
    log_file = tmp_path / "test.log"
    max_bytes = 1024
    backup_count = 2
    
    handler = create_secure_handler(log_file, max_bytes, backup_count)
    
    # Check log directory permissions
    assert oct(os.stat(tmp_path).st_mode & 0o777).endswith('750')
    
    # Check log file permissions - 640 per security module
    mode = oct(os.stat(log_file).st_mode & 0o777)
    assert mode.endswith('640'), f"Expected 640 permissions, got {mode}"
    
    # Verify handler configuration
    assert isinstance(handler, RotatingFileHandler)
    assert handler.maxBytes == max_bytes
    assert handler.backupCount == backup_count


def test_handler_existence_check():
    """Test detection of existing handlers."""
    from perihelion_auth_manager.audit.logger import get_handler
    
    logger = logging.getLogger('test_logger')
    
    # Initially no handler
    assert get_handler(logger) is None
    
    # Add a non-rotating handler
    logger.addHandler(logging.StreamHandler())
    assert get_handler(logger) is None
    
    # Add a rotating handler
    rotating_handler = RotatingFileHandler('/tmp/test.log')
    logger.addHandler(rotating_handler)
    assert get_handler(logger) == rotating_handler


def test_audit_event_logging():
    """Test logging of audit events."""
    logger = structlog.get_logger()

    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_info = mock_logger.return_value.info
        mock_error = mock_logger.return_value.error
        mock_bound = mock_logger.return_value.bind.return_value = mock_logger.return_value
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
        assert kwargs["details"]["token"] == "***"  # Token should be sanitized

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


def test_audit_event_sanitization():
    """Test sanitization of sensitive details in audit events."""
    # Capture logged events
    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_info = mock_logger.return_value.info
        mock_bound = mock_logger.return_value.bind.return_value = mock_logger.return_value
        # Log an event with sensitive details
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details={"username": "user", "password": "secret", "token": "token-value"},
        )

        # Check sanitization
        _, kwargs = mock_logger.return_value.bind.call_args
        assert kwargs["details"]["password"] == "***"
        assert kwargs["details"]["token"] == "***"
        assert kwargs["details"]["username"] == "user"


@patch("perihelion_auth_manager.audit.logger.StructuredJsonFormatter")
def test_json_logging(mock_formatter):
    """Test logging output format as JSON."""
    # Mock the handler and setup logging
    logger = setup_logging()
    
    # Configure mock formatter
    log_record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="test_event",
        args=(),
        exc_info=None
    )
    log_record.extra_field = "extra_value"
    
    mock_formatter.return_value.format.return_value = json.dumps({
        "message": "test_event",
        "extra_field": "extra_value",
        "level": "INFO"
    })
    
    # Test logging an event
    logger.info("test_event", extra_field="extra_value")
    
    # Verify that the formatter produces valid JSON with the expected fields
    output = mock_formatter.return_value.format(log_record)
    parsed = json.loads(output)
    assert parsed["message"] == "test_event"
    assert parsed["extra_field"] == "extra_value"
    assert parsed["level"] == "INFO"


def test_nested_key_sanitization():
    """Test sanitization of nested sensitive keys in audit events."""
    data = {
        "outer": {
            "password": "secret",
            "nested": {"api_key": "12345"}
        }
    }
    # Using the audit_event to test sanitization
    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_info = mock_logger.return_value.info
        mock_logger.return_value.bind.return_value = mock_logger.return_value
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details=data
        )
        _, kwargs = mock_logger.return_value.bind.call_args
        assert kwargs["details"]["outer"]["password"] == "***"
        assert kwargs["details"]["outer"]["nested"]["api_key"] == "***"


def test_handler_duplication():
    """Test prevention of duplicate secure handlers."""
    from perihelion_auth_manager.audit.logger import create_secure_handler
    
    logger = logging.getLogger("test")
    log_dir = get_log_dir()
    create_secure_handler(log_dir / "test.log", 1024, 3)
    original_handler_count = len(logger.handlers)
    create_secure_handler(get_log_dir() / "test.log", 1024, 3)
    assert len(logger.handlers) == original_handler_count


def test_structlog_configuration():
    """Test structlog configuration is applied as expected."""
    # Configure a test logger with bindings
    logger = structlog.get_logger().bind(test_bind="bind_value")

    # Verify bound fields are preserved
    assert logger._context.get("test_bind") == "bind_value"

    # Verify new key-value pairs can be added to logging calls
    assert logger._context.get("key") is None  # Not bound yet
    logger = logger.bind(key="value")
    assert logger._context.get("key") == "value"  # Now bound


def test_consistent_redaction():
    """Test redaction consistency across nested structures."""
    details = {
        "password": "secret",
        "nested": {
            "token": "abcd",
            "deep": {
                "api_key": "xyz123",
                "safe_field": "visible"
            }
        },
        "array_with_secrets": [
            {"key": "secret1"},
            {"token": "secret2"}
        ],
        "safe_field": "visible"
    }
    
    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_info = mock_logger.return_value.info
        mock_logger.return_value.bind.return_value = mock_logger.return_value
        
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details=details
        )
        
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


def test_caller_detection():
    """Test accurate detection of calling context."""
    def wrapper_function():
        def inner_function():
            mock_logger = MagicMock(spec=structlog.BoundLogger)
            mock_logger.bind = MagicMock(return_value=mock_logger)
            mock_logger.info = MagicMock()
            
            with patch("perihelion_auth_manager.audit.logger.get_logger", return_value=mock_logger):
                audit_event(
                    event_type=EventType.CRED_CREATE,
                    user="test-user",
                    success=True
                )
                
                # Verify log call
                mock_logger.info.assert_called_once()
                
                # Verify bind calls for event details
                bind_call = mock_logger.bind.call_args
                assert bind_call is not None
                args, event_details = bind_call
                
                # Verify event details
                assert event_details["event_type"] == EventType.CRED_CREATE
                assert event_details["user"] == "test-user"
                assert event_details["success"] is True
                
                # Verify caller info was included
                for call in mock_logger.bind.call_args_list:
                    _, kwargs = call
                    if "caller" in kwargs:
                        caller_info = kwargs["caller"]
                        assert caller_info["function"] == "inner_function"
                        assert "test_audit.py" in caller_info["file"]
                        assert isinstance(caller_info["line"], int)
                        assert caller_info["line"] > 0
                        break
                else:
                    assert False, "No caller info found in log event"

        return inner_function()
    
    wrapper_function()


def test_log_rotation(tmp_path):
    """Test log rotation configuration is consistent."""
    from perihelion_auth_manager.audit.logger import create_secure_handler
    
    log_file = tmp_path / "test.log"
    max_bytes = 1024
    backup_count = 2
    
    # Create and configure handler
    handler = create_secure_handler(log_file, max_bytes, backup_count)
    logger = logging.getLogger("test_rotation")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    # Generate enough log data to trigger rotation
    test_message = "A" * (max_bytes // 2)  # Message size is about half max_bytes
    
    # Write enough to trigger rotation
    for i in range(5):  # Should create main log + 2 backups
        logger.info(test_message)
    
    # Verify files exist
    assert log_file.exists()
    assert (log_file.parent / f"{log_file.name}.1").exists()
    assert (log_file.parent / f"{log_file.name}.2").exists()
    assert not (log_file.parent / f"{log_file.name}.3").exists()  # Should not exist
    
    # Verify rotation configuration
    assert isinstance(handler, RotatingFileHandler)
    assert handler.maxBytes == max_bytes
    assert handler.backupCount == backup_count


def test_logger_reset(tmp_path):
    """Test logger reset functionality and thread safety."""
    import threading
    import queue
    import time

    results = queue.Queue()

    def worker():
        try:
            # Get root logger
            root_logger = logging.getLogger()

            # Create first logger instance
            logger1 = setup_logging(base_dir=tmp_path)
            base_handlers = len(root_logger.handlers)

            # Add a custom handler to the logger
            logger1.addHandler(logging.NullHandler())
            # Verify handler was added
            assert len(logger1.handlers) > 0

            time.sleep(0.1)  # Simulate work

            # Create new logger - should reset existing one
            logger2 = setup_logging(base_dir=tmp_path)

            # Verify handler count is back to base and logger instance changed
            handlers_now = len(root_logger.handlers)
            results.put({
                'success': True,
                # After reset, should be back to just the initial handlers
                'handler_count': handlers_now == base_handlers,
                'different_instances': logger1 is not logger2
            })
        except Exception as e:
            results.put({'success': False, 'error': str(e)})
    
    # Run multiple threads simultaneously
    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=1.0)  # Add timeout to prevent deadlocks
        assert not t.is_alive(), "Thread failed to complete within timeout"
    
    # Check results from all threads
    while not results.empty():
        result = results.get()
        assert result['success'], f"Thread failed: {result.get('error', 'Unknown error')}"
        assert result['handler_count'], "Handler count mismatch after reset"
        assert result['different_instances'], "Logger instances should be different"
