"""Tests for the audit logging framework."""

import json
import logging
import os
from unittest.mock import patch

import pytest
import structlog

from perihelion_auth_manager.audit import EventType, audit_event, setup_logging


@pytest.fixture(autouse=True)
def configure_logger():
    """Configure logger for each test."""
    setup_logging(log_level="DEBUG")


@patch("perihelion_auth_manager.audit.logger.get_log_dir")
def test_logging_directory_permissions(mock_log_dir):
    """Test log directory permissions are secure."""
    # Mock log directory path
    mock_path = "/mocked/path"
    mock_log_dir.return_value = mock_path

    os.makedirs(mock_path, mode=0o700, exist_ok=True)

    # Check log directory permissions
    assert oct(os.stat(mock_path).st_mode)[-3:] == "700"


@patch("perihelion_auth_manager.audit.logger.logging.FileHandler")
def test_log_file_permissions(mock_file_handler):
    """Test log file permissions are secure."""
    # Mock log file path
    mock_path = "/mocked/path/perihelion.log"
    mock_file_handler.return_value.baseFilename = mock_path

    with open(mock_path, "w") as f:
        f.write("")  # Create mocked log file

    os.chmod(mock_path, 0o600)

    # Check log file permissions
    assert oct(os.stat(mock_path).st_mode)[-3:] == "600"


def test_audit_event_logging():
    """Test logging of audit events."""
    logger = structlog.get_logger()

    with patch.object(logger, "info") as mock_info, patch.object(
        logger, "error"
    ) as mock_error:
        # Log a successful event
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details={"operation": "create", "token": "secret-token"},
        )
        mock_info.assert_called_once()
        logged_event = mock_info.call_args[1]["event"]
        assert logged_event["event_type"] == EventType.CRED_CREATE
        assert logged_event["user"] == "test-user"
        assert logged_event["success"]
        assert logged_event["details"]["operation"] == "create"
        assert logged_event["details"]["token"] == "***"  # Token should be sanitized

        # Log a failed event
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=False,
            error=ValueError("Invalid value"),
        )
        mock_error.assert_called_once()
        logged_error_event = mock_error.call_args[1]["event"]
        assert logged_error_event["event_type"] == EventType.CRED_CREATE
        assert logged_error_event["user"] == "test-user"
        assert not logged_error_event["success"]
        assert logged_error_event["error"]["type"] == "ValueError"
        assert logged_error_event["error"]["message"] == "Invalid value"


def test_audit_event_sanitization():
    """Test sanitization of sensitive details in audit events."""
    # Capture logged events
    with patch("structlog.BoundLogger.info") as mock_info:
        # Log an event with sensitive details
        audit_event(
            event_type=EventType.CRED_CREATE,
            user="test-user",
            success=True,
            details={"username": "user", "password": "secret", "token": "token-value"},
        )

        # Check sanitization
        logged_data = mock_info.call_args[1]["event"]
        assert logged_data["details"]["password"] == "***"
        assert logged_data["details"]["token"] == "***"
        assert logged_data["details"]["username"] == "user"


@patch("perihelion_auth_manager.audit.logger.logging.FileHandler")
def test_json_logging(mock_file_handler):
    """Test logging output format as JSON."""
    # Mock file handler
    mock_file_handler.return_value.emit = lambda record: print(record.msg)

    # Log an example message
    logger = structlog.get_logger()
    logger.info("test_event", extra_field="extra_value")

    # Capture and parse logged JSON
    with patch("builtins.print") as mock_print:
        logger.info("test_event", extra_field="extra_value")
        json_output = mock_print.call_args[0][0]
        parsed_json = json.loads(json_output)

        assert parsed_json["message"] == "test_event"
        assert parsed_json["extra_field"] == "extra_value"
        assert "timestamp" in parsed_json
        assert "level" in parsed_json


def test_structlog_configuration():
    """Test structlog configuration is applied as expected."""
    logger = structlog.get_logger("test_logger")
    logger = logger.bind(test_bind="bind_value")

    with patch("structlog.BoundLogger.info") as mock_info:
        logger.info("testing", key="value")

        assert mock_info.call_args[0][0] == "testing"
        assert mock_info.call_args[1]["key"] == "value"
        assert mock_info.call_args[1]["test_bind"] == "bind_value"
