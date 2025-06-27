"""Secure audit logging framework."""

import json
import logging
import os
import platform
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import structlog
from structlog.types import EventDict, Processor


def get_log_dir() -> Path:
    """Get platform-specific log directory."""
    system = platform.system().lower()
    if system == "windows":
        base = Path.home() / "AppData/Local/Perihelion/Logs"
    elif system == "darwin":
        base = Path.home() / "Library/Logs/Perihelion"
    else:  # Linux and others
        base = Path.home() / ".local/share/perihelion/logs"

    os.makedirs(base, mode=0o700, exist_ok=True)
    return base


def add_timestamp(_, __, event_dict: EventDict) -> EventDict:
    """Add ISO 8601 timestamp."""
    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def add_log_level(_, level: str, event_dict: EventDict) -> EventDict:
    """Add log level."""
    event_dict["level"] = level
    return event_dict


def add_caller(logger: structlog.BoundLogger, _, event_dict: EventDict) -> EventDict:
    """Add caller information."""
    frame = sys._getframe()
    while frame:
        frame_info = (
            frame.f_code.co_filename,
            frame.f_lineno,
            frame.f_code.co_name,
        )
        if not any(
            p in frame_info[0]
            for p in ("structlog", "logging", __file__)
        ):
            event_dict.update(
                {
                    "caller": {
                        "file": frame_info[0],
                        "line": frame_info[1],
                        "function": frame_info[2],
                    }
                }
            )
            break
        frame = frame.f_back
    return event_dict


def add_thread_info(_: Any, __: Any, event_dict: EventDict) -> EventDict:
    """Add thread information."""
    thread = threading.current_thread()
    event_dict["thread"] = {
        "id": thread.ident,
        "name": thread.name,
    }
    return event_dict


def sanitize_keys(_, __, event_dict: EventDict) -> EventDict:
    """Sanitize log record keys."""
    # Create new dict with sanitized keys
    return {
        key.replace(".", "_").replace("$", "_"): value
        for key, value in event_dict.items()
    }


class StructuredJsonFormatter(logging.Formatter):
    """JSON formatter for structured logs."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Get basic record attributes
        data = {
            "timestamp": datetime.fromtimestamp(
                record.created, timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields
        if hasattr(record, "event_dict"):
            data.update(record.event_dict)

        # Add exception info if present
        if record.exc_info:
            data["exception"] = {
                "type": str(record.exc_info[0]),
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        return json.dumps(data)


def setup_logging(
    log_level: str = "INFO",
    correlation_id: Optional[str] = None,
) -> structlog.BoundLogger:
    """Setup structured logging.

    Args:
        log_level: Log level (default: INFO)
        correlation_id: Optional correlation ID for request tracing

    Returns:
        Configured logger instance
    """
    # Get log directory
    log_dir = get_log_dir()

    # Create log file handler
    log_file = log_dir / "perihelion.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(StructuredJsonFormatter())

    # Create stderr handler for warnings and above
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(
        logging.Formatter("%(levelname)s: %(message)s")
    )

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        handlers=[file_handler, console_handler],
    )

    # Set permissions on log file
    os.chmod(log_file, 0o600)

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            add_timestamp,
            add_thread_info,
            add_caller,
            sanitize_keys,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Create logger
    logger = structlog.get_logger()

    # Add correlation ID if provided
    if correlation_id:
        logger = logger.bind(correlation_id=correlation_id)
    else:
        logger = logger.bind(correlation_id=str(uuid.uuid4()))

    return logger


def get_logger() -> structlog.BoundLogger:
    """Get configured logger instance.

    Returns:
        Logger instance
    """
    return structlog.get_logger()


def audit_event(
    event_type: str,
    user: str,
    success: bool,
    details: Optional[Dict[str, Any]] = None,
    error: Optional[Exception] = None,
) -> None:
    """Log an audit event.

    Args:
        event_type: Type of event (e.g., "credential.create")
        user: Username or identifier
        success: Whether the operation succeeded
        details: Optional event details
        error: Optional exception if operation failed
    """
    logger = get_logger()

    event = {
        "event_type": event_type,
        "user": user,
        "success": success,
    }

    if details:
        # Sanitize sensitive data
        sanitized = {
            k: "***" if k in ("token", "password", "secret") else v
            for k, v in details.items()
        }
        event["details"] = sanitized

    if error:
        event["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }

    if success:
        logger.info("audit_event", **event)
    else:
        logger.error("audit_event", **event)
