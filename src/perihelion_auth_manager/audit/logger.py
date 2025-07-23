"""Secure audit logging framework."""

import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import stat
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

import structlog
from structlog.types import EventDict, Processor
from ..security import ensure_secure_permissions


def get_log_dir(base_dir: Union[str, Path, None] = None) -> Path:
    """Get normalized log directory path.
    
    Args:
        base_dir: Base directory for logs. If None, uses ~/.local/log
        
    Returns:
        Resolved Path object for log directory
    """
    if base_dir is None:
        base_dir = Path.home() / ".local" / "log"
    return Path(base_dir).resolve()


def create_secure_handler(log_path: Path, max_bytes: int, backup_count: int) -> RotatingFileHandler:
    """Create a secure RotatingFileHandler with proper permissions.
    
    Args:
        log_path: Path to the log file
        max_bytes: Maximum size of each log file
        backup_count: Number of backup files to keep
        
    Returns:
        Configured RotatingFileHandler instance
    """
    # Create parent directory with secure permissions
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    
    # Create file with secure permissions from the start
    ensure_secure_permissions(log_path)
    
    return RotatingFileHandler(str(log_path), maxBytes=max_bytes,
                             backupCount=backup_count)


def get_handler(logger: logging.Logger) -> Optional[RotatingFileHandler]:
    """Check if a RotatingFileHandler already exists in the logger.
    
    Args:
        logger: Logger instance to check
        
    Returns:
        Existing RotatingFileHandler or None if not found
    """
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler):
            return handler
    return None


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
        if all(
            p not in frame_info[0] for p in ("structlog", "logging", __file__)
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


def sanitize_keys(event_dict: dict, sensitive_keys: set) -> dict:
    """Sanitize dictionary by redacting sensitive keys, using case-insensitive matching and handling nested structures.
    
    Args:
        event_dict: Dictionary to sanitize
        sensitive_keys: Set of keys to redact
        
    Returns:
        Sanitized copy of the dictionary
    """
    def _sanitize_value(key: str, value: Any) -> Any:
        if any(sk.lower() == key.lower() for sk in sensitive_keys):
            return "[REDACTED]"
        if isinstance(value, dict):
            return sanitize_keys(value, sensitive_keys)
        if isinstance(value, list):
            return [_sanitize_value("", item) for item in value]
        return value
        
    return {k: _sanitize_value(k, v) for k, v in event_dict.items()}


def sanitize_event_dict(_, __, event_dict: EventDict) -> EventDict:
    """Sanitize log record keys and values, recursively masking sensitive data."""
    SENSITIVE_KEYS = {"password", "token", "secret", "key", "credential"}

    # Make a copy to preserve metadata
    sanitized = event_dict.copy()
    
    # Apply sanitization and update the copy
    sanitized.update(sanitize_keys(event_dict, SENSITIVE_KEYS))
    return sanitized


def rotate_logs(log_dir: Path, max_bytes: int = 50 * 1024 * 1024, backup_count: int = 5) -> None:
    """Configure log rotation and retention."""
    log_file = log_dir / "perihelion.log"
    
    # Check if a RotatingFileHandler already exists
    root_logger = logging.getLogger()
    if not get_handler(root_logger):
        # Create secure rotating handler
        log_handler = create_secure_handler(log_file, max_bytes, backup_count)
        root_logger.addHandler(log_handler)


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
            data |= record.event_dict

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
    max_log_size: int = 50 * 1024 * 1024,  # 50 MB
    backup_count: int = 5,
) -> structlog.BoundLogger:
    """Setup structured logging.

    Args:
        log_level: Log level (default: INFO)
        correlation_id: Optional correlation ID for request tracing
        max_log_size: Maximum size of a log file before rotation
        backup_count: Number of backup files to keep

    Returns:
        Configured logger instance
    """
    # Get log directory
    log_dir = get_log_dir()

    # Create log file handler
    log_file = log_dir / "perihelion.log"
    file_handler = create_secure_handler(log_file, max_log_size, backup_count)
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

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            add_timestamp,
            add_thread_info,
            add_caller,
            sanitize_event_dict,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Create logger
    logger = structlog.get_logger()

    # Add correlation ID
    logger = logger.bind(correlation_id=correlation_id or str(uuid.uuid4()))

    # Set up log rotation
    rotate_logs(log_dir, max_log_size, backup_count)

    return logger


_LOGGER_INSTANCE = None

def get_logger() -> structlog.BoundLogger:
    """Get configured logger instance.
    
    Returns a cached logger instance to preserve context like correlation_id
    across calls. If no logger has been configured yet, configures one with
    default settings.

    Returns:
        Cached logger instance with preserved context
    """
    global _LOGGER_INSTANCE
    if _LOGGER_INSTANCE is None:
        _LOGGER_INSTANCE = setup_logging()
    return _LOGGER_INSTANCE


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

    try:
        event = {
            "event_type": event_type,
            "user": user,
            "success": success,
        }

        if details:
            # Sanitize sensitive data
            event["details"] = sanitize_keys(details, {"password", "token", "secret", "key", "credential"})

        if error:
            event["error"] = {
                "type": type(error).__name__,
                "message": str(error),
            }

        if success:
            logger.info("audit_event", **event)
        else:
            logger.error("audit_event", **event)

    except Exception as e:
        logger.error("audit_event_logging_failure", error=str(e))

    # Error state is already handled in the try block
