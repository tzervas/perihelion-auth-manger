"""Secure audit logging framework."""

import inspect
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


# Global instances
_LOGGER_INSTANCE = None
_logger_lock = threading.Lock()


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
    # Create parent directory
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # Force directory permissions (since mkdir with exist_ok=True ignores mode)
    os.chmod(log_path.parent, 0o750)
    
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


def add_caller(logger: structlog.BoundLogger, method_name, event_dict: EventDict) -> EventDict:
    """Add caller information using inspect.stack()."""
    # Get all frames
    frames = inspect.stack()
    
    # Find the first frame outside our logging code
    for frame in frames:
        frame_file = frame.filename
        if (
            not "structlog" in frame_file and
            not "logging" in frame_file and
            not frame_file.endswith("logger.py")
        ):
            event_dict["caller"] = {
                "file": frame.filename,
                "line": frame.lineno,
                "function": frame.function,
            }
            break

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
            return "***"
        if isinstance(value, dict):
            return sanitize_keys(value, sensitive_keys)
        if isinstance(value, list):
            return [_sanitize_value("", item) for item in value]
        return value
        
    return {k: _sanitize_value(k, v) for k, v in event_dict.items()}


def sanitize_event_dict(_, __, event_dict: EventDict) -> EventDict:
    """Sanitize log record keys and values, recursively masking sensitive data."""
    SENSITIVE_KEYS = {"password", "token", "secret", "key", "credential", "api_key"}

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


def configure_logger(
    log_level: str = "INFO",
    correlation_id: Optional[str] = None,
    max_log_size: int = 50 * 1024 * 1024,  # 50 MB
    backup_count: int = 5,
    base_dir: Optional[Union[str, Path]] = None,
) -> structlog.BoundLogger:
    """Configure and return a new logger instance.

    This is a low-level function that creates a new logger configuration.
    For normal usage, prefer setup_logging() which properly handles the global instance.

    Args:
        log_level: Log level (default: INFO)
        correlation_id: Optional correlation ID for request tracing
        max_log_size: Maximum size of a log file before rotation
        backup_count: Number of backup files to keep
        base_dir: Optional base directory for log files

    Returns:
        A new configured logger instance
    """
    # Configure structlog first
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

    # Get log directory
    log_dir = get_log_dir(base_dir)

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
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        handler.close()
        root_logger.removeHandler(handler)

    # Add our handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Create logger
    logger = structlog.get_logger()

    # Add correlation ID
    logger = logger.bind(correlation_id=correlation_id or str(uuid.uuid4()))

    return logger



def setup_logging(
    log_level: str = "INFO",
    correlation_id: Optional[str] = None,
    max_log_size: int = 50 * 1024 * 1024,  # 50 MB
    backup_count: int = 5,
    base_dir: Optional[Union[str, Path]] = None,
    _keep_handlers: bool = False,
    _return_handler_count: bool = False,
) -> Union[structlog.BoundLogger, tuple[structlog.BoundLogger, int]]:
    """Setup structured logging.

    Args:
        log_level: Log level (default: INFO)
        correlation_id: Optional correlation ID for request tracing
        max_log_size: Maximum size of a log file before rotation
        backup_count: Number of backup files to keep
        base_dir: Optional base directory for log files
        _keep_handlers: Internal flag to control whether existing handlers are preserved
        _return_handler_count: Internal flag to control return type (logger vs logger+count)

    Returns:
        By default, returns the configured logger instance. If _return_handler_count is True,
        returns a tuple of (logger, handler_count).
    """
    global _LOGGER_INSTANCE
    
    with _logger_lock:
        # Get root logger and count current handlers
        root_logger = logging.getLogger()
        initial_handler_count = len(root_logger.handlers)
        
        # Always cleanup old global instance first
        old_correlation_id = None
        if _LOGGER_INSTANCE is not None:
            try:
                old_correlation_id = _LOGGER_INSTANCE._context.get('correlation_id')
            except AttributeError:
                pass
            _LOGGER_INSTANCE = None
        
        # Clear existing handlers if not keeping them
        if not _keep_handlers:
            # Close and remove all handlers
            for handler in root_logger.handlers[:]:
                try:
                    handler.close()
                except Exception:
                    pass  # Ignore errors closing handlers
                root_logger.removeHandler(handler)
            
            # Reset structlog configuration
            structlog.reset_defaults()

            # Configure new logger
            logger = configure_logger(
                log_level=log_level,
                # Use existing correlation ID if available
                correlation_id=correlation_id or old_correlation_id,
                max_log_size=max_log_size,
                backup_count=backup_count,
                base_dir=base_dir
            )
        
        # Update global instance AFTER configuration is complete
        _LOGGER_INSTANCE = logger
        
        if _return_handler_count:
            handler_count = len(root_logger.handlers)
            return logger, handler_count
        return logger


def get_logger() -> structlog.BoundLogger:
    """Get configured logger instance.
    
    Returns a cached logger instance to preserve context like correlation_id
    across calls. If no logger has been configured yet, configures one with
    default settings.

    Returns:
        Cached logger instance with preserved context
    """
    global _LOGGER_INSTANCE
    with _logger_lock:
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
        # Get caller information
        frame = inspect.currentframe().f_back
        caller_info = {
            "file": frame.f_code.co_filename,
            "line": frame.f_lineno,
            "function": frame.f_code.co_name,
        }

        event = {
            "event_type": event_type,
            "user": user,
            "success": success,
            "caller": caller_info,
        }

        if details:
            # Sanitize sensitive data
            event["details"] = sanitize_keys(details, {"password", "token", "secret", "key", "credential", "api_key"})

        if error:
            event["error"] = {
                "type": type(error).__name__,
                "message": str(error),
            }

        logger = logger.bind(**event)

        # Execute info or error based on success
        if success:
            logger.info("audit_event")
        else:
            logger.error("audit_event")

    except Exception as e:
        logger.error("audit_event_logging_failure", error=str(e))

    # Error state is already handled in the try block
