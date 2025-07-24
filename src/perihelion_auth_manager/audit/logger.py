"""Secure audit logging framework."""

import gc
import inspect
import json
import logging
import os
import sys
import threading
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict

# Global instances
_LOGGER_INSTANCE = None
_logger_lock = threading.Lock()


def get_log_dir(base_dir: str | Path | None = None) -> Path:
    """Get normalized log directory path.

    Args:
        base_dir: Base directory for logs. If None, uses ~/.local/log

    Returns:
        Resolved Path object for log directory
    """
    if base_dir is None:
        base_dir = Path.home() / ".local" / "log"
    return Path(base_dir).resolve()


def create_secure_handler(
    log_path: Path, max_bytes: int, backup_count: int
) -> RotatingFileHandler:
    """Create a secure RotatingFileHandler with proper permissions.

    Args:
        log_path: Path to the log file
        max_bytes: Maximum size of each log file
        backup_count: Number of backup files to keep

    Returns:
        Configured RotatingFileHandler instance
    """
    # Create parent directory if needed
    os.makedirs(log_path.parent, mode=0o750, exist_ok=True)

    # Create handler first
    handler = RotatingFileHandler(
        str(log_path), maxBytes=max_bytes, backupCount=backup_count
    )

    # Ensure file exists since some platforms need it for permissions
    if not log_path.exists():
        log_path.touch(mode=0o640)

    # Set file permissions
    os.chmod(log_path, 0o640)

    return handler


def get_handler(logger: logging.Logger) -> RotatingFileHandler | None:
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


def add_timestamp(
    _: structlog.BoundLogger, __: str, event_dict: EventDict
) -> EventDict:
    """Add ISO 8601 timestamp."""
    event_dict["timestamp"] = datetime.now(UTC).isoformat()
    return event_dict


def add_log_level(
    _: structlog.BoundLogger,
    level_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Add log level name to event dictionary.

    Args:
        _: The bound logger instance (unused)
        level_name: The name of the log level
        event_dict: The event dictionary to modify

    Returns:
        Modified event dictionary with log level added
    """
    event_dict["level"] = level_name
    return event_dict


def add_caller(
    logger: structlog.BoundLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add caller information using inspect.stack().

    Args:
        logger: The logger instance
        method_name: The logging method name (unused)
        event_dict: The event dictionary to modify

    Returns:
        Modified event dictionary with caller information.
        In error cases, adds an "error" field to caller indicating the issue.
    """
    # Make a type-safe copy of the event dict
    result: EventDict = dict(event_dict)
    # Add caller info to result
    result["caller"] = {"error": "No caller frame available"}

    try:
        frames = inspect.stack()
        if not frames:
            return result

        # Track if we only see logging frames
        all_frames_logging = True
        infra_patterns = {
            "structlog",
            "logging",
            "logger.py",
            "_pytest",
            "pytest.py",
            "python.py",
            "pluggy",
            "unittest",
        }

        # Try to find a valid caller frame
        found_valid_caller = False
        caller_info: dict[str, str] = {}

        # Skip our own frame
        for frame_info in frames[1:]:
            # Get the frame and validate it
            frame = frame_info.frame
            if not frame or not hasattr(frame, "f_code") or not frame.f_code:
                continue

            # Extract frame information
            frame_file = frame.f_code.co_filename
            frame_func = frame.f_code.co_name

            # Check if this is an infrastructure frame
            is_infra = any(p in frame_file for p in infra_patterns)
            if is_infra:
                continue

            all_frames_logging = False
            if frame_func not in ("<module>", "__call__", "__init__"):
                caller_info = {
                    "file": frame.f_code.co_filename,
                    "line": str(frame.f_lineno),
                    "function": frame.f_code.co_name,
                }

                # Try to get accurate function name for nested functions
                if frame.f_code.co_code:
                    try:
                        for obj in gc.get_referrers(frame.f_code):
                            if inspect.isfunction(obj) and obj.__code__ is frame.f_code:
                                caller_info["function"] = obj.__name__
                                found_valid_caller = True
                                break
                        if found_valid_caller:
                            result["caller"] = caller_info
                            break
                    except (AttributeError, RuntimeError) as e:
                        logging.debug(f"Error retrieving function name: {e}")

        if not found_valid_caller and all_frames_logging:
            result["caller"]["error"] = "All frames from logging infrastructure"

    except (AttributeError, RuntimeError, ValueError) as e:
        result["caller"]["error"] = f"Error getting caller info: {e}"

    return result


def add_thread_info(
    _: structlog.BoundLogger, __: str, event_dict: EventDict
) -> EventDict:
    """Add thread information."""
    result: EventDict = dict(event_dict)
    thread = threading.current_thread()
    result["thread"] = {
        "id": thread.ident,
        "name": thread.name,
    }
    return result


def sanitize_keys(
    event_dict: dict[str, Any], sensitive_keys: set[str]
) -> dict[str, Any]:
    """Sanitize dictionary by redacting sensitive keys, \
   using case-insensitive matching and handling nested structures.

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


def sanitize_event_dict(
    _: structlog.BoundLogger, __: str, event_dict: EventDict
) -> dict[str, Any]:
    """Sanitize log record keys and values, recursively masking sensitive data."""
    private_keys = {"password", "token", "secret", "key", "credential", "api_key"}
    # Create a new dict with sanitized values
    return sanitize_keys(dict(event_dict), private_keys)


def rotate_logs(
    log_dir: Path, max_bytes: int = 50 * 1024 * 1024, backup_count: int = 5
) -> None:
    """Configure log rotation and retention."""
    log_file = log_dir / "perihelion.log"

    # Check if a RotatingFileHandler already exists
    root_logger = logging.getLogger()
    if not get_handler(root_logger):
        # Create secure rotating handler
        log_handler = create_secure_handler(log_file, max_bytes, backup_count)
        root_logger.addHandler(log_handler)


class StructuredJsonFormatter(logging.Formatter):
    """JSON formatter for structured logs.
    
    Formats log records as JSON strings with consistent structure and typing.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string.

        Args:
            record: The log record to format

        Returns:
            JSON string representation of the log record
        """
        # Type hint for event_dict attribute
        if not hasattr(record, "event_dict"):
            record.event_dict = {}

        # Get basic record attributes
        log_data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields
        event_dict = getattr(record, "event_dict", {})
        log_data.update(event_dict)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": str(record.exc_info[0]),
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }

        return json.dumps(log_data)


def configure_logger(
    log_level: str = "INFO",
    correlation_id: str | None = None,
    max_log_size: int = 50 * 1024 * 1024,  # 50 MB
    backup_count: int = 5,
    base_dir: str | Path | None = None,
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
        A properly configured structlog.BoundLogger instance
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
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

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

    # Create logger and ensure it's the right type
    logger = structlog.get_logger()
    result: structlog.BoundLogger = logger.bind(
        correlation_id=correlation_id or str(uuid.uuid4())
    )
    if not isinstance(result, structlog.BoundLogger):
        raise TypeError("Expected BoundLogger instance")
    return result


def setup_logging(
    *,
    log_level: str = "INFO",
    correlation_id: str | None = None,
    max_log_size: int = 50 * 1024 * 1024,  # 50 MB
    backup_count: int = 5,
    base_dir: str | Path | None = None,
    keep_handlers: bool = False,
    return_handler_count: bool = False,
) -> structlog.BoundLogger:
    """Setup structured logging.

    Args:
        log_level: Log level (default: INFO)
        correlation_id: Optional correlation ID for request tracing
        max_log_size: Maximum size of a log file before rotation
        backup_count: Number of backup files to keep
        base_dir: Optional base directory for log files
        _keep_handlers: Internal flag to control whether existing handlers are preserved
        _return_handler_count: Internal flag to control return type
        (logger vs logger+count)

    Returns:
        By default, returns the configured logger instance.
        If _return_handler_count is True,
        returns a tuple of (logger, handler_count).
    """
    global _LOGGER_INSTANCE

    # Prepare variables for configuration
    new_logger = None
    root_logger = logging.getLogger()

    if not keep_handlers:
        # Reset handlers first
        for handler in root_logger.handlers[:]:
            with suppress(Exception):
                handler.close()
            with suppress(Exception):
                root_logger.removeHandler(handler)

        # Reset structlog configuration
        with suppress(Exception):
            structlog.reset_defaults()

        # Configure new logger
        new_logger = configure_logger(
            log_level=log_level,
            correlation_id=correlation_id,  # Use explicit correlation ID
            max_log_size=max_log_size,
            backup_count=backup_count,
            base_dir=base_dir,
        )

        # Update global instance quickly with timeout
        if _logger_lock.acquire(timeout=1.0):  # 1 second timeout
            try:
                _LOGGER_INSTANCE = new_logger
            finally:
                _logger_lock.release()
        else:
            # Lock acquisition timed out, force update
            logging.warning("setup_logging: Lock acquisition timed out, forcing update")
            _LOGGER_INSTANCE = new_logger

    # Return appropriate result
    if new_logger is None:
        # Create a new logger if none exists
        new_logger = configure_logger(
            log_level=log_level,
            correlation_id=correlation_id,
            max_log_size=max_log_size,
            backup_count=backup_count,
            base_dir=base_dir,
        )

    if not isinstance(new_logger, structlog.BoundLogger):
        raise TypeError("Expected BoundLogger instance")
    return new_logger


def get_logger() -> structlog.BoundLogger:
    """Get configured logger instance.

    Returns a cached logger instance to preserve context like correlation_id
    across calls. If no logger has been configured yet, configures one with
    default settings.

    Returns:
        Cached logger instance with preserved context
    """
    global _LOGGER_INSTANCE
    configured_logger: structlog.BoundLogger = configure_logger()

    # Quick check first without lock
    if _LOGGER_INSTANCE is not None:
        if not isinstance(_LOGGER_INSTANCE, structlog.BoundLogger):
            raise TypeError("Expected BoundLogger instance")
        return _LOGGER_INSTANCE

    # Double-check with lock and timeout
    try:
        if _logger_lock.acquire(timeout=1.0):  # 1 second timeout
            try:
                # Under lock, set up logger if needed
                if _LOGGER_INSTANCE is None:
                    _LOGGER_INSTANCE = configured_logger
                result = _LOGGER_INSTANCE
            finally:
                _logger_lock.release()

            if not isinstance(result, structlog.BoundLogger):
                raise TypeError("Expected BoundLogger instance")
            return result

        # Lock acquisition failed, use configured_logger
        if not isinstance(configured_logger, structlog.BoundLogger):
            raise TypeError("Expected BoundLogger instance")
        return configured_logger

    except (RuntimeError, TimeoutError) as e:
        logging.error(f"Unexpected error in get_logger: {e}")
        if not isinstance(configured_logger, structlog.BoundLogger):
            raise TypeError("Expected BoundLogger instance") from None
        return configured_logger


def reset_logger() -> None:
    """Reset logger state with proper synchronization.

    This function ensures thread-safe cleanup of the logger state by:
    1. Acquiring a global lock with timeout
    2. Storing and cleaning up existing handlers
    3. Resetting structlog configuration
    4. Clearing the global logger instance

    The function is idempotent and can be called multiple times safely.
    Any errors during cleanup are logged but won't prevent the reset from completing.
    """
    global _LOGGER_INSTANCE
    root_logger = logging.getLogger()
    handlers = root_logger.handlers[:]

    # First clean up handlers and structlog outside the lock
    for handler in handlers:
        with suppress(Exception):
            handler.close()

        with suppress(Exception):
            if handler in root_logger.handlers:
                root_logger.removeHandler(handler)

    with suppress(Exception):
        structlog.reset_defaults()

    # Then do minimal work under the lock
    try:
        if _logger_lock.acquire(timeout=1.0):  # 1 second timeout
            try:
                if _LOGGER_INSTANCE is not None:
                    try:
                        _LOGGER_INSTANCE._context.get("correlation_id")
                    except AttributeError as e:
                        logging.debug(f"Failed to retrieve correlation_id: {e}")
                _LOGGER_INSTANCE = None
            finally:
                _logger_lock.release()
        else:
            # Lock acquisition timed out
            logging.warning("reset_logger: Lock acquisition timed out, forcing reset")
            _LOGGER_INSTANCE = None
    except (RuntimeError, TimeoutError, ValueError) as e:
        # Handle any unexpected errors, still ensure instance is cleared
        logging.error(f"Unexpected error during logger reset: {e}")
        _LOGGER_INSTANCE = None


def audit_event(
    *,
    event_type: str,
    user: str,
    success: bool,
    details: dict[str, Any] | None = None,
    error: Exception | None = None,
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
    frame = inspect.currentframe()
    if frame is not None and frame.f_back is not None:
        try:
            # Get caller information
            caller_info = {
                "file": frame.f_back.f_code.co_filename,
                "line": frame.f_back.f_lineno,
                "function": frame.f_back.f_code.co_name,
            }

            event = {
                "event_type": event_type,
                "user": user,
                "success": success,
                "caller": caller_info,
            }

            if details:
                # Sanitize sensitive data
                event["details"] = sanitize_keys(
                    details,
                    {"password", "token", "secret", "key", "credential", "api_key"},
                )

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

        except (AttributeError, KeyError, ValueError) as e:
            logger.error("audit_event_logging_failure", error=str(e))
    else:
        logger.error("audit_event_frame_error", message="Failed to get caller frame")
    # Error state is already handled in the try block
