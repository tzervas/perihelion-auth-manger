"""Tests for the logger module."""

import inspect
import logging
import sys
import types
from logging.handlers import RotatingFileHandler
from pathlib import Path
from unittest import mock

import pytest

from perihelion_auth_manager.audit.logger import (
    _LOGGER_INSTANCE,
    add_caller,
    get_log_dir,
    get_logger,
    reset_logger,
    setup_logging,
)

# Enable fail-fast mode and add timeout to all tests
pytest.register_assert_rewrite('pytest')
pytest.fail_fast = True

# Add reset_logging fixture
@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging state between tests."""
    # Reset before each test
    reset_logger()
    yield
    # Clean up after test
    reset_logger()


@pytest.fixture
def cleanup_logs():
    """Clean up test log files after each test."""
    yield
    # Clean up test log files
    log_dir = get_log_dir()
    for f in log_dir.glob("*.log*"):
        f.unlink()



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


def test_add_caller_frame_detection():
    """Test that add_caller correctly detects the caller frame."""
    logger = setup_logging()
    event_dict = {}

    # Create artificial frame info objects
    def mock_frame(name, filename):
        # Python 3.13 requires 16 arguments for CodeType
        code = types.CodeType(
            0,             # argcount
            0,             # posonlyargcount
            0,             # kwonlyargcount
            0,             # nlocals
            1,             # stacksize
            0,             # flags
            b"",          # bytecode
            (),            # consts
            (),            # names
            (),            # varnames
            str(filename), # filename
            str(name),     # name
            1,             # firstlineno
            b"",          # lnotab
            (),            # cellvars
            ()             # freevars
        )
        return types.FrameType(code, {}, None)

    # Test with known frames
    with mock.patch("inspect.stack") as mock_stack:
        frame_infos = [
            inspect.FrameInfo(
                mock_frame("add_caller", "structlog/xyz.py"),
                "structlog/xyz.py", 1, "add_caller", ["def add_caller():"], 0
            ),
            inspect.FrameInfo(
                mock_frame("test_function", "test_logger.py"),
                "test_logger.py", 2, "test_function", ["def test_function():"], 0
            )
        ]
        mock_stack.return_value = frame_infos
        result = add_caller(logger, None, event_dict)

        assert "caller" in result
        assert result["caller"]["function"] == "test_function"
        assert "test_logger.py" in result["caller"]["file"]
        assert isinstance(result["caller"]["line"], int)


def test_add_caller_skips_logging_frames():
    """Test that add_caller skips frames from logging/structlog."""
    logger = setup_logging()
    event_dict = {}
    
    result = add_caller(logger, None, event_dict)
    
    assert "caller" in result
    # Should skip logging frames and use our test function
    assert "test_logger.py" in result["caller"]["file"]
    assert result["caller"]["function"] == "test_add_caller_skips_logging_frames"


def test_add_caller_edge_cases():
    """Test add_caller behavior with various call patterns."""
    logger = setup_logging()
    
    def nested_call():
        return add_caller(logger, None, {})
    
    def wrapper():
        return nested_call()
    
    # Test normal nested calls
    result = wrapper()
    assert "caller" in result
    assert result["caller"]["function"] == "nested_call"
    
    # Test when all frames are from logging
    with mock.patch("inspect.stack") as mock_stack:
        mock_stack.return_value = [
            mock.Mock(frame=mock.Mock(
                f_code=mock.Mock(
                    co_filename="structlog/xyz.py",
                    co_name="xyz_func"
                )
            )),
            mock.Mock(frame=mock.Mock(
                f_code=mock.Mock(
                    co_filename="logging/abc.py",
                    co_name="abc_func"
                )
            )),
            mock.Mock(frame=mock.Mock(
                f_code=mock.Mock(
                    co_filename="logger.py",
                    co_name="logger_func"
                )
            ))
        ]
        result = add_caller(logger, None, {})
        assert "caller" in result
        assert "error" in result["caller"]
        assert result["caller"]["error"] == "All frames from logging infrastructure"
    
    # Test with empty stack
    with mock.patch("inspect.stack", return_value=[]):
        result = add_caller(logger, None, {})
        assert "caller" in result
        assert "error" in result["caller"]
        assert result["caller"]["error"] == "No caller frame available"


@pytest.mark.filterwarnings
@pytest.mark.parametrize("caplog", [None])
@pytest.mark.timeout(30)  # Set 30 second timeout for log rotation test
def test_log_rotation(tmp_path, cleanup_logs, caplog):
    """Test that log rotation works correctly."""
    # Override default log directory to use temp path
    log_dir = tmp_path / "logs"
    
    # Ensure directory exists with proper permissions
    log_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    
    max_size = 1024  # 1KB
    backup_count = 3
    
    # Set up logging with small max size for testing
    logger = setup_logging(
        log_level="INFO",
        max_log_size=max_size,
        backup_count=backup_count,
        base_dir=log_dir
    )
    
    # Get the file handler - should be one of the handlers in root logger
    root_logger = logging.getLogger()
    assert len(root_logger.handlers) > 0, "No handlers found in root logger"
    
    for h in root_logger.handlers:
        if isinstance(h, RotatingFileHandler):
            file_handler = h
            break
    else:
        pytest.fail(
            "No RotatingFileHandler found among handlers: " + 
            ", ".join(type(h).__name__ for h in root_logger.handlers)
        )
    
    # Generate enough logs to trigger rotation
    large_msg = "x" * (max_size // 10)  # Each message is 1/10th max size
    for i in range(50):  # Should generate multiple rotations
        logger.info(f"test_message_{i}", data=large_msg)
        file_handler.flush()  # Force flush to ensure rotation happens
    
    # Check that log files exist and respect limits
    log_files = list(log_dir.glob("perihelion.log*"))
    
    # Should have main log + backup_count backups
    assert len(log_files) >= backup_count + 1
    
    # Main log file should exist
    main_log = log_dir / "perihelion.log"
    assert main_log.exists()
    
# Check size limit is respected (allow small overhead)
    assert main_log.stat().st_size <= max_size * 1.1  # Allow 10% overhead


@pytest.mark.timeout(10)  # Set 10 second timeout
def test_reset_logger(tmp_path):
    """Test that reset_logger properly cleans up logger resources."""
    # First setup a logger
    base_dir = tmp_path / "logs"
    logger = setup_logging(base_dir=base_dir)
    
    # Verify it's set as the global instance
    assert _LOGGER_INSTANCE is not None
    assert get_logger() is logger
    
    # Get initial handler count
    root_logger = logging.getLogger()
    initial_handlers = len(root_logger.handlers)
    assert initial_handlers > 0
    
    # Reset the logger
    reset_logger()
    
    # Verify the global instance is cleared
    assert _LOGGER_INSTANCE is None
    
    # Verify handlers are removed
    assert len(root_logger.handlers) == 0


@pytest.mark.timeout(30)  # Set 30 second timeout for thread safety test
def test_reset_logger_thread_safety(tmp_path):
    """Test that reset_logger is thread-safe."""
    import threading
    import time
    
    def setup_and_reset():
        setup_logging(base_dir=tmp_path / "logs")
        time.sleep(0.1)  # Simulate some work
        reset_logger()
    
    # Create multiple threads that setup and reset loggers
    threads = [threading.Thread(target=setup_and_reset) for _ in range(5)]
    
    # Start all threads
    for t in threads:
        t.start()
    
    # Wait for all threads to complete with timeout
    timeout = 5  # 5 second timeout per thread
    for t in threads:
        t.join(timeout=timeout)
        assert not t.is_alive(), "Thread failed to complete within timeout"
    
    # Verify final state
    assert _LOGGER_INSTANCE is None
    
    # Get remaining handlers (should only be pytest fixtures)
    root_logger = logging.getLogger()
    pytest_handlers = [
        h for h in root_logger.handlers 
        if type(h).__name__.startswith('LogCapture')
    ]
    assert len(root_logger.handlers) == len(pytest_handlers)


@pytest.mark.timeout(10)  # Set 10 second timeout
def test_reset_logger_no_instance():
    """Test that reset_logger handles case when no logger is initialized."""
    # Ensure no logger instance exists
    global _LOGGER_INSTANCE
    _LOGGER_INSTANCE = None
    
    # Get initial number of pytest handlers
    root_logger = logging.getLogger()
    pytest_handlers = [
        h for h in root_logger.handlers 
        if type(h).__name__.startswith('LogCapture')
    ]
    
    # Reset should work without error
    reset_logger()
    
    # Verify state remains clean
    assert _LOGGER_INSTANCE is None
    # Only pytest handlers should remain
    assert len(logging.getLogger().handlers) == len(pytest_handlers)


@pytest.mark.skipif(sys.platform == "win32",
                  reason="POSIX permissions not supported on Windows")
@pytest.mark.timeout(10)  # Set 10 second timeout
def test_logging_directory_permissions(tmp_path, cleanup_logs):
    """Test log directory permissions are secure."""
    log_dir = tmp_path / "logs"
    
    # Set up logging with handler
    logger = setup_logging(
        base_dir=log_dir,
        max_log_size=1024,  # 1KB
        backup_count=2
    )
    
    # Verify directory permissions (750)
    dir_mode = oct(log_dir.stat().st_mode & 0o777)
    assert dir_mode.endswith('750'), f"Expected 750 permissions, got {dir_mode}"
    
    # Get the file handler and its file path
    root_logger = logging.getLogger()
    for h in root_logger.handlers:
        if isinstance(h, RotatingFileHandler):
            file_handler = h
            log_file = Path(file_handler.baseFilename)
            break
    else:
        pytest.fail("No RotatingFileHandler found")
    
    # Verify file permissions (640)
    file_mode = oct(log_file.stat().st_mode & 0o777)
    assert file_mode.endswith('640'), f"Expected 640 permissions, got {file_mode}"
    
    # Write enough data to force rotation
    logger.info("test message", data="x" * 2048)  # Force rotation
    file_handler.flush()
    
    # Check rotated file permissions
    rotated_file = log_dir / "perihelion.log.1"
    assert rotated_file.exists(), "Rotated file not created"
    rotated_mode = oct(rotated_file.stat().st_mode & 0o777)
    assert rotated_mode.endswith('640'), (
        f"Expected 640 permissions on rotated file, got {rotated_mode}"
    )


@pytest.mark.timeout(10)  # Set 10 second timeout
def test_reset_logger_multiple_calls(tmp_path):
    """Test that reset_logger can be called multiple times safely."""
    # Setup initial logger
    setup_logging(base_dir=tmp_path / "logs")
    
    # Call reset multiple times
    for _ in range(3):
        reset_logger()
        
    # Verify final state
    assert _LOGGER_INSTANCE is None
    assert len(logging.getLogger().handlers) == 0
    
    # Setup new logger should work after multiple resets
    new_logger = get_logger()
    assert new_logger is not None
    assert _LOGGER_INSTANCE is not None


@pytest.mark.timeout(30)  # Set 30 second timeout for concurrent operations
def test_concurrent_logger_operations(tmp_path):
    """Test thread safety of logging operations."""
    import os
    import queue
    import threading
    
    errors = queue.Queue()
    
    def worker():
        try:
            # Perform various logging operations
            logger = get_logger()
            logger.info("test message")
            reset_logger()
            new_logger = setup_logging(base_dir=tmp_path)
            new_logger.info("another test")
        except Exception as e:
            errors.put(e)
    
    # Create and start multiple threads
    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    
    # Wait for completion
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive(), "Thread timed out"
    
    # Check for errors
    assert errors.empty(), f"Encountered errors: {list(errors.queue)}"
    
    # Verify log file integrity
    log_files = list(tmp_path.glob("**/*.log*"))
    assert len(log_files) > 0, "No log files created"
    
    # Verify file permissions
    for log_file in log_files:
        mode = oct(os.stat(log_file).st_mode & 0o777)
        assert mode.endswith('640'), f"Invalid permissions on {log_file}: {mode}"
