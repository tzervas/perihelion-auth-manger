import os
import inspect
from typing import Any, Dict
import structlog
from structlog.types import EventDict

def add_caller(logger: structlog.BoundLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Add caller information using inspect.stack() with limited depth.
    
    Args:
        logger: The bound logger instance
        method_name: Name of the logging method being called
        event_dict: Dictionary containing the log event data
        
    Returns:
        EventDict with caller information added under the 'caller' key
        
    The function inspects the call stack to find the first frame outside of logging code
    and adds the caller's file, line number and function name to the event dictionary.
    Stack inspection is limited to 10 frames for performance.
    """
    MAX_FRAMES = 10  # Limit stack inspection depth
    LOGGING_PATHS = ("structlog", "logging", "logger.py")
    
    try:
        frames = inspect.stack(context=0)[:MAX_FRAMES]
        
        try:
            # Find first frame outside logging code
            for frame in frames:
                frame_file = frame.filename
                # Check if frame is from logging code
                if not any(p in frame_file.lower() for p in LOGGING_PATHS):
                    # Convert to relative path if possible for better readability
                    try:
                        file_path = os.path.relpath(frame.filename)
                    except ValueError:
                        file_path = frame.filename
                        
                    event_dict["caller"] = {
                        "file": file_path,
                        "line": frame.lineno,
                        "function": frame.function,
                    }
                    break
            else:
                # No suitable frame found
                event_dict["caller"] = {
                    "error": "No caller frame found outside logging code"
                }
                
        finally:
            # Ensure all frames are properly closed to prevent memory leaks
            for frame in frames:
                frame.frame.clear()
                
    except Exception as e:
        # Don't fail logging if caller detection fails
        event_dict["caller"] = {
            "error": f"Failed to detect caller: {str(e)}"
        }
    
    return event_dict
