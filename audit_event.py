from typing import Dict, Optional, Any
import traceback
from enum import Enum

class EventType(Enum):
    # Example event types
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    DATA_ACCESS = "data_access"

def get_logger():
    # This is a placeholder - actual logger configuration would go here
    import logging
    return logging.getLogger(__name__)

def audit_event(event_type: EventType, user: str, success: bool = True,
                details: Optional[Dict[str, Any]] = None,
                error: Optional[Exception] = None) -> None:
    try:
        logger = get_logger()
        bound_logger = logger.bind(
            event_type=event_type,
            user=user,
            success=success
        )
        
        if error:
            bound_logger = bound_logger.bind(
                error={
                    "type": type(error).__name__,
                    "message": str(error),
                    "traceback": "".join(traceback.format_exception(error))
                }
            )
            
        if details:
            bound_logger = bound_logger.bind(details=details)
            
        if success:
            bound_logger.info("Audit event")
        else:
            bound_logger.error("Audit event failed")
            
    except (ValueError, TypeError) as e:
        logger.exception("Invalid audit event parameters",
                        event_type=event_type,
                        user=user,
                        error=str(e))
    except AttributeError as e:
        logger.exception("Logger configuration error",
                        event_type=event_type,
                        user=user,
                        error=str(e))
    except KeyError as e:
        logger.exception("Invalid event details structure",
                        event_type=event_type,
                        user=user,
                        error=str(e))
    except RuntimeError as e:
        logger.exception("Runtime error during audit logging",
                        event_type=event_type,
                        user=user,
                        error=str(e))
    except Exception as e:
        # Catch-all for truly unexpected errors that should be investigated
        logger.critical("Unexpected error during audit logging",
                       event_type=event_type,
                       user=user,
                       error=str(e))
