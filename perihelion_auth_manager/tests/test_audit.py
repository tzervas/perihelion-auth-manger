"""Tests for audit event functionality."""
from unittest.mock import patch
from perihelion_auth_manager.audit import audit_event, EventType


def test_audit_event_sanitization_case_sensitivity():
    """Test case-insensitive sanitization of sensitive keys."""
    with patch("perihelion_auth_manager.audit.logger.get_logger") as mock_logger:
        mock_logger.return_value.bind.return_value = mock_logger.return_value
        
        # Test various case combinations
        test_cases = [
            {"Password": "secret"},
            {"TOKEN": "abc123"},
            {"Api_Key": "xyz789"},
            {"credentials": {"Secret_Key": "hidden"}},
            {"nested": {"API_TOKEN": "test"}}
        ]
        
        for details in test_cases:
            audit_event(
                event_type=EventType.CRED_CREATE,
                user="test-user",
                success=True,
                details=details
            )
            
            # Verify all sensitive values are masked
            _, kwargs = mock_logger.return_value.bind.call_args
            sanitized = kwargs["details"]
            
            def check_sanitized(d):
                for k, v in d.items():
                    if isinstance(v, dict):
                        check_sanitized(v)
                    elif any(sk.lower() in k.lower() for sk in 
                           {"password", "token", "secret", "key", "credential"}):
                        assert v == "***", f"Key {k} was not sanitized"
                        
            check_sanitized(sanitized)
