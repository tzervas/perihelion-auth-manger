"""Audit event type definitions."""

from enum import Enum, auto


class EventType(str, Enum):
    """Audit event types."""

    # Authentication events
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_MFA_SETUP = "auth.mfa.setup"
    AUTH_MFA_VERIFY = "auth.mfa.verify"
    AUTH_TOKEN_CREATE = "auth.token.create"
    AUTH_TOKEN_REVOKE = "auth.token.revoke"

    # Credential events
    CRED_CREATE = "credential.create"
    CRED_READ = "credential.read"
    CRED_UPDATE = "credential.update"
    CRED_DELETE = "credential.delete"
    CRED_LIST = "credential.list"
    CRED_ROTATE = "credential.rotate"

    # Key events
    KEY_CREATE = "key.create"
    KEY_DELETE = "key.delete"
    KEY_ROTATE = "key.rotate"
    KEY_EXPORT = "key.export"
    KEY_IMPORT = "key.import"

    # Access control events
    POLICY_CREATE = "policy.create"
    POLICY_UPDATE = "policy.update"
    POLICY_DELETE = "policy.delete"
    ROLE_CREATE = "role.create"
    ROLE_UPDATE = "role.update"
    ROLE_DELETE = "role.delete"

    # System events
    SYS_STARTUP = "system.startup"
    SYS_SHUTDOWN = "system.shutdown"
    SYS_CONFIG_UPDATE = "system.config.update"
    SYS_BACKUP = "system.backup"
    SYS_RESTORE = "system.restore"

    # Error events
    ERROR_AUTH = "error.auth"
    ERROR_CRED = "error.credential"
    ERROR_KEY = "error.key"
    ERROR_POLICY = "error.policy"
    ERROR_SYSTEM = "error.system"
