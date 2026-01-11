"""Cross-platform credential storage."""

import platform
from typing import Optional, Type

from .base import CredentialStore
from .linux import LibSecretStore
from .macos import KeychainStore
from .windows import WindowsCredentialStore


def get_platform_store(store_class: Optional[Type[CredentialStore]] = None) -> CredentialStore:
    """Get the appropriate credential store for the current platform.

    Args:
        store_class: Optional specific store class to use.

    Returns:
        CredentialStore: Platform-specific credential store instance.

    Raises:
        RuntimeError: If platform is unsupported.
    """
    if store_class is not None:
        return store_class()

    system = platform.system().lower()
    if system == "linux":
        return LibSecretStore()
    elif system == "darwin":
        return KeychainStore()
    elif system == "windows":
        return WindowsCredentialStore()
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


__all__ = [
    "CredentialStore",
    "LibSecretStore",
    "KeychainStore",
    "WindowsCredentialStore",
    "get_platform_store",
]
