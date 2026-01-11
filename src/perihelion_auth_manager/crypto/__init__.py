"""Cryptographic utilities for secure credential management."""

from .encryption import (
    EncryptionError,
    decrypt,
    decrypt_with_password,
    encrypt,
    encrypt_with_password,
    generate_key,
)
from .keys import KeyStore
from .memory import compare_bytes, secure_memory, secure_string, secure_zero_memory

__all__ = [
    # Encryption
    "encrypt",
    "decrypt",
    "encrypt_with_password",
    "decrypt_with_password",
    "generate_key",
    "EncryptionError",
    # Key management
    "KeyStore",
    # Memory security
    "secure_memory",
    "secure_string",
    "secure_zero_memory",
    "compare_bytes",
]
