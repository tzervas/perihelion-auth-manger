"""Secure encryption layer for credential data."""

import base64
import os
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import structlog

logger = structlog.get_logger(__name__)

# Initialize Argon2 hasher with recommended parameters
ph = PasswordHasher(
    time_cost=3,  # Number of iterations
    memory_cost=65536,  # 64MB memory usage
    parallelism=4,  # Number of parallel threads
    hash_len=32,  # Length of the hash
    salt_len=16,  # Length of the salt
)


class EncryptionError(Exception):
    """Base exception for encryption operations."""


def hash_password(password: str) -> str:
    """Hash a password using Argon2id.

    Args:
        password: The password to hash.

    Returns:
        The hashed password string.

    Raises:
        EncryptionError: If hashing fails.
    """
    try:
        return ph.hash(password)
    except Exception as e:
        raise EncryptionError(f"Failed to hash password: {e}")


def verify_password(password: str, hash_str: str) -> bool:
    """Verify a password against its hash.

    Args:
        password: The password to verify.
        hash_str: The hash string to verify against.

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        ph.verify(hash_str, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception as e:
        logger.error("password_verification_error", error=str(e))
        return False


def generate_key(
    password: str,
    salt: Optional[bytes] = None,
    iterations: int = 100_000,
    use_scrypt: bool = True
) -> Tuple[bytes, bytes]:
    """Generate an encryption key from a password using PBKDF2.

    Args:
        password: The password to derive the key from.
        salt: Optional salt bytes. If None, generates new salt.
        iterations: Number of PBKDF2 iterations (default: 100,000).

    Returns:
        Tuple of (key, salt).

    Raises:
        EncryptionError: If key derivation fails.
    """
    try:
        if salt is None:
            salt = os.urandom(16)

        if use_scrypt:
            # Use Scrypt for stronger key derivation
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**16,  # CPU/memory cost factor
                r=8,      # Block size parameter
                p=1,      # Parallelization parameter
            )
        else:
            # Fallback to PBKDF2 if Scrypt is not available
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )

        key = kdf.derive(password.encode())
        logger.debug(
            "derived_key",
            method="scrypt" if use_scrypt else "pbkdf2",
            salt_size=len(salt),
        )
        return key, salt

    except Exception as e:
        raise EncryptionError(f"Failed to generate key: {e}")


def encrypt(data: str, key: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM.

    Args:
        data: The data to encrypt.
        key: 32-byte encryption key.

    Returns:
        Tuple of (ciphertext, nonce).

    Raises:
        EncryptionError: If encryption fails.
    """
    try:
        # Generate 96-bit nonce for GCM
        nonce = os.urandom(12)

        # Create AESGCM cipher
        aesgcm = AESGCM(key)

        # Encrypt data
        data_bytes = data.encode()
        ciphertext = aesgcm.encrypt(
            nonce,
            data_bytes,
            associated_data,
        )

        logger.debug(
            "encrypted_data",
            data_size=len(data_bytes),
            has_associated_data=associated_data is not None
        )
        return ciphertext, nonce

    except Exception as e:
        raise EncryptionError(f"Failed to encrypt data: {e}")


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: Optional[bytes] = None) -> str:
    """Decrypt data using AES-256-GCM.

    Args:
        ciphertext: The encrypted data with authentication tag.
        key: 32-byte encryption key.
        nonce: 12-byte nonce used for encryption.

    Returns:
        Decrypted string.

    Raises:
        EncryptionError: If decryption fails.
    """
    try:
        # Create AESGCM cipher
        aesgcm = AESGCM(key)

        # Decrypt data
        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            associated_data,
        )

        logger.debug(
            "decrypted_data",
            data_size=len(plaintext),
            has_associated_data=associated_data is not None
        )
        return plaintext.decode()

    except Exception as e:
        raise EncryptionError(f"Failed to decrypt data: {e}")


def encrypt_with_password(
    data: str, password: str, salt: Optional[bytes] = None
) -> Tuple[str, bytes, bytes]:
    """Encrypt data with a password.

    Args:
        data: The data to encrypt.
        password: The password to use.
        salt: Optional salt for key derivation.

    Returns:
        Tuple of (base64-encoded ciphertext, salt, nonce).

    Raises:
        EncryptionError: If encryption fails.
    """
    # Generate key
    key, salt = generate_key(password, salt)

    # Encrypt data
    ciphertext, nonce = encrypt(data, key)

    # Encode ciphertext
    encoded = base64.b64encode(ciphertext).decode()

    return encoded, salt, nonce


def decrypt_with_password(
    encoded: str, password: str, salt: bytes, nonce: bytes
) -> str:
    """Decrypt data with a password.

    Args:
        encoded: Base64-encoded ciphertext.
        password: The password to use.
        salt: Salt used for key derivation.
        nonce: Nonce used for encryption.

    Returns:
        Decrypted string.

    Raises:
        EncryptionError: If decryption fails.
    """
    # Decode ciphertext
    ciphertext = base64.b64decode(encoded)

    # Generate key
    key, _ = generate_key(password, salt)

    # Decrypt data
    return decrypt(ciphertext, key, nonce)
