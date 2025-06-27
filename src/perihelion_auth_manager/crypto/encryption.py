"""Secure encryption layer for credential data."""

import base64
import os
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionError(Exception):
    """Base exception for encryption operations."""


def generate_key(
    password: str, salt: Optional[bytes] = None, iterations: int = 100_000
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

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )

        key = kdf.derive(password.encode())
        return key, salt

    except Exception as e:
        raise EncryptionError(f"Failed to generate key: {e}")


def encrypt(data: str, key: bytes) -> Tuple[bytes, bytes]:
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
        # Generate nonce
        nonce = os.urandom(12)

        # Create cipher
        cipher = Cipher(
            algorithms.AES256(key),
            modes.GCM(nonce),
        )
        encryptor = cipher.encryptor()

        # Add padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()

        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return ciphertext + encryptor.tag, nonce

    except Exception as e:
        raise EncryptionError(f"Failed to encrypt data: {e}")


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> str:
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
        # Split ciphertext and tag
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

        # Create cipher
        cipher = Cipher(
            algorithms.AES256(key),
            modes.GCM(nonce, tag),
        )
        decryptor = cipher.decryptor()

        # Decrypt
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode()

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
