"""Tests for cryptographic utilities."""

import os
import platform
import tempfile
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from perihelion_auth_manager.crypto import (
    EncryptionError,
    KeyStore,
    compare_bytes,
    decrypt,
    decrypt_with_password,
    encrypt,
    encrypt_with_password,
    generate_key,
    secure_memory,
    secure_string,
    secure_zero_memory,
)


def test_generate_key():
    """Test key generation."""
    # Generate key with new salt
    key1, salt1 = generate_key("test-password")
    assert len(key1) == 32
    assert len(salt1) == 16

    # Generate key with existing salt
    key2, salt2 = generate_key("test-password", salt1)
    assert key2 == key1
    assert salt2 == salt1


def test_encryption():
    """Test encryption and decryption."""
    # Generate key
    key = os.urandom(32)
    data = "test-data"

    # Encrypt
    ciphertext, nonce = encrypt(data, key)
    assert len(nonce) == 12

    # Decrypt
    decrypted = decrypt(ciphertext, key, nonce)
    assert decrypted == data


def test_password_encryption():
    """Test password-based encryption."""
    # Encrypt with password
    data = "test-data"
    password = "test-password"

    # Encrypt
    encrypted, salt, nonce = encrypt_with_password(data, password)

    # Decrypt
    decrypted = decrypt_with_password(encrypted, password, salt, nonce)
    assert decrypted == data


def test_encryption_error():
    """Test encryption error handling."""
    with pytest.raises(EncryptionError):
        encrypt("test", b"invalid-key")

    with pytest.raises(EncryptionError):
        decrypt(b"invalid", b"invalid-key", b"invalid-nonce")


def test_secure_memory():
    """Test secure memory handling."""
    data = b"sensitive-data"
    written = False

    with secure_memory() as mem:
        # Write data
        mem.write(data)
        written = True

        # Read data
        mem.seek(0)
        assert mem.read(len(data)) == data

    # Memory should be cleared
    assert not written or mem.closed


def test_secure_string():
    """Test secure string handling."""
    with secure_string() as buf:
        # Write data
        buf.extend(b"sensitive-data")
        assert bytes(buf) == b"sensitive-data"

    # Buffer should be cleared
    assert all(b == 0 for b in buf)


def test_secure_zero_memory():
    """Test secure memory zeroing."""
    data = bytearray(b"sensitive-data")
    secure_zero_memory(data)
    assert all(b == 0 for b in data)


def test_compare_bytes():
    """Test constant-time byte comparison."""
    a = b"test-data"
    b = b"test-data"
    c = b"different"

    assert compare_bytes(a, b)
    assert not compare_bytes(a, c)
    assert not compare_bytes(a, b"test-data-longer")


class TestKeyStore:
    """Tests for KeyStore functionality."""

    @pytest.fixture
    def store(self):
        """Create a temporary key store."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield KeyStore(Path(tmpdir))

    def test_store_and_retrieve(self, store):
        """Test storing and retrieving keys."""
        # Create test data
        key_id = uuid4()
        key_data = os.urandom(32)
        master_key = "test-master-key"
        metadata = {
            "created": datetime.utcnow().isoformat(),
            "description": "Test key",
        }

        # Store key
        store.store_key(key_id, key_data, master_key, metadata)

        # Retrieve key
        retrieved = store.get_key(key_id, master_key)
        assert retrieved == key_data

        # Check metadata
        retrieved_meta = store.get_metadata(key_id)
        assert retrieved_meta == metadata

    def test_key_not_found(self, store):
        """Test handling of non-existent keys."""
        with pytest.raises(FileNotFoundError):
            store.get_key(uuid4(), "test-key")

    def test_delete_key(self, store):
        """Test key deletion."""
        # Store key
        key_id = uuid4()
        store.store_key(
            key_id,
            os.urandom(32),
            "test-master-key",
            {"description": "Test key"},
        )

        # Delete key
        store.delete_key(key_id)

        # Verify deletion
        with pytest.raises(FileNotFoundError):
            store.get_key(key_id, "test-master-key")

    def test_update_metadata(self, store):
        """Test metadata updates."""
        # Store key
        key_id = uuid4()
        store.store_key(
            key_id,
            os.urandom(32),
            "test-master-key",
            {"description": "Test key"},
        )

        # Update metadata
        new_metadata = {"description": "Updated key"}
        store.update_metadata(key_id, new_metadata)

        # Verify update
        retrieved = store.get_metadata(key_id)
        assert retrieved == new_metadata

    def test_list_keys(self, store):
        """Test key listing."""
        # Store multiple keys
        keys = {}
        for i in range(3):
            key_id = uuid4()
            metadata = {"description": f"Test key {i}"}
            store.store_key(key_id, os.urandom(32), "test-master-key", metadata)
            keys[key_id] = metadata

        # List keys
        listed = store.list_keys()
        assert listed == keys

    def test_secure_permissions(self, store):
        """Test secure file permissions."""
        if platform.system() == "Windows":
            pytest.skip("Permission tests not applicable on Windows")

        # Store a key
        key_id = uuid4()
        store.store_key(
            key_id,
            os.urandom(32),
            "test-master-key",
            {"description": "Test key"},
        )

        # Check permissions
        key_path = store.keys_dir / f"{key_id}.key"
        meta_path = store.meta_dir / f"{key_id}.json"

        assert oct(os.stat(store.keys_dir).st_mode).endswith("700")
        assert oct(os.stat(store.meta_dir).st_mode).endswith("700")
        assert oct(os.stat(key_path).st_mode).endswith("600")
        assert oct(os.stat(meta_path).st_mode).endswith("600")
