"""Secure key management utilities."""

import json
import os
import platform
from pathlib import Path
from typing import Dict, Optional
from uuid import UUID

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .encryption import EncryptionError
from .memory import secure_zero_memory


class KeyStore:
    """Secure key storage and management."""

    def __init__(self, root_dir: Optional[Path] = None):
        """Initialize the key store.

        Args:
            root_dir: Optional root directory for key storage.
                     If None, uses platform-specific default.
        """
        if root_dir is None:
            root_dir = self._get_default_root()
        self.root_dir = root_dir
        self.keys_dir = root_dir / "keys"
        self.meta_dir = root_dir / "metadata"

        # Create directories with secure permissions
        os.makedirs(self.keys_dir, mode=0o700, exist_ok=True)
        os.makedirs(self.meta_dir, mode=0o700, exist_ok=True)

    def _get_default_root(self) -> Path:
        """Get platform-specific default root directory."""
        system = platform.system().lower()
        if system == "windows":
            base = Path.home() / "AppData/Local/Perihelion"
        elif system == "darwin":
            base = Path.home() / "Library/Application Support/Perihelion"
        else:  # Linux and others
            base = Path.home() / ".local/share/perihelion"
        return base / "keys"

    def _derive_key(self, master_key: str, salt: bytes) -> bytes:
        """Derive a key from the master key."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(master_key.encode())

    def store_key(
        self, key_id: UUID, key_data: bytes, master_key: str, metadata: Dict
    ) -> None:
        """Store a key securely.

        Args:
            key_id: UUID for the key.
            key_data: The key data to store.
            master_key: Master key for encryption.
            metadata: Key metadata.

        Raises:
            EncryptionError: If key storage fails.
        """
        try:
            # Generate salt and derive key
            salt = os.urandom(16)
            derived_key = self._derive_key(master_key, salt)

            # Create Fernet cipher
            f = Fernet(base64.b64encode(derived_key))

            # Encrypt key data
            encrypted = f.encrypt(key_data)

            # Store encrypted key
            key_path = self.keys_dir / f"{key_id}.key"
            with open(key_path, "wb") as f:
                f.write(salt + encrypted)
            os.chmod(key_path, 0o600)

            # Store metadata
            meta_path = self.meta_dir / f"{key_id}.json"
            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)
            os.chmod(meta_path, 0o600)

        except Exception as e:
            raise EncryptionError(f"Failed to store key: {e}") from e
        finally:
            # Clear sensitive data
            if "derived_key" in locals():
                secure_zero_memory(derived_key)

    def get_key(self, key_id: UUID, master_key: str) -> bytes:
        """Retrieve a key securely.

        Args:
            key_id: UUID of the key to retrieve.
            master_key: Master key for decryption.

        Returns:
            The decrypted key data.

        Raises:
            EncryptionError: If key retrieval fails.
            FileNotFoundError: If key doesn't exist.
        """
        try:
            # Read encrypted key
            key_path = self.keys_dir / f"{key_id}.key"
            with open(key_path, "rb") as f:
                data = f.read()

            # Extract salt and ciphertext
            salt = data[:16]
            encrypted = data[16:]

            # Derive key
            derived_key = self._derive_key(master_key, salt)

            # Create Fernet cipher
            f = Fernet(base64.b64encode(derived_key))

            # Decrypt key data
            return f.decrypt(encrypted)

        except FileNotFoundError:
            raise
        except Exception as e:
            raise EncryptionError(f"Failed to retrieve key: {e}") from e
        finally:
            # Clear sensitive data
            if "derived_key" in locals():
                secure_zero_memory(derived_key)

    def delete_key(self, key_id: UUID) -> None:
        """Delete a key and its metadata.

        Args:
            key_id: UUID of the key to delete.
        """
        # Delete key file
        key_path = self.keys_dir / f"{key_id}.key"
        try:
            os.unlink(key_path)
        except FileNotFoundError:
            pass

        # Delete metadata
        meta_path = self.meta_dir / f"{key_id}.json"
        try:
            os.unlink(meta_path)
        except FileNotFoundError:
            pass

    def get_metadata(self, key_id: UUID) -> Dict:
        """Get key metadata.

        Args:
            key_id: UUID of the key.

        Returns:
            Key metadata dictionary.

        Raises:
            FileNotFoundError: If metadata doesn't exist.
        """
        meta_path = self.meta_dir / f"{key_id}.json"
        with open(meta_path, "r") as f:
            return json.load(f)

    def update_metadata(self, key_id: UUID, metadata: Dict) -> None:
        """Update key metadata.

        Args:
            key_id: UUID of the key.
            metadata: New metadata dictionary.

        Raises:
            FileNotFoundError: If key doesn't exist.
        """
        # Verify key exists
        key_path = self.keys_dir / f"{key_id}.key"
        if not key_path.exists():
            raise FileNotFoundError(f"Key not found: {key_id}")

        # Update metadata
        meta_path = self.meta_dir / f"{key_id}.json"
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        os.chmod(meta_path, 0o600)

    def list_keys(self) -> Dict[UUID, Dict]:
        """List all stored keys and their metadata.

        Returns:
            Dictionary mapping key IDs to metadata.
        """
        keys = {}
        for meta_file in self.meta_dir.glob("*.json"):
            key_id = UUID(meta_file.stem)
            try:
                metadata = self.get_metadata(key_id)
                keys[key_id] = metadata
            except (json.JSONDecodeError, FileNotFoundError):
                continue
        return keys
