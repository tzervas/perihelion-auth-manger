"""Windows credential storage using Windows Credential Manager."""

import ctypes
import json
import os
from datetime import datetime
from typing import Optional
from uuid import UUID

import keyring
from keyring.errors import PasswordDeleteError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import structlog

logger = structlog.get_logger(__name__)

# Windows API constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_NOACCESS = 0x01
MEM_RELEASE = 0x8000

from .base import (
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialStore,
    CredentialStoreError,
    SecureCredential,
)


def secure_zero_memory(ptr: int, size: int) -> None:
    """Securely zero memory using Windows APIs."""
    try:
        ctypes.windll.kernel32.RtlSecureZeroMemory(ptr, size)
    except Exception as e:
        logger.error("failed_to_zero_memory", error=str(e))


class WindowsSecureCredential:
    """Secure credential implementation for Windows."""

    def __init__(self, secret: str):
        """Initialize with secret value."""
        self._secret = secret.encode()
        self._cleared = False
        self._protected = False
        self._ptr = None
        
        # Allocate secure memory
        size = len(self._secret)
        self._ptr = ctypes.windll.kernel32.VirtualAlloc(
            None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
        if not self._ptr:
            raise CredentialStoreError("Failed to allocate secure memory")
            
        # Copy secret to secure memory
        ctypes.memmove(self._ptr, self._secret, size)
        self._size = size

    def get_secret(self) -> str:
        """Get the secret value securely."""
        if self._cleared:
            raise CredentialStoreError("Credential has been cleared")
            
        if self._protected and not ctypes.windll.kernel32.VirtualProtect(
                        self._ptr, self._size, PAGE_READWRITE, ctypes.byref(ctypes.c_ulong())
                    ):
            raise CredentialStoreError("Failed to unprotect memory")

                
        try:
            # Read secret from secure memory
            secret = ctypes.string_at(self._ptr, self._size)
            return secret.decode()
        finally:
            if self._protected:
                # Restore protection
                ctypes.windll.kernel32.VirtualProtect(
                    self._ptr, self._size, PAGE_NOACCESS, ctypes.byref(ctypes.c_ulong())
                )

    def clear(self) -> None:
        """Clear the secret from memory."""
        if not self._cleared:
            if self._ptr:
                # Make memory writable
                if self._protected:
                    ctypes.windll.kernel32.VirtualProtect(
                        self._ptr, self._size, PAGE_READWRITE, ctypes.byref(ctypes.c_ulong())
                    )
                
                # Securely zero memory
                secure_zero_memory(self._ptr, self._size)
                
                # Free memory
                ctypes.windll.kernel32.VirtualFree(self._ptr, 0, MEM_RELEASE)
                
            self._secret = b""
            self._ptr = None
            self._cleared = True
            logger.debug("cleared_secure_credential")

    def secure_memory(self) -> None:
        """Implement secure memory protections."""
        if not self._cleared and not self._protected:
            # Make memory non-readable/non-writable
            if ctypes.windll.kernel32.VirtualProtect(
                self._ptr, self._size, PAGE_NOACCESS, ctypes.byref(ctypes.c_ulong())
            ):
                self._protected = True
                logger.debug("protected_secure_credential")
            else:
                raise CredentialStoreError("Failed to protect memory")
    
    def __enter__(self) -> "WindowsSecureCredential":
        """Context manager entry."""
        self.secure_memory()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.clear()


class WindowsCredentialStore(CredentialStore):
    """Credential store implementation using Windows Credential Manager."""

    def __init__(self):
        """Initialize the store."""
        self._metadata_dir = os.path.expanduser(
            "~/AppData/Local/Perihelion/Credentials"
        )
        os.makedirs(self._metadata_dir, mode=0o700, exist_ok=True)

    def _get_metadata_path(self, credential_id: UUID) -> str:
        """Get the metadata file path for a credential."""
        return os.path.join(self._metadata_dir, f"{credential_id}.json")

    def _read_metadata(self, credential_id: UUID) -> CredentialMetadata:
        """Read metadata from file."""
        path = self._get_metadata_path(credential_id)
        try:
            with open(path, "r") as f:
                data = json.load(f)
                return CredentialMetadata(
                    created_at=datetime.fromisoformat(data["created_at"]),
                    updated_at=datetime.fromisoformat(data["updated_at"]),
                    expires_at=datetime.fromisoformat(data["expires_at"])
                    if data.get("expires_at")
                    else None,
                    description=data["description"],
                    scope=data["scope"],
                    labels=data["labels"],
                    platform=data["platform"],
                    username=data["username"],
                    credential_id=UUID(data["credential_id"]),
                )
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise CredentialNotFoundError(f"Metadata not found: {e}")

    def _write_metadata(self, metadata: CredentialMetadata) -> None:
        """Write metadata to file."""
        path = self._get_metadata_path(metadata.credential_id)
        data = metadata.model_dump()
        data["created_at"] = data["created_at"].isoformat()
        data["updated_at"] = data["updated_at"].isoformat()
        if data["expires_at"]:
            data["expires_at"] = data["expires_at"].isoformat()

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def store_credential(
        self, credential: str, metadata: CredentialMetadata
    ) -> None:
        """Store a credential in Windows Credential Manager."""
        try:
            # Store the credential
            keyring.set_password(
                "perihelion",
                str(metadata.credential_id),
                credential,
            )

            # Store metadata
            self._write_metadata(metadata)

        except Exception as e:
            raise CredentialStoreError(f"Failed to store credential: {e}")

    def get_credential(self, credential_id: UUID) -> SecureCredential:
        """Retrieve a credential from Windows Credential Manager."""
        try:
            # Verify metadata exists
            self._read_metadata(credential_id)

            # Retrieve credential
            credential = keyring.get_password("perihelion", str(credential_id))
            if credential is None:
                raise CredentialNotFoundError(
                    f"Credential not found: {credential_id}"
                )

            return WindowsSecureCredential(credential)

        except Exception as e:
            raise CredentialStoreError(f"Failed to retrieve credential: {e}") from e

    def list_credentials(
        self,
        platform: Optional[str] = None,
        username: Optional[str] = None,
        attributes: Optional[Dict[str, str]] = None,
    ) -> list[CredentialMetadata]:
        """List stored credentials with optional filtering.
        
        Args:
            platform: Optional platform filter
            username: Optional username filter
            attributes: Optional attribute-based filters matching metadata labels
        """
        try:
            credentials = []
            for filename in os.listdir(self._metadata_dir):
                if not filename.endswith(".json"):
                    continue

                credential_id = UUID(filename[:-5])
                metadata = self._read_metadata(credential_id)

                # Apply platform filter
                if platform and metadata.platform != platform:
                    continue
                    
                # Apply username filter
                if username and metadata.username != username:
                    continue
                    
                # Apply attribute filters
                if attributes:
                    matches = True
                    for key, value in attributes.items():
                        if metadata.labels.get(key) != value:
                            matches = False
                            break
                    if not matches:
                        continue

                credentials.append(metadata)
                
            logger.debug(
                "listed_credentials",
                count=len(credentials),
                platform=platform,
                username=username,
                attributes=attributes,
            )
            return credentials

        except Exception as e:
            raise CredentialStoreError(f"Failed to list credentials: {e}")

    def delete_credential(self, credential_id: UUID) -> None:
        """Delete a credential."""
        try:
            # Delete from Windows Credential Manager
            try:
                keyring.delete_password("perihelion", str(credential_id))
            except PasswordDeleteError:
                # Already deleted or doesn't exist
                pass

            # Delete metadata
            try:
                os.unlink(self._get_metadata_path(credential_id))
            except FileNotFoundError:
                pass

        except Exception as e:
            raise CredentialStoreError(f"Failed to delete credential: {e}") from e

    def update_metadata(
        self, credential_id: UUID, metadata: CredentialMetadata
    ) -> None:
        """Update credential metadata."""
        if metadata.credential_id != credential_id:
            raise CredentialStoreError("Credential ID mismatch")

        # Verify credential exists
        self.get_credential(credential_id)

        # Update metadata
        metadata.updated_at = datetime.utcnow()
        self._write_metadata(metadata)
