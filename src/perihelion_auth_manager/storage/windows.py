"""Windows credential storage using Windows Credential Manager."""

import json
import os
from datetime import datetime
from typing import Optional
from uuid import UUID

import keyring
from keyring.errors import PasswordDeleteError

from .base import (
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialStore,
    CredentialStoreError,
    SecureCredential,
)


class WindowsSecureCredential:
    """Secure credential implementation for Windows."""

    def __init__(self, secret: str):
        """Initialize with secret value."""
        self._secret = secret
        self._cleared = False

    def get_secret(self) -> str:
        """Get the secret value securely."""
        if self._cleared:
            raise CredentialStoreError("Credential has been cleared")
        return self._secret

    def clear(self) -> None:
        """Clear the secret from memory."""
        if not self._cleared:
            self._secret = ""
            self._cleared = True

    def __enter__(self) -> "WindowsSecureCredential":
        """Context manager entry."""
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
            raise CredentialStoreError(f"Failed to retrieve credential: {e}")

    def list_credentials(
        self, platform: Optional[str] = None, username: Optional[str] = None
    ) -> list[CredentialMetadata]:
        """List stored credentials."""
        try:
            credentials = []
            for filename in os.listdir(self._metadata_dir):
                if not filename.endswith(".json"):
                    continue

                credential_id = UUID(filename[:-5])
                metadata = self._read_metadata(credential_id)

                if platform and metadata.platform != platform:
                    continue
                if username and metadata.username != username:
                    continue

                credentials.append(metadata)

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
            raise CredentialStoreError(f"Failed to delete credential: {e}")

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
