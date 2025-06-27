"""Linux credential storage using libsecret."""

import json
import os
import subprocess
from datetime import datetime
from typing import Optional
from uuid import UUID

from .base import (
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialStore,
    CredentialStoreError,
    SecureCredential,
)


class LinuxSecureCredential:
    """Secure credential implementation for Linux."""

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

    def __enter__(self) -> "LinuxSecureCredential":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.clear()


class LibSecretStore(CredentialStore):
    """Credential store implementation using libsecret."""

    def __init__(self):
        """Initialize the store."""
        self._check_libsecret()
        self._metadata_dir = os.path.expanduser("~/.config/perihelion/credentials")
        os.makedirs(self._metadata_dir, mode=0o700, exist_ok=True)

    def _check_libsecret(self) -> None:
        """Check if libsecret is available."""
        try:
            subprocess.run(
                ["secret-tool", "search", "dummy", "dummy"],
                capture_output=True,
                check=False,
            )
        except FileNotFoundError:
            raise CredentialStoreError(
                "libsecret not found. Please install libsecret-tools."
            )

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
        os.chmod(path, 0o600)

    def store_credential(
        self, credential: str, metadata: CredentialMetadata
    ) -> None:
        """Store a credential using libsecret."""
        try:
            # Store the credential
            subprocess.run(
                [
                    "secret-tool",
                    "store",
                    "--label",
                    f"Perihelion: {metadata.platform} - {metadata.username}",
                    "credential_id",
                    str(metadata.credential_id),
                ],
                input=credential.encode(),
                check=True,
            )

            # Store metadata
            self._write_metadata(metadata)

        except subprocess.CalledProcessError as e:
            raise CredentialStoreError(f"Failed to store credential: {e}")

    def get_credential(self, credential_id: UUID) -> SecureCredential:
        """Retrieve a credential using libsecret."""
        try:
            # Verify metadata exists
            self._read_metadata(credential_id)

            # Retrieve credential
            result = subprocess.run(
                [
                    "secret-tool",
                    "lookup",
                    "credential_id",
                    str(credential_id),
                ],
                capture_output=True,
                check=True,
            )

            return LinuxSecureCredential(result.stdout.decode().strip())

        except subprocess.CalledProcessError as e:
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
            # Delete from libsecret
            subprocess.run(
                [
                    "secret-tool",
                    "clear",
                    "credential_id",
                    str(credential_id),
                ],
                check=True,
            )

            # Delete metadata
            os.unlink(self._get_metadata_path(credential_id))

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
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
