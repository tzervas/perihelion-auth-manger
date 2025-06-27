"""Base interfaces and types for credential storage."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Optional, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, Field


class CredentialMetadata(BaseModel):
    """Metadata for stored credentials."""

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    description: str = ""
    scope: str = ""
    labels: Dict[str, str] = Field(default_factory=dict)
    platform: str
    username: str
    credential_id: UUID = Field(default_factory=UUID.uuid4)


@runtime_checkable
class SecureCredential(Protocol):
    """Protocol for secure credential objects."""

    def get_secret(self) -> str:
        """Get the secret value securely."""
        ...

    def clear(self) -> None:
        """Clear the secret from memory."""
        ...

    def __enter__(self) -> "SecureCredential":
        """Context manager entry."""
        ...

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        ...


class CredentialStore(ABC):
    """Abstract base class for credential storage backends."""

    @abstractmethod
    def store_credential(
        self, credential: str, metadata: CredentialMetadata
    ) -> None:
        """Store a credential securely.

        Args:
            credential: The credential to store.
            metadata: Associated metadata.

        Raises:
            CredentialStoreError: If storage fails.
        """
        ...

    @abstractmethod
    def get_credential(self, credential_id: UUID) -> SecureCredential:
        """Retrieve a credential by ID.

        Args:
            credential_id: The UUID of the credential.

        Returns:
            A SecureCredential object.

        Raises:
            CredentialNotFoundError: If credential doesn't exist.
            CredentialStoreError: If retrieval fails.
        """
        ...

    @abstractmethod
    def list_credentials(
        self, platform: Optional[str] = None, username: Optional[str] = None
    ) -> list[CredentialMetadata]:
        """List stored credential metadata.

        Args:
            platform: Optional platform filter.
            username: Optional username filter.

        Returns:
            List of credential metadata.
        """
        ...

    @abstractmethod
    def delete_credential(self, credential_id: UUID) -> None:
        """Delete a credential by ID.

        Args:
            credential_id: The UUID of the credential.

        Raises:
            CredentialNotFoundError: If credential doesn't exist.
            CredentialStoreError: If deletion fails.
        """
        ...

    @abstractmethod
    def update_metadata(
        self, credential_id: UUID, metadata: CredentialMetadata
    ) -> None:
        """Update credential metadata.

        Args:
            credential_id: The UUID of the credential.
            metadata: New metadata.

        Raises:
            CredentialNotFoundError: If credential doesn't exist.
            CredentialStoreError: If update fails.
        """
        ...


class CredentialStoreError(Exception):
    """Base exception for credential store operations."""


class CredentialNotFoundError(CredentialStoreError):
    """Exception raised when a credential is not found."""
