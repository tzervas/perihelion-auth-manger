"""Base interfaces and types for credential storage."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Optional, Protocol, runtime_checkable
from uuid import UUID

from cryptography.fernet import Fernet
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)


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
        """Clear the secret from memory.
        
        This must ensure the secret is securely wiped from memory
        using techniques like overwriting with zeros.
        """
        ...

    def secure_memory(self) -> None:
        """Implement secure memory protections.
        
        This should:
        1. Lock memory pages to prevent swapping
        2. Mark memory as non-readable/non-writable when not in use
        3. Apply memory sanitization on clear
        """
        ...

    def __enter__(self) -> "SecureCredential":
        """Context manager entry.
        
        Automatically applies secure memory protections.
        """
        self.secure_memory()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit.
        
        Automatically clears secret and releases memory protections.
        """
        self.clear()


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
        logger.info(
            "storing_credential",
            credential_id=str(metadata.credential_id),
            platform=metadata.platform,
            username=metadata.username,
            scope=metadata.scope,
        )
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
        self,
        platform: Optional[str] = None,
        username: Optional[str] = None,
        attributes: Optional[Dict[str, str]] = None,
    ) -> list[CredentialMetadata]:
        """List stored credential metadata.

        Args:
            platform: Optional platform filter.
            username: Optional username filter.
            attributes: Optional attribute-based filters matching metadata labels.

        Returns:
            List of credential metadata.
        """
        logger.debug(
            "listing_credentials",
            platform=platform,
            username=username,
            attributes=attributes,
        )
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
        logger.info(
            "deleting_credential",
            credential_id=str(credential_id),
        )
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
