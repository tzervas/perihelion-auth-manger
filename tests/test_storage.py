"""Tests for credential storage implementations."""

import platform
from datetime import datetime, timedelta
from typing import Type
from uuid import UUID, uuid4

import pytest

from perihelion_auth_manager.storage import (
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialStore,
    LibSecretStore,
    KeychainStore,
    WindowsCredentialStore,
    get_platform_store,
)


@pytest.fixture
def store() -> CredentialStore:
    """Get the appropriate store for the current platform."""
    return get_platform_store()


@pytest.fixture
def metadata() -> CredentialMetadata:
    """Create test credential metadata."""
    return CredentialMetadata(
        platform="github",
        username="test-user",
        description="Test credential",
        scope="repo,read:org",
        labels={"env": "test"},
        expires_at=datetime.utcnow() + timedelta(days=30),
    )


def test_store_and_retrieve(store: CredentialStore, metadata: CredentialMetadata):
    """Test storing and retrieving a credential."""
    # Store credential
    test_secret = "test-secret"
    store.store_credential(test_secret, metadata)

    # Retrieve and verify
    with store.get_credential(metadata.credential_id) as cred:
        assert cred.get_secret() == test_secret

    # Verify metadata
    creds = store.list_credentials(
        platform=metadata.platform, username=metadata.username
    )
    assert len(creds) == 1
    assert creds[0].credential_id == metadata.credential_id
    assert creds[0].platform == metadata.platform
    assert creds[0].username == metadata.username
    assert creds[0].description == metadata.description
    assert creds[0].scope == metadata.scope
    assert creds[0].labels == metadata.labels


def test_credential_not_found(store: CredentialStore):
    """Test handling of non-existent credentials."""
    with pytest.raises(CredentialNotFoundError):
        store.get_credential(uuid4())


def test_update_metadata(store: CredentialStore, metadata: CredentialMetadata):
    """Test updating credential metadata."""
    # Store initial credential
    test_secret = "test-secret"
    store.store_credential(test_secret, metadata)

    # Update metadata
    updated_metadata = metadata.model_copy()
    updated_metadata.description = "Updated description"
    updated_metadata.labels = {"env": "prod"}

    store.update_metadata(metadata.credential_id, updated_metadata)

    # Verify updates
    creds = store.list_credentials(
        platform=metadata.platform, username=metadata.username
    )
    assert len(creds) == 1
    assert creds[0].description == "Updated description"
    assert creds[0].labels == {"env": "prod"}


def test_delete_credential(store: CredentialStore, metadata: CredentialMetadata):
    """Test deleting a credential."""
    # Store credential
    test_secret = "test-secret"
    store.store_credential(test_secret, metadata)

    # Delete credential
    store.delete_credential(metadata.credential_id)

    # Verify deletion
    with pytest.raises(CredentialNotFoundError):
        store.get_credential(metadata.credential_id)

    creds = store.list_credentials(
        platform=metadata.platform, username=metadata.username
    )
    assert len(creds) == 0


def test_secure_credential_clearing(
    store: CredentialStore, metadata: CredentialMetadata
):
    """Test secure credential clearing."""
    # Store credential
    test_secret = "test-secret"
    store.store_credential(test_secret, metadata)

    # Test context manager
    with store.get_credential(metadata.credential_id) as cred:
        assert cred.get_secret() == test_secret

    # Verify cleared after context
    with pytest.raises(Exception):
        cred.get_secret()


def test_platform_store_selection():
    """Test platform-specific store selection."""
    system = platform.system().lower()
    store = get_platform_store()

    if system == "linux":
        assert isinstance(store, LibSecretStore)
    elif system == "darwin":
        assert isinstance(store, KeychainStore)
    elif system == "windows":
        assert isinstance(store, WindowsCredentialStore)
    else:
        pytest.skip("Unsupported platform for testing")
