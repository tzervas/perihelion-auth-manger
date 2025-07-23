"""Tests for the CLI interface."""

import json
import uuid
from unittest.mock import Mock, patch

import click.testing
import pytest

from perihelion_auth_manager.cli import cli


@pytest.fixture
def cli_runner():
    """Create a CLI test runner."""
    return click.testing.CliRunner()


@pytest.fixture
def mock_store():
    """Create a mock credential store."""
    with patch("perihelion_auth_manager.cli.get_platform_store") as mock:
        yield mock.return_value


@pytest.fixture
def mock_keystore():
    """Create a mock key store."""
    with patch("perihelion_auth_manager.cli.KeyStore") as mock:
        yield mock.return_value


def test_add_credential(cli_runner, mock_store):
    """Test adding a credential."""
    result = cli_runner.invoke(
        cli,
        ["add-credential", "--username", "test-user", "--password", "test-pass"],
        input="test-pass\n",
    )
    assert result.exit_code == 0
    assert "added for test-user" in result.output
    mock_store.store_credential.assert_called_once()


def test_add_credential_with_labels(cli_runner, mock_store):
    """Test adding a credential with labels."""
    result = cli_runner.invoke(
        cli,
        [
            "add-credential",
            "--username",
            "test-user",
            "--password",
            "test-pass",
            "--labels",
            "env=prod",
            "--labels",
            "team=security",
        ],
        input="test-pass\n",
    )
    assert result.exit_code == 0
    assert "added for test-user" in result.output

    # Verify labels were properly converted
    metadata = mock_store.store_credential.call_args[0][2]
    assert metadata["labels"] == {"env": "prod", "team": "security"}


def test_add_credential_error(cli_runner, mock_store):
    """Test error handling when adding a credential."""
    mock_store.store_credential.side_effect = Exception("Test error")
    result = cli_runner.invoke(
        cli,
        ["add-credential", "--username", "test-user", "--password", "test-pass"],
        input="test-pass\n",
    )
    assert result.exit_code == 0  # Click doesn't propagate exceptions by default
    assert "Error adding credential" in result.output


def test_get_key(cli_runner, mock_keystore):
    """Test retrieving a key."""
    key_id = str(uuid.uuid4())
    mock_keystore.get_key.return_value = b"test-key-data"

    result = cli_runner.invoke(
        cli,
        ["get-key", "--key-id", key_id, "--password", "test-pass"],
        input="test-pass\n",
    )
    assert result.exit_code == 0
    mock_keystore.get_key.assert_called_once_with(uuid.UUID(key_id), "test-pass")


def test_get_key_error(cli_runner, mock_keystore):
    """Test error handling when retrieving a key."""
    key_id = str(uuid.uuid4())
    mock_keystore.get_key.side_effect = Exception("Test error")

    result = cli_runner.invoke(
        cli,
        ["get-key", "--key-id", key_id, "--password", "test-pass"],
        input="test-pass\n",
    )
    assert "Error retrieving key" in result.output


def test_list_credentials(cli_runner, mock_store):
    """Test listing credentials."""
    mock_cred = Mock()
    mock_cred.credential_id = uuid.uuid4()
    mock_cred.username = "test-user"
    mock_cred.platform = "test-platform"
    mock_store.list_credentials.return_value = [mock_cred]

    result = cli_runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert str(mock_cred.credential_id) in result.output
    assert mock_cred.username in result.output
    assert mock_cred.platform in result.output


def test_list_credentials_empty(cli_runner, mock_store):
    """Test listing when no credentials exist."""
    mock_store.list_credentials.return_value = []
    result = cli_runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "No credentials found" in result.output


def test_list_credentials_filtered(cli_runner, mock_store):
    """Test listing credentials with filters."""
    result = cli_runner.invoke(
        cli, ["list", "--platform", "github", "--username", "test-user"]
    )
    assert result.exit_code == 0
    mock_store.list_credentials.assert_called_once_with("github", "test-user")


def test_delete_key(cli_runner, mock_keystore):
    """Test deleting a key."""
    key_id = str(uuid.uuid4())
    result = cli_runner.invoke(cli, ["delete-key", "--key-id", key_id], input="y\n")
    assert result.exit_code == 0
    assert "deleted" in result.output
    mock_keystore.delete_key.assert_called_once_with(uuid.UUID(key_id))


def test_delete_key_abort(cli_runner, mock_keystore):
    """Test aborting key deletion."""
    key_id = str(uuid.uuid4())
    result = cli_runner.invoke(cli, ["delete-key", "--key-id", key_id], input="n\n")
    assert result.exit_code == 0
    assert "Aborted" in result.output
    mock_keystore.delete_key.assert_not_called()


def test_update_key_metadata(cli_runner, mock_keystore):
    """Test updating key metadata."""
    key_id = str(uuid.uuid4())
    result = cli_runner.invoke(
        cli,
        [
            "update-key-metadata",
            "--key-id",
            key_id,
            "--description",
            "Updated description",
            "--labels",
            "env=prod",
        ],
    )
    assert result.exit_code == 0
    assert "updated" in result.output

    # Verify metadata update
    expected_metadata = {
        "description": "Updated description",
        "labels": {"env": "prod"},
    }
    mock_keystore.update_metadata.assert_called_once_with(
        uuid.UUID(key_id), expected_metadata
    )
