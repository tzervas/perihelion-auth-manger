"""Command-line interface for Perihelion Auth-Manager."""

import click
import base64
import os
import uuid
from typing import List, Optional

from perihelion_auth_manager.audit import audit_event, EventType
from perihelion_auth_manager.crypto import KeyStore
from perihelion_auth_manager.storage import get_platform_store


@click.group()
@click.version_option()
def cli() -> None:
    """Perihelion Auth-Manager CLI"""


@cli.command()
@click.option("--username", prompt=True, help="Username for credentials.")
@click.password_option(help="Password for encryption.")
@click.option("--description", default="", help="Credential description.")
@click.option("--labels", multiple=True, help="Key-value labels.")
def add_credential(
    username: str, password: str, description: str, labels: Optional[List[str]]
) -> None:
    """Add a new credential."""
    # Convert labels to dict
    label_dict = dict(label.split("=") for label in labels)

    # Generate random credential data
    credential_data = base64.b64encode(os.urandom(32)).decode()

    # Create credential metadata
    metadata = {
        "platform": "example-platform",
        "username": username,
        "description": description,
        "labels": label_dict,
    }

    credential_id = uuid.uuid4()
    store = get_platform_store()

    try:
        # Store credential
        store.store_credential(credential_data, credential_id, metadata)
        audit_event(EventType.CRED_CREATE, username, True, {"credential_id": str(credential_id)})
        click.echo(f"Credential {credential_id} added for {username}.")
    except Exception as e:
        audit_event(EventType.CRED_CREATE, username, False, {"credential_id": str(credential_id)}, e)
        click.echo(f"Error adding credential: {e}", err=True)


@cli.command()
@click.option("--key-id", prompt=True, help="Key ID for retrieval.")
@click.password_option(help="Password for decryption.")
def get_key(key_id: str, password: str) -> None:
    """Retrieve a stored key."""
    store = KeyStore()

    try:
        # Retrieve key
        key = store.get_key(uuid.UUID(key_id), password)
        click.echo(f"Key: {base64.b64encode(key).decode()}")
    except Exception as e:
        audit_event(EventType.KEY_IMPORT, key_id, False, {}, e)
        click.echo(f"Error retrieving key: {e}", err=True)


@cli.command(name="list")
@click.option("--platform", default=None, help="Filter by platform.")
@click.option("--username", default=None, help="Filter by username.")
def list_credentials(platform: Optional[str], username: Optional[str]) -> None:
    """List stored credentials."""
    store = get_platform_store()
    creds = store.list_credentials(platform, username)

    if not creds:
        click.echo("No credentials found.")
        return

    for cred in creds:
        click.echo(f"ID: {cred.credential_id}, Username: {cred.username}, Platform: {cred.platform}")


@cli.command()
@click.option("--key-id", prompt=True, help="Key ID for deletion.")
@click.confirmation_option(prompt="Are you sure you want to delete this key?")
def delete_key(key_id: str) -> None:
    """Delete a stored key."""
    store = KeyStore()

    try:
        store.delete_key(uuid.UUID(key_id))
        audit_event(EventType.KEY_DELETE, key_id, True)
        click.echo(f"Key {key_id} deleted.")
    except Exception as e:
        audit_event(EventType.KEY_DELETE, key_id, False, {}, e)
        click.echo(f"Error deleting key: {e}", err=True)


@cli.command()
@click.option("--key-id", prompt=True, help="Key ID for metadata update.")
@click.option("--description", prompt=True, help="New description.")
@click.option("--labels", multiple=True, help="New key-value labels.")
def update_key_metadata(key_id: str, description: str, labels: Optional[List[str]]) -> None:
    """Update key metadata."""
    store = KeyStore()
    label_dict = dict(label.split("=") for label in labels)

    try:
        store.update_metadata(uuid.UUID(key_id), {"description": description, "labels": label_dict})
        audit_event(EventType.KEY_ROTATE, key_id, True)
        click.echo(f"Metadata for key {key_id} updated.")
    except Exception as e:
        audit_event(EventType.KEY_ROTATE, key_id, False, {}, e)
        click.echo(f"Error updating metadata: {e}", err=True)


if __name__ == "__main__":
    cli()
