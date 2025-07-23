"""Command-line interface for Perihelion Auth-Manager."""

import base64
import os
import uuid
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar, cast

import click

from perihelion_auth_manager.audit import EventType, audit_event
from perihelion_auth_manager.crypto import EncryptionError, KeyStore
from perihelion_auth_manager.storage import (
    CredentialNotFoundError,
    CredentialStoreError,
    get_platform_store,
)

# Type definitions for Click decorators
P = ParamSpec("P")
T = TypeVar("T")
ClickDecorator = Callable[[Callable[P, T]], Callable[P, T]]
ClickOptionDecorator = Callable[..., ClickDecorator]


def typed_command() -> ClickDecorator:
    """Create a typed Click command decorator."""
    return cast(ClickDecorator, click.command())


def typed_option(
    param_name: str,
    *,
    prompt: bool = False,
    help_text: str = "",
    **kwargs: Any,
) -> ClickDecorator:
    """Create a typed Click option decorator.
    
    Args:
        param_name: The parameter name/flag
        prompt: Whether to prompt for input
        help: Help text for the option
        **kwargs: Additional Click option parameters
    """
    return cast(
        ClickDecorator,
        click.option(param_name, prompt=prompt, help=help_text, **kwargs)
    )


def typed_password_option(
    *,
    help_text: str = "",
    **kwargs: Any,
) -> ClickDecorator:
    """Create a typed Click password option decorator.
    
    Args:
        help: Help text for the option
        **kwargs: Additional Click option parameters
    """
    return cast(ClickDecorator, click.password_option(help=help_text, **kwargs))


@click.group()
@click.version_option()
def cli() -> None:
    """Perihelion Auth-Manager CLI."""


@cli.command()
@typed_option("--username", prompt=True, help="Username for credentials.")
@typed_password_option(help="Password for encryption.")
@typed_option("--description", default="", help="Credential description.")
@typed_option("--labels", multiple=True, help="Key-value labels (key=value).")
def add_credential(
    username: str,
    password: str,
    description: str,
    labels: list[str] | None = None,
) -> None:
    """Add a new credential."""
    labels = labels or []
    try:
        label_dict = dict(label.split("=", 1) for label in labels)
    except ValueError:
        click.echo("Error: Labels must be in key=value format.", err=True)
        return

    credential_data = base64.b64encode(os.urandom(32)).decode()
    metadata = {
        "platform": "example-platform",
        "username": username,
        "description": description,
        "labels": label_dict,
    }

    credential_id = uuid.uuid4()
    store = get_platform_store()

    try:
        store.store_credential(credential_data, credential_id, metadata)
        audit_event(
            EventType.CRED_CREATE,
            username,
            success=True,
            details={"credential_id": str(credential_id)},
        )
        click.echo(f"Credential {credential_id} added for {username}.")
    except (CredentialStoreError, EncryptionError) as e:
        audit_event(
            EventType.CRED_CREATE,
            username,
            success=False,
            details={"credential_id": str(credential_id)},
            error=e,
        )
        click.echo(f"Error storing credential: {e}", err=True)
    except ValueError as e:
        audit_event(
            EventType.CRED_CREATE,
            username,
            success=False,
            details={"credential_id": str(credential_id)},
            error=e,
        )
        click.echo(f"Invalid credential data: {e}", err=True)


@cli.command()
@typed_option("--key-id", prompt=True, help="Key ID for retrieval.")
@typed_password_option(help="Password for decryption.")
def get_key(key_id: str, password: str) -> None:
    """Retrieve a stored key."""
    store = KeyStore()
    try:
        key = store.get_key(uuid.UUID(key_id), password)
        click.echo(f"Key: {base64.b64encode(key).decode()}")
    except CredentialNotFoundError as e:
        audit_event(EventType.KEY_IMPORT, key_id, success=False, details={}, error=e)
        click.echo(f"Key not found: {key_id}", err=True)
    except (CredentialStoreError, EncryptionError) as e:
        audit_event(EventType.KEY_IMPORT, key_id, success=False, details={}, error=e)
        click.echo(f"Error retrieving key: {e}", err=True)
    except ValueError as e:
        audit_event(EventType.KEY_IMPORT, key_id, success=False, details={}, error=e)
        click.echo(f"Invalid key ID format: {e}", err=True)


@cli.command(name="list")
@typed_option("--platform", default=None, help="Filter by platform.")
@typed_option("--username", default=None, help="Filter by username.")
def list_credentials(platform: str | None = None, username: str | None = None) -> None:
    """List stored credentials."""
    store = get_platform_store()
    credentials = store.list_credentials(platform, username)

    if not credentials:
        click.echo("No credentials found.")
        return

    for cred in credentials:
        click.echo(
            f"ID: {cred.credential_id}, "
            f"Username: {cred.username}, "
            f"Platform: {cred.platform}"
        )


@cli.command()
@typed_option("--key-id", prompt=True, help="Key ID for deletion.")
@click.confirmation_option(prompt="Are you sure you want to delete this key?")
def delete_key(key_id: str) -> None:
    """Delete a stored key."""
    store = KeyStore()
    try:
        store.delete_key(uuid.UUID(key_id))
        audit_event(EventType.KEY_DELETE, key_id, success=True)
        click.echo(f"Key {key_id} deleted.")
    except CredentialNotFoundError:
        # Silently succeed if key doesn't exist
        audit_event(EventType.KEY_DELETE, key_id, success=True)
        click.echo(f"Key {key_id} deleted.")
    except (CredentialStoreError, EncryptionError) as e:
        audit_event(EventType.KEY_DELETE, key_id, success=False, details={}, error=e)
        click.echo(f"Error deleting key: {e}", err=True)
    except ValueError as e:
        audit_event(EventType.KEY_DELETE, key_id, success=False, details={}, error=e)
        click.echo(f"Invalid key ID format: {e}", err=True)


@cli.command()
@typed_option("--key-id", prompt=True, help="Key ID for metadata update.")
@typed_option("--description", prompt=True, help="New description.")
@typed_option("--labels", multiple=True, help="New key-value labels (key=value).")
def update_key_metadata(
    key_id: str,
    description: str,
    labels: list[str] | None = None,
) -> None:
    """Update key metadata."""
    store = KeyStore()
    labels = labels or []
    try:
        label_dict = dict(label.split("=", 1) for label in labels)
    except ValueError:
        click.echo("Error: Labels must be in key=value format.", err=True)
        return

    try:
        store.update_metadata(
            uuid.UUID(key_id), {"description": description, "labels": label_dict}
        )
        audit_event(EventType.KEY_ROTATE, key_id, success=True)
        click.echo(f"Metadata for key {key_id} updated.")
    except CredentialNotFoundError as e:
        audit_event(EventType.KEY_ROTATE, key_id, success=False, details={}, error=e)
        click.echo(f"Key not found: {key_id}", err=True)
    except (CredentialStoreError, EncryptionError) as e:
        audit_event(EventType.KEY_ROTATE, key_id, success=False, details={}, error=e)
        click.echo(f"Error updating metadata: {e}", err=True)
    except ValueError as e:
        audit_event(EventType.KEY_ROTATE, key_id, success=False, details={}, error=e)
        click.echo(f"Invalid key ID format: {e}", err=True)


if __name__ == "__main__":
    cli()
