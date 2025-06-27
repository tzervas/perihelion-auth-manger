"""Main CLI implementation."""

import json
import logging
from pathlib import Path
from typing import Optional
from uuid import UUID

import click
import structlog
from rich.console import Console
from rich.table import Table

from ..audit import audit_event, setup_logging
from ..crypto import EncryptionError
from ..storage import (
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialStore,
    CredentialStoreError,
    get_store,
)

# Initialize logger
logger = structlog.get_logger()
console = Console()


def print_table(title: str, rows: list[dict], columns: list[tuple[str, str]]) -> None:
    """Print data in a formatted table.

    Args:
        title: Table title
        rows: List of row dictionaries
        columns: List of (key, header) tuples defining columns
    """
    table = Table(title=title)
    for key, header in columns:
        table.add_column(header, style="cyan")

    for row in rows:
        values = [str(row.get(key, "")) for key, _ in columns]
        table.add_row(*values)

    console.print(table)


@click.group()
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Set logging level",
)
def cli(log_level: str) -> None:
    """Perihelion Auth Manager CLI.

    Secure credential management with OAuth integration.
    """
    # Setup logging
    setup_logging(log_level)


@cli.group()
def credential() -> None:
    """Manage credentials."""


@credential.command()
@click.option("--username", required=True, help="Username for the credential")
@click.option("--platform", required=True, help="Platform identifier")
@click.option("--scope", default="", help="Optional credential scope")
@click.option("--description", default="", help="Optional description")
@click.option(
    "--label",
    multiple=True,
    help="Labels in key=value format (can be specified multiple times)",
)
@click.argument("value")
def store(
    username: str,
    platform: str,
    scope: str,
    description: str,
    label: tuple[str],
    value: str,
) -> None:
    """Store a credential.

    VALUE is the credential value to store.
    """
    try:
        # Parse labels
        labels = {}
        for item in label:
            try:
                key, val = item.split("=", 1)
                labels[key.strip()] = val.strip()
            except ValueError:
                raise click.BadParameter(
                    f"Invalid label format: {item}. Use key=value format."
                )

        # Create metadata
        metadata = CredentialMetadata(
            username=username,
            platform=platform,
            scope=scope,
            description=description,
            labels=labels,
        )

        # Store credential
        store = get_store()
        store.store_credential(value, metadata)

        audit_event(
            "credential.create",
            username,
            True,
            {"platform": platform, "credential_id": str(metadata.credential_id)},
        )

        click.echo(f"Stored credential with ID: {metadata.credential_id}")

    except Exception as e:
        audit_event("credential.create", username, False, error=e)
        raise click.ClickException(str(e))


@credential.command()
@click.argument("id")
def get(id: str) -> None:
    """Get a credential by ID."""
    try:
        store = get_store()
        cred = store.get_credential(UUID(id))

        with cred as secure_cred:
            value = secure_cred.get_secret()
            click.echo(value)

        audit_event("credential.read", "cli", True, {"credential_id": id})

    except CredentialNotFoundError:
        raise click.ClickException(f"Credential not found: {id}")
    except Exception as e:
        audit_event("credential.read", "cli", False, {"credential_id": id}, error=e)
        raise click.ClickException(str(e))


@credential.command()
@click.option("--platform", help="Filter by platform")
@click.option("--username", help="Filter by username")
@click.option(
    "--label",
    multiple=True,
    help="Filter by labels in key=value format (can be specified multiple times)",
)
def list(platform: Optional[str], username: Optional[str], label: tuple[str]) -> None:
    """List stored credentials."""
    try:
        # Parse labels
        labels = {}
        for item in label:
            try:
                key, val = item.split("=", 1)
                labels[key.strip()] = val.strip()
            except ValueError:
                raise click.BadParameter(
                    f"Invalid label format: {item}. Use key=value format."
                )

        store = get_store()
        credentials = store.list_credentials(
            platform=platform, username=username, attributes=labels
        )

        # Format as table
        rows = [
            {
                "id": str(c.credential_id),
                "platform": c.platform,
                "username": c.username,
                "scope": c.scope,
                "description": c.description,
                "created": c.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "labels": ", ".join(f"{k}={v}" for k, v in c.labels.items()),
            }
            for c in credentials
        ]

        columns = [
            ("id", "ID"),
            ("platform", "Platform"),
            ("username", "Username"),
            ("scope", "Scope"),
            ("description", "Description"),
            ("created", "Created"),
            ("labels", "Labels"),
        ]

        print_table("Stored Credentials", rows, columns)
        audit_event(
            "credential.list",
            "cli",
            True,
            {"platform": platform, "username": username, "labels": labels},
        )

    except Exception as e:
        audit_event("credential.list", "cli", False, error=e)
        raise click.ClickException(str(e))


@credential.command()
@click.argument("id")
def delete(id: str) -> None:
    """Delete a credential by ID."""
    try:
        store = get_store()
        store.delete_credential(UUID(id))
        click.echo(f"Deleted credential: {id}")
        audit_event("credential.delete", "cli", True, {"credential_id": id})

    except CredentialNotFoundError:
        raise click.ClickException(f"Credential not found: {id}")
    except Exception as e:
        audit_event("credential.delete", "cli", False, {"credential_id": id}, error=e)
        raise click.ClickException(str(e))


@cli.group()
def auth() -> None:
    """Manage authentication."""


@auth.command()
@click.option(
    "--provider",
    type=click.Choice(["github", "gitlab", "keycloak"]),
    required=True,
    help="OAuth provider",
)
@click.option("--client-id", required=True, help="OAuth client ID")
@click.option("--client-secret", required=True, help="OAuth client secret")
def setup(provider: str, client_id: str, client_secret: str) -> None:
    """Configure OAuth provider."""
    try:
        # Store OAuth configuration
        store = get_store()
        metadata = CredentialMetadata(
            username="oauth",
            platform=provider,
            scope="config",
            labels={"type": "oauth_config"},
        )
        config = {
            "client_id": client_id,
            "client_secret": client_secret,
        }
        store.store_credential(json.dumps(config), metadata)

        click.echo(f"Configured {provider} OAuth provider")
        audit_event(
            "auth.setup", "cli", True, {"provider": provider, "client_id": client_id}
        )

    except Exception as e:
        audit_event(
            "auth.setup",
            "cli",
            False,
            {"provider": provider, "client_id": client_id},
            error=e,
        )
        raise click.ClickException(str(e))


def main() -> None:
    """CLI entry point."""
    cli()
