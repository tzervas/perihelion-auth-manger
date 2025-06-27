"""CLI entry points for Perihelion Auth-Manager."""

import click

from perihelion_auth_manager.cli import cli


def entrypoint() -> None:
    """Entry point for CLI."""
    cli()
