#!/usr/bin/env python3
"""Branch Hierarchy Update Tool.

This script provides intelligent and dynamic branch updates based on a defined hierarchy schema.
It supports complex parent-child relationships and custom update patterns.
"""

import argparse
import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional, Set, Union

import toml
import yaml
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class BranchNode:
    """Represents a branch in the hierarchy."""

    name: str
    parent: Optional[str] = None
    children: List[str] = None
    update_strategy: str = "merge"  # merge, rebase, or custom
    protected: bool = False

    def __post_init__(self):
        """Initialize children as empty list if None."""
        if self.children is None:
            self.children = []


class GitBranchManager:
    """Manages Git branch operations with hierarchy support."""

    def __init__(self, repo_path: str):
        """Initialize with repository path."""
        self.repo_path = Path(repo_path).resolve()
        if not self._is_git_repo():
            raise ValueError(f"Not a git repository: {self.repo_path}")
        self.current_branch = self._get_current_branch()
        self.stashed_changes = False

    def _run_git(
        self, cmd: List[str], check: bool = True, capture_output: bool = False
    ) -> subprocess.CompletedProcess:
        """Run a git command in the repository."""
        try:
            result = subprocess.run(
                ["git"] + cmd,
                cwd=self.repo_path,
                check=check,
                capture_output=capture_output,
                text=True,
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed: git {' '.join(cmd)}")
            logger.error(f"Error output: {e.stderr if e.stderr else 'No error output'}")
            if check:
                raise
            return e

    def _is_git_repo(self) -> bool:
        """Check if path is a git repository."""
        try:
            self._run_git(["rev-parse", "--git-dir"], capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _get_current_branch(self) -> str:
        """Get current branch name."""
        result = self._run_git(
            ["rev-parse", "--abbrev-ref", "HEAD"], capture_output=True
        )
        return result.stdout.strip()

    def _stash_changes(self) -> bool:
        """Stash any uncommitted changes."""
        if self._run_git(
            ["diff-index", "--quiet", "HEAD", "--"], check=False
        ).returncode != 0:
            logger.info("Stashing uncommitted changes...")
            self._run_git(
                ["stash", "push", "-m", "Auto-stash before branch updates"]
            )
            return True
        return False

    def _pop_stash(self):
        """Restore stashed changes if any."""
        if self.stashed_changes:
            logger.info("Restoring stashed changes...")
            try:
                self._run_git(["stash", "pop"], check=False)
            except subprocess.CalledProcessError:
                logger.warning(
                    "Failed to pop stash automatically. Manual resolution may be needed."
                )

    def checkout_branch(self, branch: str, create: bool = False) -> bool:
        """Checkout a branch, optionally creating it."""
        cmd = ["checkout"]
        if create:
            cmd.append("-b")
        cmd.append(branch)
        try:
            self._run_git(cmd)
            return True
        except subprocess.CalledProcessError:
            logger.error(f"Failed to checkout branch: {branch}")
            return False

    def update_branch(
        self, branch: str, source: str, strategy: str = "merge"
    ) -> bool:
        """Update a branch from its source using the specified strategy."""
        if not self.checkout_branch(branch):
            return False

        try:
            if strategy == "merge":
                self._run_git(["merge", "--no-edit", source])
            elif strategy == "rebase":
                self._run_git(["rebase", source])
            else:
                logger.error(f"Unsupported update strategy: {strategy}")
                return False

            # Push changes
            self._run_git(["push", "origin", branch])
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update branch {branch} from {source}: {e}")
            # Abort any pending merge or rebase
            if strategy == "merge":
                self._run_git(["merge", "--abort"], check=False)
            elif strategy == "rebase":
                self._run_git(["rebase", "--abort"], check=False)
            return False

    def process_branch_hierarchy(self, hierarchy: Dict[str, BranchNode]) -> bool:
        """Process the entire branch hierarchy."""
        try:
            # Stash any changes and remember current branch
            self.stashed_changes = self._stash_changes()
            original_branch = self._get_current_branch()

            # Update main first if it exists and is protected
            if "main" in hierarchy and hierarchy["main"].protected:
                logger.info("Updating protected main branch...")
                self.checkout_branch("main")
                self._run_git(["pull", "origin", "main"])

            # Process all branches in dependency order
            processed = set()
            failed = set()

            def process_branch(branch_name: str, visited: Set[str]) -> bool:
                """Recursively process a branch and its dependencies."""
                if branch_name in processed:
                    return True
                if branch_name in failed:
                    return False
                if branch_name in visited:
                    logger.error(f"Circular dependency detected: {branch_name}")
                    return False

                visited.add(branch_name)
                branch = hierarchy[branch_name]

                # Process parent first if it exists
                if branch.parent and branch.parent not in processed:
                    if not process_branch(branch.parent, visited):
                        failed.add(branch_name)
                        return False

                # Update this branch from its parent
                success = True
                if branch.parent:
                    logger.info(f"Updating {branch_name} from {branch.parent}")
                    success = self.update_branch(
                        branch_name, branch.parent, branch.update_strategy
                    )

                if success:
                    processed.add(branch_name)
                    # Process children
                    for child in branch.children:
                        if not process_branch(child, set()):
                            success = False
                            break
                else:
                    failed.add(branch_name)

                visited.remove(branch_name)
                return success

            # Process all branches that haven't been processed yet
            for branch_name in hierarchy:
                if branch_name not in processed and branch_name not in failed:
                    process_branch(branch_name, set())

            # Return to original branch
            self.checkout_branch(original_branch)
            self._pop_stash()

            if failed:
                logger.warning(f"Failed to update branches: {', '.join(failed)}")
                return False
            return True

        except Exception as e:
            logger.error(f"Error processing branch hierarchy: {e}")
            return False


def load_config(path: str) -> Dict[str, Any]:
    """Load configuration from YAML or TOML file."""
    try:
        with open(path) as f:
            if path.endswith('.toml'):
                return toml.load(f)
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration from {path}: {e}")
        raise

def interpolate_templates(data: Union[Dict, List, str], env: Dict[str, str]) -> Any:
    """Recursively interpolate environment variables in configuration."""
    if isinstance(data, dict):
        return {k: interpolate_templates(v, env) for k, v in data.items()}
    elif isinstance(data, list):
        return [interpolate_templates(item, env) for item in data]
    elif isinstance(data, str):
        return Template(data).safe_substitute(env)
    return data

def load_branch_schema(schema_path: str, env_file: Optional[str] = None) -> Dict[str, BranchNode]:
    """Load and validate branch hierarchy schema from YAML/TOML file."""
    try:
        # Load environment variables
        env = os.environ.copy()
        if env_file:
            load_dotenv(env_file)
            env.update(os.environ)

        # Load and parse schema
        data = load_config(schema_path)
        
        # Interpolate environment variables
        data = interpolate_templates(data, env)

        hierarchy = {}
        for branch_data in data["branches"]:
            branch = BranchNode(
                name=branch_data["name"],
                parent=branch_data.get("parent"),
                children=branch_data.get("children", []),
                update_strategy=branch_data.get("update_strategy", "merge"),
                protected=branch_data.get("protected", False),
            )
            hierarchy[branch.name] = branch

        # Validate parent-child relationships
        for name, branch in hierarchy.items():
            if branch.parent and branch.parent not in hierarchy:
                raise ValueError(f"Parent branch {branch.parent} not found for {name}")
            for child in branch.children:
                if child not in hierarchy:
                    raise ValueError(f"Child branch {child} not found for {name}")
                if hierarchy[child].parent != name:
                    raise ValueError(
                        f"Inconsistent parent-child relationship: {name} -> {child}"
                    )

        return hierarchy

    except Exception as e:
        logger.error(f"Error loading branch schema: {e}")
        raise


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Update Git branches according to hierarchy schema"
    )
    parser.add_argument(
        "--repo", "-r", default=".", help="Path to Git repository (default: current dir)"
    )
    parser.add_argument(
        "--schema",
        "-s",
        required=True,
        help="Path to YAML/TOML schema file defining branch hierarchy",
    )
    parser.add_argument(
        "--env-file",
        "-e",
        help="Path to .env file for template variables",
    )
    parser.add_argument(
        "--template-vars",
        "-t",
        help="Additional template variables in KEY=VALUE format",
        action='append',
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Set additional template variables from command line
    if args.template_vars:
        for var in args.template_vars:
            try:
                key, value = var.split('=', 1)
                os.environ[key.strip()] = value.strip()
            except ValueError:
                logger.warning(f"Ignoring invalid template variable: {var}")

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        hierarchy = load_branch_schema(args.schema, args.env_file)
        manager = GitBranchManager(args.repo)
        success = manager.process_branch_hierarchy(hierarchy)
        sys.exit(0 if success else 1)

    except Exception as e:
        logger.error(f"Failed to update branches: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
