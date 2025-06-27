# Development Guide

This guide provides comprehensive instructions for setting up and working with the Perihelion Auth-Manager development environment.

## Development Environment Setup

### Prerequisites

- Docker Desktop (for devcontainer support)
- Visual Studio Code with Remote Development extension
- Git
- GPG key for commit signing

### Quick Start

1. Clone the repository:
```bash
git clone https://github.com/tzervas/perihelion-auth-manager.git
cd perihelion-auth-manager
```

2. Open in VS Code with devcontainer:
```bash
code .
```
- When prompted, click "Reopen in Container"
- VS Code will build and start the development container

3. The devcontainer will automatically:
- Install all dependencies
- Set up pre-commit hooks
- Configure the Python environment
- Install VS Code extensions

### Manual Setup (Without Devcontainer)

1. Install Python 3.12+
2. Install UV package manager:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

3. Create virtual environment:
```bash
uv venv
source .venv/bin/activate
```

4. Install dependencies:
```bash
uv pip install -e ".[dev]"
```

5. Install pre-commit hooks:
```bash
pre-commit install
```

## Development Workflow

### Code Style

This project follows:
- PEP 8 standards
- Black code formatting
- Ruff linting
- MyPy type checking

### Branch Strategy

- `main`: Protected branch for releases
- `feature/*`: New features
- `fix/*`: Bug fixes
- `docs/*`: Documentation updates
- `refactor/*`: Code refactoring
- `test/*`: Test additions/updates

### Commit Messages

Follow conventional commits:
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation
- style: Formatting
- refactor: Code restructuring
- test: Test updates
- chore: Maintenance

### Testing

Run tests:
```bash
pytest
```

With coverage:
```bash
pytest --cov=perihelion_auth_manager
```

### Pre-commit Checks

The following checks run automatically on commit:
- Black formatting
- Ruff linting
- MyPy type checking
- pytest
- Various file checks

### Documentation

- Update documentation alongside code changes
- Use Google-style docstrings
- Keep README.md updated
- Document API changes

### Security Considerations

- Never commit secrets
- Always use GPG signing for commits
- Follow secure coding practices
- Regular dependency updates
- Security testing

## Troubleshooting

### Common Issues

1. GPG signing fails:
```bash
# Check GPG keys
gpg --list-secret-keys --keyid-format LONG

# Configure Git
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
```

2. Pre-commit hooks fail:
```bash
# Update hooks
pre-commit autoupdate

# Run manually
pre-commit run --all-files
```

3. Dependency conflicts:
```bash
# Clean environment
rm -rf .venv
uv venv
uv pip install -e ".[dev]"
```

### Getting Help

- Check existing issues
- Create a new issue with:
  - Environment details
  - Steps to reproduce
  - Expected vs actual behavior
  - Relevant logs

## Release Process

1. Update version in:
   - pyproject.toml
   - __init__.py
   - CHANGELOG.md

2. Create release commit:
```bash
git checkout -b release/v1.0.0
git commit -S -m "chore(release): v1.0.0"
```

3. Create PR for release

4. After merge, tag release:
```bash
git tag -s v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

## Continuous Integration

GitHub Actions workflows handle:
- Code quality checks
- Test execution
- Security scanning
- Documentation building
- Release automation

## IDE Setup

### VS Code

Required extensions:
- Python
- Pylance
- Black Formatter
- Ruff
- Even Better TOML
- GitLens
- GitHub Actions
- GitHub Copilot (recommended)

Recommended settings are in `.vscode/settings.json`

### PyCharm

- Enable Black formatter
- Configure pytest as test runner
- Set Python interpreter to virtual environment
- Enable type checking

## Project Structure

```
perihelion-auth-manager/
├── .devcontainer/       # Development container configuration
├── .github/            # GitHub Actions workflows
├── .vscode/           # VS Code settings
├── docs/             # Documentation
├── examples/         # Usage examples
├── src/             # Source code
│   └── perihelion_auth_manager/
│       ├── core/    # Core functionality
│       ├── auth/    # Authentication
│       ├── crypto/  # Cryptography
│       └── utils/   # Utilities
├── tests/           # Test suite
├── .gitignore      # Git ignore rules
├── .pre-commit-config.yaml  # Pre-commit hooks
├── LICENSE         # MIT license
├── README.md      # Project overview
└── pyproject.toml # Project configuration
```
