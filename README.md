# Git Credential Manager

A secure-by-design, multi-platform Git authentication tool that provides intelligent credential management for GitHub, GitLab, and Gitea across Linux, macOS, and Windows.

## Features

- **Multi-Platform Support**: Works seamlessly on Linux, macOS, and Windows
- **Multiple Git Platforms**: Supports GitHub, GitLab, Gitea, and self-hosted instances
- **Intelligent Context Detection**: Automatically detects Git platform from repository remotes
- **Secure Credential Storage**: Uses platform-native secure storage (libsecret, Keychain, Credential Manager)
- **Multiple Users per Platform**: Manage multiple accounts for different scopes and permissions
- **GPG Signing Integration**: Easy setup for commit and tag signing
- **Zero External Dependencies**: Uses only Python standard library

## Security Features

- Credentials stored in platform-native secure keychains
- Configuration files use restrictive permissions (600/700)
- PATs are never stored in plain text
- Secure input handling (masked password input)
- Automatic credential helper installation and configuration

## Installation

### Quick Start

1. Clone or download the script:
```bash
curl -O https://raw.githubusercontent.com/tzervas/git-credential-manager/main/git_credential_manager.py
chmod +x git_credential_manager.py
```

2. Run the interactive setup:
```bash
python3 git_credential_manager.py
```

### Using pip (if packaged)

```bash
pip install git-credential-manager
git-cred-manager
```

## Usage

### Interactive Mode

Run without arguments for interactive menu:
```bash
python3 git_credential_manager.py
```

### Command Line Interface

```bash
# Add a user (auto-detects platform from current repo)
python3 git_credential_manager.py add

# List configured users
python3 git_credential_manager.py list

# Remove a user
python3 git_credential_manager.py remove

# Setup GPG signing
python3 git_credential_manager.py gpg
```

## Platform-Specific Setup

### Linux

The tool automatically installs `git-credential-libsecret` if not present:

```bash
# Manual installation (if needed)
sudo apt update
sudo apt install libsecret-1-dev build-essential
```

### macOS

Uses the built-in Keychain Access. No additional setup required.

### Windows

Uses Windows Credential Manager. Ensure Git for Windows is installed.

## Workflow Example

1. **Navigate to a Git repository**:
```bash
cd /path/to/your/repo
```

2. **Run the credential manager**:
```bash
python3 git_credential_manager.py
```

3. **Add a user** (the tool detects you're in a GitHub repo):
```
Detected platform: GitHub (github.com)

Adding user for GitHub (github.com)
Enter username: myusername
Enter Personal Access Token (PAT): [hidden input]
Enter token description/scope (optional): repo-access-token

Successfully added user myusername for GitHub (github.com)
```

4. **Configure GPG signing** (optional):
```bash
python3 git_credential_manager.py gpg
```

5. **Test the setup**:
```bash
git push origin main
# Credentials are automatically retrieved from secure storage
```

## Multiple Users and Scoped Access

The tool supports multiple users per platform, allowing you to:

- Set up different accounts for personal vs. work repositories
- Use tokens with different scopes for different operations
- Manage agent accounts with limited permissions
- Organize credentials by project or access level

Example configuration:
```
GitHub:
  github.com:
    • personal-account - Full access token (added: 2024-01-15 10:30:00)
    • work-account - Work repositories only (added: 2024-01-15 10:35:00)
    • deploy-bot - Deployment token (added: 2024-01-15 10:40:00)

GitLab:
  gitlab.company.com:
    • admin-user - Admin access (added: 2024-01-15 11:00:00)
    • developer - Read/write access (added: 2024-01-15 11:05:00)
```

## Configuration

### Config Directory Locations

- **Linux**: `~/.config/git-credential-manager/`
- **macOS**: `~/.config/git-credential-manager/`
- **Windows**: `%LOCALAPPDATA%\\GitCredentialManager\\`

### Files

- `credentials.json`: Metadata about configured users (no sensitive data)
- Actual credentials are stored in platform-native secure storage

## Supported Platforms

### Git Hosting Platforms

- **GitHub**: github.com
- **GitLab**: gitlab.com and self-hosted instances
- **Gitea**: gitea.com, codeberg.org, and self-hosted instances

### Operating Systems

- **Linux**: Ubuntu, Debian, RHEL, Rocky Linux, etc.
- **macOS**: All versions with Keychain Access
- **Windows**: Windows 10/11 with Git for Windows

## Security Considerations

- PATs are stored in OS-native secure storage only
- Configuration files use restrictive permissions
- No credentials are logged or cached in plain text
- Each platform/host can have separate credential helpers
- Supports least-privilege access with scoped tokens

## Troubleshooting

### Linux: libsecret not found
```bash
sudo apt install libsecret-tools libsecret-1-dev
```

### macOS: Keychain Access denied
Grant Terminal.app access to Keychain in System Preferences.

### Windows: Credential Manager issues
Ensure Git for Windows is properly installed and configured.

### Git push still asks for password
Check that the credential helper is properly configured:
```bash
git config --global --list | grep credential
```

## License

MIT License - see LICENSE file for details.

## Author

Tyler Zervas <tz-dev@vectorweight.com>

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Changelog

### v1.0.0
- Initial release
- Multi-platform support (Linux, macOS, Windows)
- Support for GitHub, GitLab, Gitea
- Secure credential storage
- GPG signing integration
- Interactive and CLI modes
