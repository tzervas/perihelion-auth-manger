"""
Platform-specific security implementations for file operations.

This module provides secure file creation and permission management functions
that are platform-aware and implement appropriate security measures.

Platform-specific security notes:
- Windows: Uses ACLs for permission management
- POSIX: Uses file mode bits (0640 for files, 0750 for dirs)
- Other: Falls back to basic file creation with warnings
"""

import os
import sys
import logging
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

def create_secure_file(path: Path) -> None:
    """
    Create a file with secure permissions appropriate for the platform.
    
    Args:
        path: Path object representing the file to create
        
    Raises:
        OSError: If file creation fails
        PermissionError: If setting permissions fails
    """
    if sys.platform == "win32":
        # Windows-specific secure file creation
        import win32security
        import ntsecuritycon as con
        
        path.touch(exist_ok=True)
        security = win32security.GetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION
        )
        
        # Get current process owner
        token = win32security.OpenProcessToken(
            win32security.GetCurrentProcess(),
            win32security.TOKEN_QUERY
        )
        sid = win32security.GetTokenInformation(
            token, win32security.TokenUser)[0]
        
        # Create DACL with restrictive permissions
        dacl = win32security.ACL()
        # Owner full control
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_ALL_ACCESS,
            sid
        )
        
        # Set the DACL
        security.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            str(path),
            win32security.DACL_SECURITY_INFORMATION,
            security
        )
    else:
        # POSIX secure file creation
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o640)
        os.close(fd)

def ensure_secure_permissions(path: Path) -> None:
    """
    Ensure a file has secure permissions, falling back to basic creation if needed.
    
    Args:
        path: Path object representing the file to secure
    """
    try:
        create_secure_file(path)
    except (OSError, PermissionError) as e:
        logger.warning(f"Could not set secure permissions: {e}")
        # Fallback to basic file creation
        path.touch(exist_ok=True)
