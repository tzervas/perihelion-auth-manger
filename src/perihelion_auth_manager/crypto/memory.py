"""Secure memory handling utilities."""

import ctypes
import mmap
import os
from contextlib import contextmanager
from typing import Any, Iterator, TypeVar

T = TypeVar("T")


def secure_zero_memory(data: bytes) -> None:
    """Securely zero memory containing sensitive data.

    Args:
        data: The bytes object to clear.
    """
    # Get the buffer interface
    try:
        buf = memoryview(data).cast("B")
        ctypes.memset(buf._arr.buffer_info()[0], 0, len(buf))
    except (TypeError, AttributeError):
        # Fallback: overwrite with zeros
        length = len(data)
        for i in range(length):
            data[i:i+1] = b"\x00"


@contextmanager
def secure_memory() -> Iterator[mmap.mmap]:
    """Create a secure memory region that will be zeroed on exit.

    The memory region is protected from being swapped to disk.

    Yields:
        A mmap object that can be used to store sensitive data.
    """
    # Create anonymous memory mapping
    if os.name == "posix":
        flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
        if hasattr(mmap, "MAP_LOCKED"):
            flags |= mmap.MAP_LOCKED
    else:
        flags = 0

    # Allocate memory
    mem = mmap.mmap(-1, 4096, flags=flags)
    try:
        yield mem
    finally:
        # Zero and close memory
        mem.seek(0)
        mem.write(b"\x00" * 4096)
        mem.close()


@contextmanager
def secure_string() -> Iterator[bytearray]:
    """Create a secure string buffer that will be zeroed on exit.

    Yields:
        A bytearray that can be used to store sensitive strings.
    """
    # Create bytearray
    buf = bytearray()
    try:
        yield buf
    finally:
        # Zero buffer
        buf[:] = b"\x00" * len(buf)


def compare_bytes(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if the strings are equal, False otherwise.
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
