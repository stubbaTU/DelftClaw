
"""Windows-specific libsodium DLL loader.

This module ensures that PyNaCl can find and load libsodium.dll on Windows systems.
It should be imported early in the application lifecycle (before any cryptography calls).

Usage:
    from agent.libsodium_setup import setup_libsodium
    setup_libsodium()
"""

import ctypes
import logging
import os
import sys
from pathlib import Path
from typing import Optional

_logger = logging.getLogger(__name__)


def _find_libsodium_dll() -> Optional[str]:
    """Find libsodium.dll in common locations.

    Returns:
        Path to libsodium.dll if found, None otherwise.
    """
    search_paths = [
        # Project root (where libsodium.dll is bundled)
        Path(__file__).parent.parent / "libsodium.dll",
        # Windows system paths (checked via PATH env var)
        Path(os.getenv("SYSTEMROOT", "C:\\Windows")) / "libsodium.dll",
        Path(os.getenv("SYSTEMROOT", "C:\\Windows")) / "System32" / "libsodium.dll",
    ]

    for path in search_paths:
        if path.exists():
            _logger.debug(f"Found libsodium.dll at {path}")
            return str(path)

    return None


def setup_libsodium() -> bool:
    """Configure libsodium for PyNaCl on Windows.

    Adds the directory containing libsodium.dll to the DLL search path
    and preloads it if possible to ensure PyNaCl can find it.

    Returns:
        True if setup successful, False otherwise.
    """
    if sys.platform != "win32":
        _logger.debug("Not on Windows; libsodium setup not needed")
        return True

    dll_path = _find_libsodium_dll()
    if not dll_path:
        _logger.warning(
            "libsodium.dll not found. PyNaCl may fail to initialize. "
            "Please ensure libsodium.dll is in the project root or system PATH."
        )
        return False

    # Try to add the DLL directory to the DLL search path (Windows 10+)
    dll_dir = os.path.dirname(dll_path)
    try:
        if sys.version_info >= (3, 8):
            os.add_dll_directory(dll_dir)
            _logger.debug(f"Added {dll_dir} to DLL search path")
    except Exception as e:
        _logger.warning(f"Could not add DLL directory to search path: {e}")

    # Try to preload the DLL
    try:
        ctypes.CDLL(dll_path)
        _logger.info(f"Successfully preloaded libsodium from {dll_path}")
        return True
    except Exception as e:
        _logger.error(f"Failed to preload libsodium: {e}")
        return False


# Auto-setup on module import
try:
    setup_libsodium()
except Exception as e:
    _logger.warning(f"Exception during libsodium auto-setup: {e}")

