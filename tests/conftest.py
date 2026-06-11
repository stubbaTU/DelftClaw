"""pytest configuration for the DelftClaw test suite.

Skips collection of test files that target modules not yet built
(TDD red-step tests added by colleagues working on parallel
sub-projects). When the missing module lands, drop the entry from
``_RED_STEP_TESTS``.

"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


_DLL_DIRECTORY = None
if sys.platform == "win32":
    _project_root = Path(__file__).resolve().parent.parent
    if (_project_root / "libsodium.dll").exists():
        _DLL_DIRECTORY = os.add_dll_directory(str(_project_root))


# (test-file basename, module-it-imports) pairs. If the module can't be
# imported, the test file is skipped at collection time.
_RED_STEP_TESTS: list[tuple[str, str]] = [
    ("test_server_layer3.py", "redteam.integration.server"),
    ("test_signed_server.py", "redteam.integration.server"),
]

def _module_unavailable(modname: str) -> bool:
    """``find_spec`` raises ``ModuleNotFoundError`` if a parent package is
    missing — wrap it so the conftest stays loadable."""
    try:
        return importlib.util.find_spec(modname) is None
    except (ImportError, ModuleNotFoundError, ValueError):
        return True


collect_ignore: list[str] = [
    fname for fname, modname in _RED_STEP_TESTS if _module_unavailable(modname)
]
