"""Environment capture for reproducible experiment results."""

from __future__ import annotations

import importlib.metadata
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any


DEPENDENCIES = ("cryptography", "ipv8", "pytest", "numpy", "pandas", "matplotlib", "scipy")


def _git_output(repo_root: Path, args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def git_commit(repo_root: Path) -> str:
    return _git_output(repo_root, ["rev-parse", "HEAD"]) or "unavailable"


def git_dirty(repo_root: Path) -> bool | str:
    status = _git_output(repo_root, ["status", "--short"])
    if status is None:
        return "unavailable"
    return bool(status)


def dependency_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in DEPENDENCIES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = "not_installed"
    return versions


def capture_environment(repo_root: str | Path) -> dict[str, Any]:
    root = Path(repo_root)
    return {
        "repository_root": str(root.resolve()),
        "git_commit": git_commit(root),
        "git_dirty": git_dirty(root),
        "python_version": platform.python_version(),
        "python": sys.version,
        "platform": platform.platform(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "dependencies": dependency_versions(),
    }
