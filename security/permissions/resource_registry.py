from __future__ import annotations

from pathlib import Path

from security.permissions.models import Resource


PROTECTED_PATH_MARKERS = (
    "private",
    "identity",
    "wallet",
    "accountability.log",
    "reputation",
    "seedbox",
    ".gateway_identity",
)


class ResourceRegistry:
    def __init__(self) -> None:
        self._resources: dict[str, Resource] = {}
        self._path_map: dict[Path, str] = {}
        self._protected_roots: list[Path] = []

    def register(self, resource: Resource) -> None:
        self._resources[resource.resource_id] = resource
        path = resource.metadata.get("path")
        if path:
            self._path_map[Path(path).expanduser().resolve()] = resource.resource_id
        protected_root = resource.metadata.get("protected_root")
        if protected_root:
            self.add_protected_root(protected_root)

    def add_protected_root(self, path: str | Path) -> None:
        self._protected_roots.append(Path(path).expanduser().resolve())

    def resolve(self, resource_id: str) -> Resource | None:
        return self._resources.get(resource_id)

    def label_for(self, resource_id: str) -> str | None:
        resource = self.resolve(resource_id)
        return resource.label if resource else None

    def is_registered(self, resource_id: str) -> bool:
        return resource_id in self._resources

    def resolve_path(self, raw_path: str) -> Resource | None:
        path = Path(raw_path).expanduser()
        try:
            resolved = path.resolve()
        except OSError:
            return None
        resource_id = self._path_map.get(resolved)
        return self.resolve(resource_id) if resource_id else None

    def classify_path(self, raw_path: str) -> tuple[bool, str]:
        normalized = raw_path.replace("\\", "/")
        if "../" in normalized or normalized.startswith("../") or "/.." in normalized:
            return False, "path traversal is not allowed"
        lowered = normalized.lower()
        if Path(raw_path).is_absolute() and any(marker in lowered for marker in PROTECTED_PATH_MARKERS):
            return False, "absolute protected path is not allowed"
        try:
            resolved = Path(raw_path).expanduser().resolve()
        except OSError:
            return False, "path could not be resolved"
        for root in self._protected_roots:
            if _is_relative_to(resolved, root):
                return False, "path resolves inside a protected root"
        return True, "path accepted"


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
