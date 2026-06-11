from __future__ import annotations

from pathlib import Path

from security.preventative_layer.infrastructure.permissions import Resource, ResourceRegistry


def test_register_and_resolve_resource() -> None:
    registry = ResourceRegistry()
    registry.register(Resource("task_input_001", "public.task"))

    assert registry.resolve("task_input_001").label == "public.task"
    assert registry.label_for("task_input_001") == "public.task"
    assert registry.resolve("missing") is None


def test_path_classification_blocks_traversal_and_protected_roots(tmp_path: Path) -> None:
    protected = tmp_path / "identity"
    protected.mkdir()
    registry = ResourceRegistry()
    registry.add_protected_root(protected)

    assert registry.classify_path("../identity/key.json")[0] is False
    assert registry.classify_path(str(protected / "key.json"))[0] is False
