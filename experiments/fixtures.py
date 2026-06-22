"""Spec loading + canonicalization for SQ3.

Loads the three experimental specs from ``protocol/examples/`` exactly once at
module import and caches the parsed form. The harness's runner and interop
modules both reuse the same canonical bytes / parsed structures, so two
independent compiles of the same spec see byte-identical inputs (a load-bearing
invariant for the cross-LLM interop measurement).

Also computes a ``fixture_sha`` over the load-bearing source files (compiler +
schema) — recorded with every run record so cells with mid-experiment
compiler/schema edits are detectable post-hoc and excluded from the final
analysis per the doc's Internal Validity threats.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from protocol.compiler import ParsedOverlay, canonicalize_md, community_id_from_md, parse_md, validate_schema


REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "protocol" / "examples"

SPEC_NAMES: tuple[str, ...] = ("echo", "content_community", "payment", "file_transfer")

_SPEC_PATHS: dict[str, Path] = {
    "echo": EXAMPLES_DIR / "echo_overlay.md",
    "content_community": EXAMPLES_DIR / "content_community.md",
    "payment": EXAMPLES_DIR / "payment_request.md",
    "file_transfer": EXAMPLES_DIR / "file_transfer_overlay.md",
}


@dataclass(frozen=True)
class SpecFixture:
    """Everything the harness needs about one spec, cached at import time."""
    name: str
    md_text: str
    canonical_bytes: bytes
    community_id_hex: str
    parsed: ParsedOverlay


def _load_specs() -> dict[str, SpecFixture]:
    out: dict[str, SpecFixture] = {}
    for name in SPEC_NAMES:
        path = _SPEC_PATHS[name]
        if not path.is_file():
            # Don't crash at import — a partial repo (or a future spec set)
            # should still let the other specs load. Missing specs surface
            # when the CLI tries to use them.
            continue
        md_text = path.read_text(encoding="utf-8")
        parsed = parse_md(md_text)
        validate_schema(parsed)
        out[name] = SpecFixture(
            name=name,
            md_text=md_text,
            canonical_bytes=canonicalize_md(md_text),
            community_id_hex=community_id_from_md(md_text).hex(),
            parsed=parsed,
        )
    return out


_SPECS: dict[str, SpecFixture] = _load_specs()


def get_spec(name: str) -> SpecFixture:
    """Look up a spec by name; raises KeyError with the list of known names
    if absent so a CLI typo surfaces fast."""
    if name not in _SPECS:
        known = ", ".join(sorted(_SPECS))
        raise KeyError(f"spec {name!r} not loaded (known: {known or '(none)'})")
    return _SPECS[name]


def loaded_spec_names() -> list[str]:
    """Names of specs that successfully parsed + validated at import."""
    return sorted(_SPECS)


def fixture_sha() -> str:
    """SHA-256 over the load-bearing schema-defining files.

    Recorded in every run record so a cell whose compiler.py was modified
    mid-experiment is detectable (and per the doc's threats-to-validity
    section, excluded from the final analysis). Pure read; no side effects.
    """
    digest = hashlib.sha256()
    for rel_path in (
        "protocol/compiler.py",
        "protocol/schema.md",
        "protocol/llm.py",
    ):
        digest.update(rel_path.encode("utf-8"))
        digest.update(b"\x00")
        digest.update((REPO_ROOT / rel_path).read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()
