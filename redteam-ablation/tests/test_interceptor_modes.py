"""Enforcement-mode ladder on the P1/P3 interceptors (plan 2026-06-10 §1.1).

P1 (``OwnerAnchoredIdentityInterceptor``) and P3 (``ConstitutionHashInterceptor``)
gain a keyword-only constructor parameter ``mode: str`` with values
``"audit" | "strict"`` (default ``"strict"``, preserving fail-closed semantics
for existing direct instantiation):

* **strict** = current behaviour: a violation is DENIED
  (``InterceptDecision(allow=False, reason=...)``).
* **audit** = detect-and-proceed: a violation is ALLOWED but flagged
  (``allow=True, flagged=True, reason="audit: ..."``); audit mode NEVER denies,
  including on the fail-closed missing-context paths.
* invalid mode -> ``ValueError`` at construction (fail loudly).
* ``name`` carries the mode tag (``P1-owner-identity[audit]`` vs
  ``P1-owner-identity[strict]``) so denied_by / flagged_by attribution is
  mode-unambiguous.

P2 (``SignedLogAuditInterceptor``) is audit by construction: it has NO mode
parameter (its asymmetry is intentional and stays).
"""

from __future__ import annotations

import pytest

from redteam_ablation.contracts import ToolDecision
from redteam_ablation.interceptors.constitution_check import (
    ConstitutionHashInterceptor,
)
from redteam_ablation.interceptors.identity_check import (
    OwnerAnchoredIdentityInterceptor,
)
from redteam_ablation.interceptors.signed_log_audit import (
    SignedLogAuditInterceptor,
)

OWNER = "owner-principal-id"
NON_OWNER = "spoofed-non-owner-id"
PUBLISHED = "published-constitution-hash"
TAMPERED = "tampered-constitution-hash"


# --- per-primitive (decision, context) factories ----------------------------


def _p1_violation():
    """A non-owner sender: the P1 violation input."""
    decision = ToolDecision(tool_name="write_memory", sender_id=NON_OWNER)
    return decision, {"owner_id": OWNER}


def _p1_clean():
    """The owner sender: a clean (non-violating) call for P1."""
    decision = ToolDecision(tool_name="write_memory", sender_id=OWNER)
    return decision, {"owner_id": OWNER}


def _p3_violation():
    """A diverged session constitution hash: the P3 violation input."""
    decision = ToolDecision(tool_name="write_file", sender_id=OWNER)
    return decision, {
        "published_constitution_hash": PUBLISHED,
        "session_constitution_hash": TAMPERED,
    }


def _p3_clean():
    """Matching constitution hashes: a clean (non-violating) call for P3."""
    decision = ToolDecision(tool_name="write_file", sender_id=OWNER)
    return decision, {
        "published_constitution_hash": PUBLISHED,
        "session_constitution_hash": PUBLISHED,
    }


# Each param: (interceptor class, base name, violation factory, clean factory).
PRIMITIVES = [
    pytest.param(
        OwnerAnchoredIdentityInterceptor,
        "P1-owner-identity",
        _p1_violation,
        _p1_clean,
        id="P1",
    ),
    pytest.param(
        ConstitutionHashInterceptor,
        "P3-constitution-hash",
        _p3_violation,
        _p3_clean,
        id="P3",
    ),
]


# --- constructor contract (§1.1) ---------------------------------------------


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
def test_mode_is_keyword_only(cls, base, violation, clean):
    """``mode`` cannot be passed positionally (keyword-only parameter)."""
    with pytest.raises(TypeError):
        cls("audit")


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
@pytest.mark.parametrize("bad_mode", ["lenient", "AUDIT", "Strict", ""])
def test_invalid_mode_raises_value_error(cls, base, violation, clean, bad_mode):
    """Only ``"audit"`` and ``"strict"`` are valid; anything else fails loudly."""
    with pytest.raises(ValueError):
        cls(mode=bad_mode)


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
def test_default_mode_is_strict(cls, base, violation, clean):
    """A bare construction is strict: violation denied, name tagged [strict]."""
    interceptor = cls()
    assert interceptor.name == f"{base}[strict]"
    decision, context = violation()
    verdict = interceptor.inspect(decision, context)
    assert verdict.allow is False


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
def test_name_carries_mode_tag(cls, base, violation, clean):
    """The interceptor name is mode-unambiguous for denied_by / flagged_by."""
    assert cls(mode="audit").name == f"{base}[audit]"
    assert cls(mode="strict").name == f"{base}[strict]"
    assert cls(mode="audit").name != cls(mode="strict").name


# --- strict mode: deny on violation (each gets an audit-flag mirror twin) ----


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
def test_strict_denies_on_violation(cls, base, violation, clean):
    """Strict = current fail-closed behaviour: violation -> allow=False."""
    decision, context = violation()
    verdict = cls(mode="strict").inspect(decision, context)
    assert verdict.allow is False
    assert verdict.reason  # a non-empty attribution reason is recorded
    assert verdict.flagged is False  # denial is not a flag (§1.1 strict shape)


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
def test_audit_allows_and_flags_violation(cls, base, violation, clean):
    """Audit mirror of the strict deny: violation -> allow=True, flagged=True."""
    decision, context = violation()
    verdict = cls(mode="audit").inspect(decision, context)
    assert verdict.allow is True
    assert verdict.flagged is True
    assert verdict.reason.startswith("audit: ")


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
def test_strict_denies_on_missing_context(cls, base, violation, clean):
    """Strict keeps the fail-closed path: an unattestable call is denied."""
    decision, _ = violation()
    verdict = cls(mode="strict").inspect(decision, {})
    assert verdict.allow is False


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
def test_audit_never_denies_even_on_missing_context(cls, base, violation, clean):
    """Audit mirror of the fail-closed deny: detect-and-proceed, NEVER denies
    (§1.1: audit mode never denies), so the missing-context violation is
    allowed and flagged instead of blocked."""
    decision, _ = violation()
    verdict = cls(mode="audit").inspect(decision, {})
    assert verdict.allow is True
    assert verdict.flagged is True
    assert verdict.reason.startswith("audit: ")


# --- clean calls: allowed and unflagged in BOTH modes -------------------------


@pytest.mark.parametrize("cls, base, violation, clean", PRIMITIVES)
@pytest.mark.parametrize("mode", ["audit", "strict"])
def test_clean_call_allowed_and_unflagged(cls, base, violation, clean, mode):
    """A non-violating call passes silently regardless of mode."""
    decision, context = clean()
    verdict = cls(mode=mode).inspect(decision, context)
    assert verdict.allow is True
    assert verdict.flagged is False


# --- P2: no mode parameter (§1.1) ---------------------------------------------


def test_p2_has_no_mode_param():
    """P2 is audit by construction: passing a mode is a TypeError."""
    with pytest.raises(TypeError):
        SignedLogAuditInterceptor(mode="audit")


def test_p2_name_carries_no_mode_tag():
    """P2's name stays untagged -- there is no mode axis on it."""
    assert SignedLogAuditInterceptor().name == "P2-signed-log"
