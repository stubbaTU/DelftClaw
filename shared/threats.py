"""Threat enumeration the Communication channel addresses (post-v3.0 scope cut)."""

from __future__ import annotations

from enum import StrEnum


class Threat(StrEnum):
    """Threat scenarios the channel must address. Each maps to one or more layers."""

    IDENTITY_LIE = "identity_lie"
    # Peer claims a public key it does not actually control.

    CREDENTIAL_LIE = "credential_lie"
    # Peer presents a VC it is not the rightful subject of.

    REPLAY = "replay"
    # An old WireFrame or VC presentation is replayed by an adversary.

    NETWORK_OBSERVER = "network_observer"
    # Passive eavesdropper records traffic for offline analysis.

    PAST_KEY_COMPROMISE = "past_key_compromise"
    # Forward-secrecy violation: yesterday's key leaks and exposes today's traffic.

    FUTURE_KEY_COMPROMISE = "future_key_compromise"
    # Post-compromise: takeover today must not let the attacker read tomorrow's traffic.


# --- Scoping note (2026-05-06) ----------------------------------------------
# DelftClaw was scoped to IPv8 + Verifiable Credentials + signed application
# messaging on 2026-05-06 (PROJECT_DESIGN.md §15 ADR-0004). As a result the
# following threats are explicitly OUT OF SCOPE:
#
#   * PAST_KEY_COMPROMISE / FUTURE_KEY_COMPROMISE — no key ratchet (no MLS,
#     no Double Ratchet); a compromised member rotates by disbanding the
#     room. See ADR-0003 (§15.1).
#   * The *confidentiality* dimension of NETWORK_OBSERVER — WireFrame.payload
#     is plaintext on the wire; deployments needing confidentiality run the
#     agents over a private VPN.
#
# Bitcoin-payment threats and replica-spawning threats (formerly INTENT_LIE,
# PROVENANCE_LIE, PROMPT_INJECTION, ROGUE_REPLICA) were dropped on 2026-05-06
# together with the corresponding implementation directories (replication/,
# security/) — see ADR-0004.
#
# The *authenticity* and *replay* dimensions of NETWORK_OBSERVER remain in
# scope and are addressed by WireFrame.sender_signature plus the
# ``communication/replay/`` nonce cache + skew window.
