"""BIP-32 derived agent identity: one seed, two keys (IPv8, app-signing).

``Wallet`` and ``AgentIdentity`` are loaded lazily via PEP 562
``__getattr__`` so that ``python -m identity.wallet`` doesn't trigger
the ``RuntimeWarning: 'identity.wallet' found in sys.modules after
import of package 'identity', but prior to execution`` warning — the
wallet module is only imported on first attribute access, not when the
package itself is imported.
"""

from __future__ import annotations

from typing import Any

__version__ = "0.1.0"

from identity.seed import (
    Seed,
    SeedSource,
    MnemonicSeedSource,
    EnvSeedSource,
    KeyringSeedSource,
    KeyfileSeedSource,
)
from identity.derivation import (
    DerivationPath,
    derive,
    IPV8_PATH,
    APP_PATH,
    WALLET_PATH,
)
from identity.ipv8_key import IPv8KeyPair
from identity.app_key import AppSigningKey

# ``Wallet`` and ``AgentIdentity`` are intentionally lazy-loaded —
# see module docstring above.

__all__ = [
    "Seed",
    "SeedSource",
    "MnemonicSeedSource",
    "EnvSeedSource",
    "KeyringSeedSource",
    "KeyfileSeedSource",
    "DerivationPath",
    "derive",
    "IPV8_PATH",
    "APP_PATH",
    "WALLET_PATH",
    "IPv8KeyPair",
    "AppSigningKey",
    "Wallet",
    "AgentIdentity",
]


def __getattr__(name: str) -> Any:
    if name == "Wallet":
        from identity.wallet import Wallet
        return Wallet
    if name == "AgentIdentity":
        from identity.agent_identity import AgentIdentity
        return AgentIdentity
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
