"""BIP-32 derived agent identity: one seed, two keys (IPv8, app-signing).

Public identity helpers are loaded lazily via PEP 562 ``__getattr__`` so
importing narrow subpackages such as ``identity.lineage`` does not pull in
wallet, seed, or Bitcoin-related dependencies.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__version__ = "0.1.0"

_LAZY_EXPORTS = {
    "Seed": ("identity.seed", "Seed"),
    "SeedSource": ("identity.seed", "SeedSource"),
    "MnemonicSeedSource": ("identity.seed", "MnemonicSeedSource"),
    "EnvSeedSource": ("identity.seed", "EnvSeedSource"),
    "KeyringSeedSource": ("identity.seed", "KeyringSeedSource"),
    "KeyfileSeedSource": ("identity.seed", "KeyfileSeedSource"),
    "DerivationPath": ("identity.derivation", "DerivationPath"),
    "derive": ("identity.derivation", "derive"),
    "IPV8_PATH": ("identity.derivation", "IPV8_PATH"),
    "APP_PATH": ("identity.derivation", "APP_PATH"),
    "WALLET_PATH": ("identity.derivation", "WALLET_PATH"),
    "IPv8KeyPair": ("identity.ipv8_key", "IPv8KeyPair"),
    "AppSigningKey": ("identity.app_key", "AppSigningKey"),
    "Wallet": ("identity.wallet", "Wallet"),
    "AgentIdentity": ("identity.agent_identity", "AgentIdentity"),
}

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
    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
