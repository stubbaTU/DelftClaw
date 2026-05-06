"""BIP-32 derived agent identity: one seed, two keys (IPv8, app-signing)."""

__version__ = "0.1.0"

from identity.seed import (
    Seed,
    SeedSource,
    MnemonicSeedSource,
    EnvSeedSource,
    KeyringSeedSource,
)
from identity.derivation import (
    DerivationPath,
    derive,
    IPV8_PATH,
    APP_PATH,
)
from identity.ipv8_key import IPv8KeyPair
from identity.app_key import AppSigningKey
from identity.agent_identity import AgentIdentity

__all__ = [
    "Seed",
    "SeedSource",
    "MnemonicSeedSource",
    "EnvSeedSource",
    "KeyringSeedSource",
    "DerivationPath",
    "derive",
    "IPV8_PATH",
    "APP_PATH",
    "IPv8KeyPair",
    "AppSigningKey",
    "AgentIdentity",
]
