"""BIP-32 derived agent identity: one seed, two keys (IPv8, app-signing)."""

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
from identity.wallet import Wallet
from identity.agent_identity import AgentIdentity

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
