"""BIP-39/BIP-32 derived identity primitives for OpenClaw agents."""

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
    wallet_path,
    verification_challenge_path,
)
from identity.ipv8_key import IPv8KeyPair
from identity.app_key import AppSigningKey
from identity.mls_key import MLSSigningKey
from identity.wallet import Wallet
from identity.agent_identity import AgentIdentity
from identity.openclaw_identity import OpenClawIdentity

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
    "wallet_path",
    "verification_challenge_path",
    "IPv8KeyPair",
    "AppSigningKey",
    "MLSSigningKey",
    "Wallet",
    "AgentIdentity",
    "OpenClawIdentity",
]
