"""BIP-32 derived agent identity: one seed, three keys (IPv8, MLS, Bitcoin)."""

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
    MLS_PATH,
    BTC_PATH,
    REPLICA_PATH_TEMPLATE,
)
from identity.ipv8_key import IPv8KeyPair
from identity.mls_key import MLSSigningKey
from identity.wallet import Wallet, SignedTransaction, UTXO
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
    "MLS_PATH",
    "BTC_PATH",
    "REPLICA_PATH_TEMPLATE",
    "IPv8KeyPair",
    "MLSSigningKey",
    "Wallet",
    "SignedTransaction",
    "UTXO",
    "AgentIdentity",
]
