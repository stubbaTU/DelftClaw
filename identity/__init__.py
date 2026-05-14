"""DelftClaw identity helpers."""

__version__ = "0.1.0"

try:
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
except ModuleNotFoundError:
    Seed = SeedSource = MnemonicSeedSource = EnvSeedSource = KeyringSeedSource = KeyfileSeedSource = None
    DerivationPath = derive = IPV8_PATH = APP_PATH = WALLET_PATH = None
    IPv8KeyPair = AppSigningKey = Wallet = AgentIdentity = None

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
