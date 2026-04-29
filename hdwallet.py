from zpywallet.wallet import generate_mnemonic, create_wallet
from zpywallet.network import BitcoinMainNet

class HDWallet:
    def __init__(self, network="BTC", seed=None):
        if seed is None:
            self.seed = generate_mnemonic()
        else:
            self.seed = seed
        self.network = BitcoinMainNet
        self.wallet = create_wallet(network=self.network, mnemonic=self.seed)

    def get_seed(self):
        return self.seed

    def get_address(self):
        return self.wallet.address()

    def get_private_key(self):
        return self.wallet.private_key.to_hex()

    def get_public_key(self):
        pub_hex = self.wallet.public_key.to_hex()
        return pub_hex

    def get_child(self, child_index):
        child_path = f"m/44'/0'/0'/0/{child_index}"
        child_wallet = self.wallet.get_child_for_path(child_path)
        new_hd = HDWallet(seed=self.seed)
        new_hd.wallet = child_wallet
        return new_hd
