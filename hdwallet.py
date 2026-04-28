from pywallet import wallet

class HDWallet:
    def __init__(self, network="BTC", seed=None):
        if seed is None:
            self.seed = wallet.generate_mnemonic()
        else:
            self.seed = seed
        self.network = network
        self.wallet = wallet.create_wallet(network=self.network, seed=self.seed, children=1)

    def get_seed(self):
        return self.seed

    def get_address(self):
        return self.wallet.get("address")

    def get_private_key(self):
        return self.wallet.get("private_key")

    def get_public_key(self):
        return self.wallet.get("public_key")

    def get_child(self, child_index):
        return wallet.create_wallet(network=self.network, seed=self.seed, children=child_index)


