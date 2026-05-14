"""
SporeStack Integration - Deploy VPS servers using Bitcoin payments.

This module integrates HD wallet functionality with SporeStack API
to enable autonomous server deployment using cryptocurrency.
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
import time


class SporeStackDeployer:
    """
    Deploy and manage SporeStack VPS servers using Bitcoin wallet.
    
    SporeStack is a VPS hosting service that accepts Bitcoin, Bitcoin Cash,
    and Monero payments without requiring personal information.
    """
    
    def __init__(
        self,
        wallet,
        config_dir: str = None,
        use_testnet: bool = False
    ):
        """
        Initialize SporeStack deployer.
        
        :param wallet: HDWallet instance with funds
        :param config_dir: Directory to store configuration files
        :param use_testnet: Use Bitcoin testnet instead of mainnet
        """
        self.wallet = wallet
        self.use_testnet = use_testnet
        
        # Setup configuration directory
        if config_dir is None:
            config_dir = os.path.expanduser("~/.sporestack_deployer")
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.token_file = self.config_dir / "sporestack_token.txt"
        self.server_file = self.config_dir / "deployed_servers.json"
        
        # Import sporestack library
        try:
            import sporestack
            self.sporestack = sporestack
        except ImportError:
            raise ImportError(
                "sporestack library not installed. "
                "Install with: pip install sporestack"
            )
    
    def get_payment_address(self, amount_usd: float) -> Dict[str, Any]:
        """
        Get a Bitcoin payment address to fund SporeStack token.
        
        :param amount_usd: Amount in USD to fund
        :return: Dictionary with payment address and amount info
        """
        try:
            # Create a SporeStack token
            # This generates a payment address where you send Bitcoin
            result = self.sporestack.token.create(
                dollars=amount_usd,
                currency='btc'  # or 'bch' for Bitcoin Cash, 'xmr' for Monero
            )
            
            return {
                'payment_address': result.get('address'),
                'amount_btc': result.get('amount'),
                'amount_usd': amount_usd,
                'token': result.get('token'),
                'expires': result.get('expires')
            }
        except Exception as e:
            print(f"Error creating payment request: {e}")
            raise
    
    def fund_sporestack_token(self, amount_usd: float) -> str:
        """
        Fund a SporeStack token using wallet balance.
        
        :param amount_usd: Amount in USD to fund the token
        :return: Token string
        """
        print(f"Creating SporeStack token for ${amount_usd}...")
        
        # Get payment information
        payment_info = self.get_payment_address(amount_usd)
        
        print(f"Payment address: {payment_info['payment_address']}")
        print(f"Amount needed: {payment_info['amount_btc']} BTC")
        
        # Check wallet balance
        wallet_balance = self.wallet.get_balance()
        print(f"Wallet balance: {wallet_balance / 100000000:.8f} BTC")
        
        # Convert BTC amount to satoshis
        amount_satoshis = int(float(payment_info['amount_btc']) * 100000000)
        
        if wallet_balance < amount_satoshis:
            raise ValueError(
                f"Insufficient funds. Need {amount_satoshis} satoshis, "
                f"have {wallet_balance} satoshis"
            )
        
        # Send payment
        print(f"Sending payment of {amount_satoshis} satoshis...")
        tx_hash = self.wallet.send(
            payment_info['payment_address'],
            amount_satoshis
        )
        
        print(f"Payment sent! Transaction: {tx_hash}")
        print("Waiting for confirmation...")
        
        # Wait for payment confirmation (this is simplified)
        time.sleep(60)  # Wait 1 minute for confirmation
        
        # Save token
        token = payment_info['token']
        self._save_token(token)
        
        print(f"Token funded and saved: {token[:20]}...")
        return token
    
    def _save_token(self, token: str):
        """Save SporeStack token to file."""
        with open(self.token_file, 'w') as f:
            f.write(token)
    
    def _load_token(self) -> Optional[str]:
        """Load SporeStack token from file."""
        if self.token_file.exists():
            with open(self.token_file, 'r') as f:
                return f.read().strip()
        return None
    
    def get_token_balance(self, token: str = None) -> float:
        """
        Check SporeStack token balance.
        
        :param token: SporeStack token (uses saved token if None)
        :return: Balance in USD
        """
        if token is None:
            token = self._load_token()
            if token is None:
                raise ValueError("No token found. Fund a token first.")
        
        try:
            info = self.sporestack.token.info(token)
            return info.get('balance', 0.0)
        except Exception as e:
            print(f"Error checking token balance: {e}")
            raise
    
    def deploy_server(
        self,
        token: str = None,
        hostname: str = "myserver",
        operating_system: str = "ubuntu-22-04",
        flavor: str = "vc2-1c-1gb",
        region: str = "ewr",
        provider: str = "vultr",
        days: int = 30,
        autorenew: bool = False,
        ssh_key_file: str = None
    ) -> Dict[str, Any]:
        """
        Deploy a VPS server on SporeStack.
        
        :param token: SporeStack token (uses saved token if None)
        :param hostname: Server hostname
        :param operating_system: OS to install
        :param flavor: Server size/flavor
        :param region: Geographic region
        :param provider: Cloud provider (vultr, digitalocean, etc.)
        :param days: Number of days to run
        :param autorenew: Auto-renew from token balance
        :param ssh_key_file: Path to SSH public key file
        :return: Server information dictionary
        """
        if token is None:
            token = self._load_token()
            if token is None:
                raise ValueError("No token found. Fund a token first.")
        
        print(f"Deploying server '{hostname}'...")
        print(f"Provider: {provider}, Region: {region}")
        print(f"Flavor: {flavor}, OS: {operating_system}")
        
        # Read SSH key if provided
        ssh_key = None
        if ssh_key_file:
            with open(os.path.expanduser(ssh_key_file), 'r') as f:
                ssh_key = f.read().strip()
        
        try:
            # Launch server
            server = self.sporestack.server.launch(
                token=token,
                hostname=hostname,
                operating_system=operating_system,
                flavor=flavor,
                region=region,
                provider=provider,
                days=days,
                autorenew=autorenew,
                ssh_key=ssh_key
            )
            
            server_info = {
                'machine_id': server.get('machine_id'),
                'hostname': hostname,
                'ipv4': server.get('ipv4'),
                'ipv6': server.get('ipv6'),
                'provider': provider,
                'region': region,
                'flavor': flavor,
                'operating_system': operating_system,
                'launched_at': time.time()
            }
            
            # Save server info
            self._save_server_info(server_info)
            
            print(f"Server deployed successfully!")
            print(f"Machine ID: {server_info['machine_id']}")
            print(f"IPv4: {server_info['ipv4']}")
            
            return server_info
            
        except Exception as e:
            print(f"Error deploying server: {e}")
            raise
    
    def _save_server_info(self, server_info: Dict[str, Any]):
        """Save deployed server information."""
        servers = []
        if self.server_file.exists():
            with open(self.server_file, 'r') as f:
                servers = json.load(f)
        
        servers.append(server_info)
        
        with open(self.server_file, 'w') as f:
            json.dump(servers, f, indent=2)
    
    def list_servers(self) -> list:
        """List all deployed servers."""
        if not self.server_file.exists():
            return []
        
        with open(self.server_file, 'r') as f:
            return json.load(f)
    
    def get_server_info(self, machine_id: str) -> Dict[str, Any]:
        """
        Get information about a specific server.
        
        :param machine_id: SporeStack machine ID
        :return: Server information
        """
        try:
            info = self.sporestack.server.info(machine_id)
            return info
        except Exception as e:
            print(f"Error getting server info: {e}")
            raise
    
    def stop_server(self, machine_id: str):
        """Stop a running server."""
        try:
            self.sporestack.server.stop(machine_id)
            print(f"Server {machine_id} stopped.")
        except Exception as e:
            print(f"Error stopping server: {e}")
            raise
    
    def delete_server(self, machine_id: str):
        """Delete a server."""
        try:
            self.sporestack.server.delete(machine_id)
            print(f"Server {machine_id} deleted.")
        except Exception as e:
            print(f"Error deleting server: {e}")
            raise


# Utility functions for common operations

def quick_deploy(
    wallet_seed: str = None,
    fund_amount_usd: float = 10.0,
    server_config: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Quick deployment: create wallet, fund token, deploy server.
    
    :param wallet_seed: BIP39 seed (generates new if None)
    :param fund_amount_usd: Amount to fund SporeStack token
    :param server_config: Server configuration dictionary
    :return: Deployment information
    """
    from hd_wallet import HDWallet
    
    # Create or load wallet
    print("Initializing wallet...")
    wallet = HDWallet(network="bitcoin", seed=wallet_seed)
    
    print(f"Wallet address: {wallet.get_address()}")
    print(f"Seed phrase: {wallet.get_seed()}")
    print("SAVE THIS SEED PHRASE SECURELY!")
    
    # Initialize deployer
    deployer = SporeStackDeployer(wallet)
    
    # Fund token
    token = deployer.fund_sporestack_token(fund_amount_usd)
    
    # Deploy server with default or custom config
    if server_config is None:
        server_config = {
            'hostname': 'autoserver',
            'operating_system': 'ubuntu-22-04',
            'flavor': 'vc2-1c-1gb',
            'region': 'ewr',
            'days': 30
        }
    
    server = deployer.deploy_server(token=token, **server_config)
    
    return {
        'wallet_address': wallet.get_address(),
        'seed': wallet.get_seed(),
        'token': token,
        'server': server
    }