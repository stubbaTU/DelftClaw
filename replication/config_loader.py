"""
Configuration loader for the Bitcoin transaction verification system.

This module handles loading and validating configuration from config.txt.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


class VerificationConfig:
    """
    Configuration container for the verification system.
    
    Loads configuration from a JSON file (config.txt) and provides
    typed access to configuration values.
    """
    
    def __init__(self, config_path: str = "config.txt") -> None:
        """
        Initialize configuration from file.
        
        :param config_path: Path to the configuration file.
        :raises ConfigurationError: If config file is missing or invalid.
        """
        self.config_path = Path(config_path)
        self._config: dict[str, Any] = {}
        self._load_config()
        self._validate_config()
    
    def _load_config(self) -> None:
        """Load configuration from JSON file."""
        if not self.config_path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {self.config_path}"
            )
        
        try:
            with open(self.config_path, 'r') as f:
                self._config = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(
                f"Invalid JSON in configuration file: {e}"
            ) from e
        except Exception as e:
            raise ConfigurationError(
                f"Failed to load configuration: {e}"
            ) from e
    
    def _validate_config(self) -> None:
        """Validate required configuration sections exist."""
        required_sections = ["wallet", "verification", "blockchain"]
        
        for section in required_sections:
            if section not in self._config:
                raise ConfigurationError(
                    f"Missing required configuration section: {section}"
                )
    
    # Wallet Configuration
    
    @property
    def wallet_name(self) -> str:
        """Get the wallet name."""
        return self._config["wallet"].get("name", "default_wallet")
    
    @property
    def wallet_network(self) -> str:
        """Get the wallet network (bitcoin, testnet, etc.)."""
        return self._config["wallet"].get("network", "testnet")
    
    @property
    def wallet_witness_type(self) -> str:
        """Get the wallet witness type (legacy, segwit, etc.)."""
        return self._config["wallet"].get("witness_type", "segwit")
    
    @property
    def wallet_db_uri(self) -> Optional[str]:
        """Get the wallet database URI."""
        return self._config["wallet"].get("db_uri")
    
    # Verification Configuration
    
    @property
    def min_confirmations(self) -> int:
        """Get minimum required confirmations."""
        return self._config["verification"].get("min_confirmations", 1)
    
    @property
    def treasury_address(self) -> str:
        """Get the treasury address for payments."""
        addr = self._config["verification"].get("treasury_address")
        if not addr:
            raise ConfigurationError(
                "treasury_address is required in verification config"
            )
        return addr
    
    @property
    def default_fee_sats(self) -> int:
        """Get the default fee in satoshis."""
        return self._config["verification"].get("default_fee_sats", 10000)
    
    @property
    def network_fee_sats(self) -> int:
        """Get the network transaction fee in satoshis."""
        return self._config["verification"].get("network_fee_sats", 1000)
    
    # Service Configuration
    
    @property
    def service_providers(self) -> Optional[list[str]]:
        """Get list of service providers to use."""
        service_config = self._config.get("service", {})
        return service_config.get("providers")
    
    @property
    def service_timeout(self) -> int:
        """Get service timeout in seconds."""
        service_config = self._config.get("service", {})
        return service_config.get("timeout_seconds", 30)
    
    # Blockchain Configuration
    
    @property
    def blockchain_network(self) -> str:
        """Get the blockchain network."""
        return self._config["blockchain"].get("network", "testnet")
    
    @property
    def explorer_url(self) -> str:
        """Get the block explorer base URL."""
        return self._config["blockchain"].get(
            "explorer_url",
            "https://blockstream.info/testnet/tx/"
        )
    
    # Security Configuration
    
    @property
    def require_commitment(self) -> bool:
        """Get whether commitments are required."""
        security_config = self._config.get("security", {})
        return security_config.get("require_commitment", True)
    
    @property
    def commitment_min_length(self) -> int:
        """Get minimum commitment length in hex characters."""
        security_config = self._config.get("security", {})
        return security_config.get("commitment_min_length", 8)
    
    @property
    def allow_zero_confirmations(self) -> bool:
        """Get whether zero-confirmation transactions are allowed."""
        security_config = self._config.get("security", {})
        return security_config.get("allow_zero_confirmations", False)
    
    # Utility Methods
    
    def get_explorer_url_for_tx(self, txid: str) -> str:
        """
        Get the full explorer URL for a transaction.
        
        :param txid: The transaction ID.
        :returns: Full URL to view the transaction.
        """
        return f"{self.explorer_url}{txid}"
    
    def to_dict(self) -> dict[str, Any]:
        """
        Get the full configuration as a dictionary.
        
        :returns: Complete configuration dictionary.
        """
        return self._config.copy()
    
    def save(self, path: Optional[str] = None) -> None:
        """
        Save the current configuration to file.
        
        :param path: Path to save to. If None, uses original config_path.
        """
        save_path = Path(path) if path else self.config_path
        
        with open(save_path, 'w') as f:
            json.dump(self._config, f, indent=2)
    
    def update(self, section: str, key: str, value: Any) -> None:
        """
        Update a configuration value.
        
        :param section: Configuration section (e.g., 'wallet', 'verification').
        :param key: Configuration key within the section.
        :param value: New value to set.
        """
        if section not in self._config:
            self._config[section] = {}
        
        self._config[section][key] = value
    
    def __repr__(self) -> str:
        return f"VerificationConfig(wallet={self.wallet_name}, network={self.wallet_network})"


def create_default_config(path: str = "config.txt") -> None:
    """
    Create a default configuration file.
    
    :param path: Path where to create the config file.
    """
    default_config = {
        "wallet": {
            "name": "my_treasury_wallet",
            "network": "testnet",
            "witness_type": "segwit",
            "db_uri": None
        },
        "verification": {
            "min_confirmations": 1,
            "treasury_address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "default_fee_sats": 10000,
            "network_fee_sats": 1000
        },
        "service": {
            "providers": ["blockstream", "blockchair"],
            "timeout_seconds": 30
        },
        "blockchain": {
            "network": "testnet",
            "explorer_url": "https://blockstream.info/testnet/tx/"
        },
        "security": {
            "require_commitment": True,
            "commitment_min_length": 8,
            "allow_zero_confirmations": False
        }
    }
    
    config_path = Path(path)
    
    if config_path.exists():
        raise FileExistsError(f"Configuration file already exists: {path}")
    
    with open(config_path, 'w') as f:
        json.dump(default_config, f, indent=2)
    
    print(f"Created default configuration: {path}")


# Example usage
if __name__ == "__main__":
    # Create a default config if it doesn't exist
    try:
        create_default_config("config.txt")
    except FileExistsError:
        print("Config file already exists, loading it...")
    
    # Load and display configuration
    config = VerificationConfig("config.txt")
    
    print("\n" + "=" * 60)
    print("Configuration Loaded")
    print("=" * 60)
    print(f"Wallet Name: {config.wallet_name}")
    print(f"Network: {config.wallet_network}")
    print(f"Treasury Address: {config.treasury_address}")
    print(f"Default Fee: {config.default_fee_sats} sats")
    print(f"Min Confirmations: {config.min_confirmations}")
    print(f"Service Providers: {config.service_providers}")
    print("=" * 60)