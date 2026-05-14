from __future__ import annotations

from decimal import Decimal
from typing import Any, Optional

from bitcoinlib.transactions import Transaction
from bitcoinlib.services.services import Service

from authentication.transaction_verification.exceptions import TransactionFetchError
from authentication.transaction_verification.models import (
    NormalizedTransaction,
    NormalizedTxOutput,
)
from authentication.transaction_verification.base_verifier import BaseVerifier


class BitcoinlibVerifier(BaseVerifier):
    """
    Transaction verifier that retrieves transaction data using bitcoinlib.

    This verifier fetches transactions through bitcoinlib's Service layer, normalizes
    the transaction data into internal transaction models, and delegates the actual
    verification logic to BaseVerifier.
    """

    def __init__(
        self,
        network: str = "bitcoin",
        service_providers: Optional[list[str]] = None,
    ) -> None:
        """
        Initialize the bitcoinlib verifier.

        :param network: The network name (e.g., 'bitcoin', 'testnet', 'litecoin').
        :param service_providers: Optional list of service provider names to use.
                                  If None, uses bitcoinlib's default providers.
        """
        self._network = network
        self._service = Service(
            network=network,
            providers=service_providers,
        )

    def close(self) -> None:
        """Close any resources held by the verifier."""
        # bitcoinlib Service doesn't require explicit cleanup
        pass

    def _fetch_transaction(self, txid: str) -> NormalizedTransaction | None:
        """
        Fetch and normalize a transaction by its transaction ID.

        This method retrieves the transaction using bitcoinlib's Service layer and
        converts it into a NormalizedTransaction. If the transaction does not exist,
        None is returned. Fetch and normalization failures are wrapped in
        TransactionFetchError.

        :param txid: The transaction ID to fetch.
        :returns: The normalized transaction, or None if the transaction was not found.
        :raises TransactionFetchError: If the transaction fetch fails or if the
                                       transaction data cannot be normalized.
        """
        try:
            # Fetch the transaction using bitcoinlib's service layer
            tx = self._service.gettransaction(txid)
            
            if tx is None:
                return None
            
            # If we get a Transaction object, we need to ensure it's fully fetched
            if isinstance(tx, Transaction):
                # Check if transaction data is complete
                if not tx.outputs:
                    # Try to fetch raw transaction and parse it
                    try:
                        raw_tx = self._service.getrawtransaction(txid)
                        if raw_tx:
                            tx = Transaction.import_raw(raw_tx, network=self._network)
                    except Exception:
                        pass
                
                return self._normalize_transaction(tx)
            
            return None
            
        except Exception as exc:
            # Check if it's a "not found" error
            error_msg = str(exc).lower()
            if "not found" in error_msg or "no transaction" in error_msg:
                return None
            
            raise TransactionFetchError(
                f"Failed to fetch transaction data: {exc}"
            ) from exc

    def _normalize_transaction(self, tx: Transaction) -> NormalizedTransaction:
        """
        Convert a bitcoinlib Transaction into a normalized transaction model.

        This method extracts the transaction ID, confirmations, and outputs from the
        bitcoinlib Transaction object and normalizes them into the internal format.

        :param tx: The bitcoinlib Transaction object.
        :returns: A normalized transaction representation suitable for verification.
        :raises ValueError: If the transaction is missing required data.
        """
        if not tx.txid:
            raise ValueError("Transaction missing txid.")

        # Get confirmations (default to 0 if not available)
        confirmations = getattr(tx, 'confirmations', 0) or 0
        if not isinstance(confirmations, int):
            confirmations = 0

        outputs: list[NormalizedTxOutput] = []
        
        for output in tx.outputs:
            # Get value in satoshis
            value_sats = output.value
            if not isinstance(value_sats, int):
                raise ValueError(f"Invalid output value: {value_sats}")

            # Get the script hex
            script_hex = output.lock_script.hex() if output.lock_script else ""
            if not script_hex:
                raise ValueError("Output missing script hex.")

            # Extract address if available
            address = None
            if hasattr(output, 'address') and output.address:
                address = str(output.address)
            elif hasattr(output, 'addresses') and output.addresses:
                # Take the first address if multiple are present
                address = str(output.addresses[0])

            outputs.append(
                NormalizedTxOutput(
                    value_sats=value_sats,
                    address=address,
                    script_hex=script_hex,
                )
            )

        return NormalizedTransaction(
            txid=tx.txid,
            confirmations=confirmations,
            outputs=outputs,
        )


class WalletVerifier(BitcoinlibVerifier):
    """
    Transaction verifier that uses an HDWallet instance for transaction verification.

    This verifier can work with transactions related to a specific HD wallet,
    allowing for verification of transactions involving wallet addresses.
    """

    def __init__(
        self,
        wallet_name: str,
        network: str = "bitcoin",
        db_uri: Optional[str] = None,
    ) -> None:
        """
        Initialize the HD wallet verifier.

        :param wallet_name: Name of the HD wallet to use.
        :param network: The network name (e.g., 'bitcoin', 'testnet').
        :param db_uri: Optional database URI for the wallet database.
        """
        super().__init__(network=network)
        
        from bitcoinlib.wallets import HDWallet
        
        try:
            self._wallet = HDWallet(
                wallet_name,
                network=network,
                db_uri=db_uri,
            )
        except Exception as exc:
            raise ValueError(f"Failed to load wallet '{wallet_name}': {exc}") from exc

    def get_wallet_address(self, account_id: int = 0, change: int = 0) -> str:
        """
        Get a receiving address from the wallet.

        :param account_id: Account index to use.
        :param change: 0 for receiving addresses, 1 for change addresses.
        :returns: A Bitcoin address from the wallet.
        """
        key = self._wallet.new_key(account_id=account_id, change=change)
        return key.address

    def verify_wallet_transaction(
        self,
        txid: str,
        expected_fee_sats: int,
        expected_registration_commitment: str,
    ) -> tuple[bool, str]:
        """
        Verify a transaction against wallet addresses.

        This is a convenience method that automatically uses one of the wallet's
        treasury addresses for verification.

        :param txid: The transaction ID to verify.
        :param expected_fee_sats: Minimum satoshis expected to be paid.
        :param expected_registration_commitment: Expected OP_RETURN commitment hex.
        :returns: Tuple of (success, reason).
        """
        from authentication.transaction_verification.models import (
            TransactionVerificationRequest,
        )
        
        # Get a treasury address from the wallet
        treasury_address = self.get_wallet_address(account_id=0, change=0)
        
        request = TransactionVerificationRequest(
            txid=txid,
            expected_treasury_address=treasury_address,
            expected_fee_sats=expected_fee_sats,
            expected_registration_commitment=expected_registration_commitment,
        )
        
        result = self.verify(request)
        return result.success, result.reason or "Success"

    def close(self) -> None:
        """Close wallet and verifier resources."""
        if hasattr(self, '_wallet'):
            # Close wallet database connections if any
            pass
        super().close()