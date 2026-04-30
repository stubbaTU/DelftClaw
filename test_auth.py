import json
import unittest
from agent import P2PAgent


class TestAgentAuthentication(unittest.TestCase):
    def setUp(self):
        # Initialize two agents on distinct ports
        # This will auto-generate random identities for both
        self.agent_a = P2PAgent(port=8101)
        self.agent_b = P2PAgent(port=8102)

    def test_valid_signature_verification(self):
        """Test that Agent B correctly verifies a valid message from Agent A."""
        data = {"action": "test_action", "payload": "hello_world"}
        payload_bytes = json.dumps(data).encode()

        # Agent A signs the data
        signature_hex = self.agent_a.identity.ipv8.sign(payload_bytes).hex()
        ipv8_pubkey_hex = self.agent_a.identity.ipv8.pubkey.hex()

        # Agent B verifies the data
        is_valid = self.agent_b.verify_message_signature(
            ipv8_pubkey_hex,
            signature_hex,
            data
        )
        self.assertTrue(is_valid, "Valid signature must be accepted.")

    def test_invalid_signature_tampered_data(self):
        """Test that tampering with the payload invalidates the signature."""
        data = {"action": "test_action", "payload": "hello_world"}
        payload_bytes = json.dumps(data).encode()

        # Agent A signs the original data
        signature_hex = self.agent_a.identity.ipv8.sign(payload_bytes).hex()
        ipv8_pubkey_hex = self.agent_a.identity.ipv8.pubkey.hex()

        # An attacker intercepts and changes the data
        tampered_data = {"action": "test_action", "payload": "malicious_injection"}

        # Agent B attempts to verify the tampered data against the original signature
        is_valid = self.agent_b.verify_message_signature(
            ipv8_pubkey_hex,
            signature_hex,
            tampered_data
        )
        self.assertFalse(is_valid, "Tampered data must fail signature verification.")

    def test_invalid_signature_wrong_key(self):
        """Test that a signature verified against the wrong public key fails."""
        data = {"action": "test_action", "payload": "hello_world"}
        payload_bytes = json.dumps(data).encode()

        # Agent A signs the data
        signature_hex = self.agent_a.identity.ipv8.sign(payload_bytes).hex()

        # The message claims it came from Agent B (identity spoofing)
        wrong_pubkey_hex = self.agent_b.identity.ipv8.pubkey.hex()

        # Agent B attempts to verify it
        is_valid = self.agent_b.verify_message_signature(
            wrong_pubkey_hex,
            signature_hex,
            data
        )
        self.assertFalse(is_valid, "Signature verified against the wrong public key must fail.")


if __name__ == '__main__':
    unittest.main()
