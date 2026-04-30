import asyncio
import json
from network import UDPEndpoint
from identity.seed import MnemonicSeedSource
from identity.agent_identity import AgentIdentity
from security.subq2_accountability.append_log import AppendOnlyLog
from security.subq2_accountability.proxy import IsolationProxy
from security.subq2_accountability.reputation import ReputationEngine


class P2PAgent:
    """
    A basic P2P Agent that uses AgentIdentity and UDPEndpoint for communication.
    """

    def __init__(self, host='0.0.0.0', port=8090, seed_phrase: str = None, log_path=None):
        if not seed_phrase:
            # Generate a random seed if none provided (for ad-hoc testing)
            from bitcoinlib.mnemonic import Mnemonic
            seed_phrase = Mnemonic().generate()

        seed_src = MnemonicSeedSource(seed_phrase)
        master_seed = seed_src.load()

        self.identity = AgentIdentity.from_seed(master_seed)
        self.wallet = self.identity.wallet
        self.ipv8 = self.identity.ipv8

        self.endpoint = UDPEndpoint(host=host, port=port)
        self.endpoint.add_message_callback(self.on_message)

        # Identity details
        self.address = self.wallet.address()
        self.public_key_hex = self.wallet.pubkey.hex()

        print(f"Agent starting with address: {self.address} and AgentId: {self.identity.agent_id}")

        # Security Components
        self.host_log = AppendOnlyLog(log_path=log_path or f"agent_{port}_actions.log")
        self.proxy = IsolationProxy(agent_id=self.address, logger=self.host_log)
        self.reputation = ReputationEngine(log_path=self.host_log.log_path)

    async def start(self):
        await self.endpoint.start()

    def stop(self):
        self.endpoint.stop()

    def send_json(self, data: dict, target_addr: tuple):
        # Attach the sender's identity to the message
        # We can use the IPv8 key for network-level signatures
        payload_bytes = json.dumps(data).encode()
        signature = self.identity.ipv8.sign(payload_bytes).hex()

        payload = {
            "sender": self.address,
            "agent_id": self.identity.agent_id,
            "pubkey": self.public_key_hex,
            "ipv8_pubkey": self.identity.ipv8.pubkey.hex(),
            "signature": signature,
            "data": data
        }

        msg = json.dumps(payload).encode('utf-8')
        self.endpoint.send(msg, target_addr)

    def verify_message_signature(self, ipv8_pubkey_hex: str, signature_hex: str, data: dict) -> bool:
        try:
            from ipv8.keyvault.crypto import default_eccrypto
            pub_bytes = bytes.fromhex(ipv8_pubkey_hex)
            sig_bytes = bytes.fromhex(signature_hex)
            data_bytes = json.dumps(data).encode()

            # Use ipv8's default ECC crypto system which understands the "LibNaCLPK:" prefix
            pub_key = default_eccrypto.key_from_public_bin(pub_bytes)
            return pub_key.verify(sig_bytes, data_bytes)
        except Exception as e:
            return False

    def on_message(self, message: bytes, addr: tuple):
        try:
            payload = json.loads(message.decode('utf-8'))
            sender = payload.get("sender")
            pubkey = payload.get("pubkey")
            ipv8_pubkey = payload.get("ipv8_pubkey")
            sig = payload.get("signature")
            data = payload.get("data", {})

            if ipv8_pubkey and sig:
                if not self.verify_message_signature(ipv8_pubkey, sig, data):
                    print(f"[{self.address}] INVALID SIGNATURE from {sender} at {addr}. Dropping message.")
                    return

            action = data.get("action")

            # Reputation Check: drop packet if sender is banned
            self.reputation.scan_log(self.endpoint)
            if self.reputation.is_banned(sender):
                print(f"[{self.address}] Packet dropped. Sender {sender} is banned.")
                return

            # 1. Handle incoming network-wide Log Broadcasts from other peers
            if action == "log_broadcast":
                entry = data.get("entry", {})
                if entry.get("reporter_id") != sender:
                    self.proxy.report_violation(
                        subject_id=sender,
                        action="log_spoof_attempt",
                        details={"claimed_reporter": entry.get("reporter_id")}
                    )
                    print(f"[{self.address}] Rejected spoofed log broadcast from {sender}")
                    return

                self.host_log.append_event(
                    reporter_id=sender,
                    subject_id=entry.get("subject_id", sender),
                    action=entry.get("action", "unknown"),
                    details=entry.get("details", {}),
                    severity=entry.get("severity", 0),
                    evidence={
                        "remote_entry_hash": entry.get("entry_hash"),
                        "received_from": sender,
                    }
                )
                print(f"[{self.address}] Synced public log from peer {sender}")
                return

            # 2. Handle mock tool calls / agent instruction requests
            if action == "execute_tool":
                tool_name = data.get("tool")
                kwargs = data.get("kwargs", {})
                print(f"[{self.address}] Received mock request to execute tool: {tool_name}")

                # Simple mock privilege separation check
                if tool_name == "unauthorized_tool_use":
                    print(f"[{self.address}] SEC-BLOCK: Refusing to run unauthorized tool!")
                    self.proxy.report_violation(
                        subject_id=sender,
                        action="unauthorized_tool_request",
                        details={"requested_by": sender, "tool": tool_name}
                    )
                else:
                    self.proxy.log_action("tool_execution_success", {"requested_by": sender, "tool": tool_name})

                # Broadcast our newly logged action to the network so others update their public reputation logs
                self.broadcast_log()
        except Exception as e:
            print(f"Failed to process message from {addr}: {e}")

    def broadcast_log(self, target_peers=None):
        """Broadcasts our most recent local log entries to known peers."""
        if target_peers is None:
            target_peers = [('127.0.0.1', 8091), ('127.0.0.1', 8092)]

        try:
            entries = self.host_log.read_entries()
            if entries:
                last_entry = entries[-1]
                # Broadcast to hardcoded mock peers
                for peer in target_peers:
                    if peer != (self.endpoint.host, self.endpoint.port):
                        self.send_json({
                            "action": "log_broadcast",
                            "entry": last_entry
                        }, peer)
        except Exception as e:
            print(f"Failed to broadcast log: {e}")


if __name__ == "__main__":
    async def main():
        agent = P2PAgent(port=8090)
        await agent.start()

        # Keep alive
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            agent.stop()
            print("\nAgent stopped.")


    asyncio.run(main())
