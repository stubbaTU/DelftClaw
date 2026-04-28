import asyncio
import json
import ecdsa
import hashlib
from network import UDPEndpoint
from hdwallet import HDWallet
from security.append_log import AppendOnlyLog
from security.proxy import IsolationProxy
from security.reputation import ReputationEngine

class P2PAgent:
    """
    A basic P2P Agent that uses HDWallet for identity and UDPEndpoint for communication.
    """
    def __init__(self, host='0.0.0.0', port=8090, seed=None):
        self.wallet = HDWallet(seed=seed)
        self.endpoint = UDPEndpoint(host=host, port=port)
        self.endpoint.add_message_callback(self.on_message)
        
        # Identity details
        self.address = self.wallet.get_address()
        self.public_key_hex = self.wallet.get_public_key()
        self.private_key_hex = self.wallet.get_private_key()
        
        # Setup ECDSA signing
        self.signing_key = ecdsa.SigningKey.from_string(
            bytes.fromhex(self.private_key_hex), 
            curve=ecdsa.SECP256k1
        )
        print(f"Agent starting with address: {self.address}")
        
        # Security Components
        self.host_log = AppendOnlyLog()
        self.proxy = IsolationProxy(agent_id=self.address, logger=self.host_log)
        self.reputation = ReputationEngine(log_path=self.host_log.log_path)

    async def start(self):
        await self.endpoint.start()
        
    def stop(self):
        self.endpoint.stop()
        
    def send_json(self, data: dict, target_addr: tuple):
        # Attach the sender's identity to the message
        payload = {
            "sender": self.address,
            "pubkey": self.public_key_hex,
            "data": data
        }
        
        # Serialize the message and sign it
        payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
        signature = self.signing_key.sign_deterministic(payload_bytes, hashfunc=hashlib.sha256)
        
        # Send raw message wrapped with its digital signature
        envelope = {
            "payload": payload_bytes.decode('utf-8'),
            "signature": signature.hex()
        }
        
        raw_bytes = json.dumps(envelope).encode('utf-8')
        self.endpoint.send(raw_bytes, target_addr)
        
    def on_message(self, data: bytes, addr: tuple):
        try:
            envelope = json.loads(data.decode('utf-8'))
            
            # Extract signature and unverified payload
            payload_raw = envelope.get("payload", "")
            signature_hex = envelope.get("signature", "")
            
            payload_bytes = payload_raw.encode('utf-8')
            signature = bytes.fromhex(signature_hex)
            
            payload = json.loads(payload_raw)
            sender = payload.get("sender", "Unknown")

            # Reputation Check: drop packet if sender is banned
            self.reputation.scan_log(self.endpoint)
            if self.reputation.is_banned(sender):
                print(f"[{self.address}] Packet dropped. Sender {sender} is banned.")
                return

            pubkey_hex = payload.get("pubkey", "")
            message_data = payload.get("data", {})
            
            # Verify the signature matches the payload and the provided public key
            # Handle both uncompressed (130 hex chars, "04" prefix) and compressed (66 hex chars, "02"/"03" prefix)
            pubkey_bytes = bytes.fromhex(pubkey_hex)
            if len(pubkey_bytes) == 65:  # Uncompressed
                vk_string = pubkey_bytes[1:]
            else:  # Compressed (zpywallet defaults to this)
                vk_string = pubkey_bytes

            verifying_key = ecdsa.VerifyingKey.from_string(
                vk_string,
                curve=ecdsa.SECP256k1,
                valid_encodings=[ecdsa.der.FieldElement.to_bytes] if len(pubkey_bytes) == 65 else None
            )
            
            try:
                verifying_key.verify(signature, payload_bytes, hashfunc=hashlib.sha256)
                print(f"[VERIFIED {self.address}] Received from {sender}@{addr}: {message_data}")

                # Log incoming verified messages via Isolation Proxy
                self.proxy.log_action("receive_message", {
                    "sender": sender,
                    "data": message_data
                })

                self.handle_message(sender, message_data, addr)
            except ecdsa.BadSignatureError:
                print(f"[{self.address}] Invalid signature from {addr}! Dropping message.")
                
        except Exception as e:
            print(f"Failed to process message from {addr}: {e}")

    def handle_message(self, sender, data, addr):
        action = data.get("action")

        # 1. Handle incoming network-wide Log Broadcasts from other peers
        if action == "log_broadcast":
            entry = data.get("entry", {})
            # We blindly append broadcasted logs from others (trusting the cryptographic signature verified above)
            self.host_log.append(sender, entry.get("action", "unknown"), entry.get("details", {}))
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
                # Log our own action securely via proxy
                self.proxy.log_action("unauthorized_tool_use", {"requested_by": sender, "tool": tool_name})
            else:
                self.proxy.log_action("tool_execution_success", {"requested_by": sender, "tool": tool_name})

            # Broadcast our newly logged action to the network so others update their public reputation logs
            self.broadcast_log()

    def broadcast_log(self, target_peers=[('127.0.0.1', 8091), ('127.0.0.1', 8092)]):
        """Broadcasts our most recent local log entries to known peers."""
        try:
            with open(self.host_log.log_path, 'r') as f:
                lines = f.readlines()
                if len(lines) > 1: # Ignore header
                    last_entry = json.loads(lines[-1].strip())
                    # Broadcast to hardcoded mock peers
                    for peer in target_peers:
                        if peer != (self.endpoint.host, self.endpoint.port):
                            self.send_json({
                                "action": "log_broadcast",
                                "entry": last_entry
                            }, peer)
        except Exception as e:
            print(f"Failed to broadcast log: {e}")
