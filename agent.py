import asyncio
import json
import ecdsa
import hashlib
from network import UDPEndpoint
from hdwallet import HDWalle

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
            pubkey_hex = payload.get("pubkey", "")
            message_data = payload.get("data", {})
            
            # Verify the signature matches the payload and the provided public key
            verifying_key = ecdsa.VerifyingKey.from_string(
                bytes.fromhex(pubkey_hex)[1:], # Strip the '04' uncompressed prefix
                curve=ecdsa.SECP256k1
            )
            
            try:
                verifying_key.verify(signature, payload_bytes, hashfunc=hashlib.sha256)
                print(f"[VERIFIED {self.address}] Received from {sender}@{addr}: {message_data}")
                self.handle_message(sender, message_data, addr)
            except ecdsa.BadSignatureError:
                print(f"[{self.address}] Invalid signature from {addr}! Dropping message.")
                
        except Exception as e:
            print(f"Failed to process message from {addr}: {e}")

    def handle_message(self, sender, data, addr):
        # Override this method for custom OpenClaw agent logic
        pass

# --- Example of running an Agent ---
# async def main():
#     agent1 = P2PAgent(host='127.0.0.1', port=8091)
#     agent2 = P2PAgent(host='127.0.0.1', port=8092)
#     
#     await agent1.start()
#     await agent2.start()
#     
#     # Agent 1 sends a message to Agent 2
#     agent1.send_json({"action": "ping"}, ('127.0.0.1', 8092))
#     
#     await asyncio.sleep(2)
#     agent1.stop()
#     agent2.stop()
#
# if __name__ == "__main__":
#     asyncio.run(main())
