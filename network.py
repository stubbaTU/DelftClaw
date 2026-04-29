import asyncio

class TriblerUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def connection_made(self, transport):
        self.endpoint.transport = transport

    def datagram_received(self, data, addr):
        # Pass the received data up to the endpoint for processing
        self.endpoint.on_datagram_received(data, addr)

class UDPEndpoint:
    """
    A basic asynchronous UDP endpoint, similar to what Tribler (IPv8) uses
    to send and receive peer-to-peer datagrams over the network.
    """
    def __init__(self, host='0.0.0.0', port=8090):
        self.host = host
        self.port = port
        self.transport = None
        self.callbacks = []

    async def start(self):
        loop = asyncio.get_running_loop()
        print(f"Starting UDP endpoint on {self.host}:{self.port}")
        # Bind and create the Datagram connection
        self.transport, _protocol = await loop.create_datagram_endpoint(
            lambda: TriblerUDPProtocol(self),
            local_addr=(self.host, self.port)
        )

    def stop(self):
        if self.transport:
            self.transport.close()
            print("UDP endpoint stopped.")

    def send(self, data: bytes, addr: tuple):
        if self.transport:
            self.transport.sendto(data, addr)
        else:
            print("Cannot send; transport not initialized.")

    def add_message_callback(self, callback):
        self.callbacks.append(callback)

    def on_datagram_received(self, data, addr):
        # Trigger any listeners when a packet comes in
        for callback in self.callbacks:
            callback(data, addr)

# --- Example Usage (Commented out) ---
# async def main():
#     endpoint = UDPEndpoint(host='127.0.0.1', port=8090)
#     endpoint.add_message_callback(lambda data, addr: print(f"Received {data} from {addr}"))
#
#     await endpoint.start()
#     endpoint.send(b"Ping", ('127.0.0.1', 8090))
#
#     await asyncio.sleep(5)
#     endpoint.stop()
#
# if __name__ == "__main__":
#     asyncio.run(main())
