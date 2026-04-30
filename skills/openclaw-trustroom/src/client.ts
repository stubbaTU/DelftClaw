// JSON-RPC client over a Unix-domain socket.
// Used by every tool to talk to the Python sidecar at ~/.openclaw/trustroom.sock.

export class JSONRpcClient {
    constructor(socketPath: string) {
        // Store the socket path; do NOT connect yet — connect() opens the socket.
    }

    async connect(): Promise<void> {
        // Open the Unix-domain socket; raise if the sidecar is not running.
    }

    async call<T>(method: string, params: unknown): Promise<T> {
        // Send a length-prefixed JSON-RPC request frame, await the response, decode result.
        // Throw on JSON-RPC errors so handlers surface them to the user.
        return undefined as unknown as T;
    }

    async close(): Promise<void> {
        // Drain pending calls, close the socket.
    }
}
