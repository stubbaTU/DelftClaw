// send_payment: compose, sign, and broadcast a Bitcoin payment to a peer.

import type { JSONRpcClient } from "../client.js";

export interface SendPaymentParams {
    recipient: { pubkey_hex: string };
    amount_sats: number;
}

export interface SendPaymentResult {
    txid: string;
}

export const sendPayment = {
    name: "send_payment",
    description: "Compose, sign, and broadcast a Bitcoin payment to another agent. Returns the on-network transaction id.",
    handler: async (
        params: SendPaymentParams,
        ctx: { client: JSONRpcClient },
    ): Promise<SendPaymentResult> => {
        // Forward to the Python sidecar via JSONRpcClient.call("send_payment", params).
        return ctx.client.call<SendPaymentResult>("send_payment", params);
    },
};
