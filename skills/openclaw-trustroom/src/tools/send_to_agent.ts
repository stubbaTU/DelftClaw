// send_to_agent: encrypt + ship a message (optionally with a Bitcoin payment).

import type { JSONRpcClient } from "../client.js";

export interface SendToAgentParams {
    room_id: string;
    text: string;
    payment?: {
        amount_sats: number;
        recipient_btc_pubkey_hex: string;
        signed_tx_hex: string;
    };
}

export interface SendToAgentResult {
    message_id: string;
}

export const sendToAgent = {
    name: "send_to_agent",
    description: "Send a message (optionally with a Bitcoin payment) to an agent in a Trustroom.",
    handler: async (
        params: SendToAgentParams,
        ctx: { client: JSONRpcClient },
    ): Promise<SendToAgentResult> => {
        // Forward to the Python sidecar via JSONRpcClient.call("send_to_agent", params).
        return ctx.client.call<SendToAgentResult>("send_to_agent", params);
    },
};
