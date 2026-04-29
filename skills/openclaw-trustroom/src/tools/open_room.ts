// open_room: create a new Trustroom with a chosen admission policy.

import type { JSONRpcClient } from "../client.js";

export interface OpenRoomParams {
    policy: {
        kind: "openclaw-agent" | "issuer-allowlist" | "composite";
        issuer_pubkeys_hex?: string[];
    };
}

export interface OpenRoomResult {
    room_id: string;
}

export const openRoom = {
    name: "open_room",
    description: "Create a new Trustroom with a chosen admission policy. Returns the room id to share with peers.",
    handler: async (
        params: OpenRoomParams,
        ctx: { client: JSONRpcClient },
    ): Promise<OpenRoomResult> => {
        // Forward to the Python sidecar via JSONRpcClient.call("open_room", params).
        return ctx.client.call<OpenRoomResult>("open_room", params);
    },
};
