// join_room: present a stored VC to join an advertised Trustroom.

import type { JSONRpcClient } from "../client.js";

export interface JoinRoomParams {
    room_id: string;
    credential_id: string;
}

export interface JoinRoomResult {
    joined: boolean;
    reason: string;
}

export const joinRoom = {
    name: "join_room",
    description: "Join a Trustroom by presenting a stored Verifiable Credential. Returns whether admission was granted.",
    handler: async (
        params: JoinRoomParams,
        ctx: { client: JSONRpcClient },
    ): Promise<JoinRoomResult> => {
        // Forward to the Python sidecar via JSONRpcClient.call("join_room", params).
        return ctx.client.call<JoinRoomResult>("join_room", params);
    },
};
