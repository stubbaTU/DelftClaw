// list_room_members: enumerate the current member set of a Trustroom.

import type { JSONRpcClient } from "../client.js";

export interface ListMembersParams {
    room_id: string;
}

export interface ListMembersResult {
    members: { pubkey_hex: string }[];
}

export const listRoomMembers = {
    name: "list_room_members",
    description: "List the current credentialed members of a Trustroom.",
    handler: async (
        params: ListMembersParams,
        ctx: { client: JSONRpcClient },
    ): Promise<ListMembersResult> => {
        // Forward to the Python sidecar via JSONRpcClient.call("list_room_members", params).
        return ctx.client.call<ListMembersResult>("list_room_members", params);
    },
};
