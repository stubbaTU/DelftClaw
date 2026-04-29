// Skill registration entry point. Exports the six tools the runtime registers.

import { sendToAgent } from "./tools/send_to_agent.js";
import { openRoom } from "./tools/open_room.js";
import { joinRoom } from "./tools/join_room.js";
import { listRoomMembers } from "./tools/list_room_members.js";
import { presentCredential } from "./tools/present_credential.js";
import { sendPayment } from "./tools/send_payment.js";

export const tools = [
    sendToAgent,
    openRoom,
    joinRoom,
    listRoomMembers,
    presentCredential,
    sendPayment,
];

export { JSONRpcClient } from "./client.js";
