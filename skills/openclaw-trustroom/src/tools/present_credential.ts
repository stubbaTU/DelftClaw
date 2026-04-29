// present_credential: produce a holder-bound Presentation blob for a target audience.

import type { JSONRpcClient } from "../client.js";

export interface PresentCredentialParams {
    credential_id: string;
    audience: { pubkey_hex: string };
}

export interface PresentCredentialResult {
    // base64-encoded Presentation bytes the caller hands to a remote room host.
    presentation_blob: string;
}

export const presentCredential = {
    name: "present_credential",
    description: "Build a holder-bound Verifiable Presentation tied to a specific audience and nonce. Returns the serialised presentation blob.",
    handler: async (
        params: PresentCredentialParams,
        ctx: { client: JSONRpcClient },
    ): Promise<PresentCredentialResult> => {
        // Forward to the Python sidecar via JSONRpcClient.call("present_credential", params).
        return ctx.client.call<PresentCredentialResult>("present_credential", params);
    },
};
