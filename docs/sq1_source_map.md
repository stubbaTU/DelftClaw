# SQ1 — Source map for the candidate property list

**Companion to:** [`sq1_research.md`](sq1_research.md).
**Purpose:** show, per property, which paper(s) ground each anchor, so the
list in `sq1_research.md` is auditable in one glance.
**Status:** draft, 2026-05-08.

Two anchor classes per property:

- **Agent-specific anchor** — paper that argues the property is *required*
  for autonomous-agent communication.
- **M2M / human anchor** — protocol or standard where the property is
  *absent or partial*, satisfying the SQ1 "where it is absent or partial"
  half of the success criterion.

## Per-property source map

| # | Property | Agent-specific source | M2M / human source |
|---|----------|----------------------|---------------------|
| 1 | Principal-intent binding | **Abdelnabi et al. [1]** (AISec '23) — indirect prompt injection, *"processing retrieved prompts can act as arbitrary code execution"* + **Perez & Ribeiro [13]** — direct prompt-override (the *"Ignore Previous Prompt"* attack). Together they cover both indirect (data-channel) and direct (message-channel) intent hijacking. | **TLS 1.3 (RFC 8446)** — verbatim *"does not specify how protocols add security … left to the judgment of the designers."* |
| 2 | Identity lineage and replication-aware delegation | **Garzon et al. [16]** (ICAART 2026) — *"limited support for delegation of authority … reliance on static trust models that fail to adapt dynamically."* Proposes DID-doc deputies. | **X.509 (RFC 5280) + OIDC**, as characterised by Garzon. |
| 3 | Mid-conversation compromise containment | **Abdelnabi et al. [1]** (per-message compromise feasibility, indirect) + **Perez & Ribeiro [13]** (direct prompt-override per message) + **Kong et al. [10]** — *"the accumulation of tiny benign deviations on each step may lead to an intolerable risk."* | **MLS RFC 9420 [2]** — *"It's left to the application to determine an appropriate amount of time between Updates."* (PCS rotation is operator-driven.) |
| 4 | Per-message auth + replay defence | **Louck et al. [11]** — A2A *"do not enforce per-message signing or nonce-based validation"*; ACP **ROBUST** via *"JWS applied per MIME segment."* | **TLS 1.3 (RFC 8446)** — point-to-point, channel-level, message-content-agnostic above the record layer. |
| 5 | Credential-gated admission + selective disclosure | **Garzon et al. [16]** — *"self-sovereign digital identity … W3C DID … set of third-party issued W3C VCs"*; *"verifiable presentation (VP) exchange at dialogue initiation."* | **MLS RFC 9420 [2]** — authorization is *"left to the application"*; **mTLS** reveals the entire client cert (no selective disclosure). |
| 6 | Bonded participation (economic stake at admission) | **Louck et al. [11]** — vulnerability category *"Registry Pollution and Denial-of-Service"* + **Kong et al. [10]** on attack-success rates amplified by cheap agent replication. | **MLS [2, 3], Signal Double Ratchet [4, 14]** — none incorporate economic stake; Sybil resistance is delegated to the PKI layer above them. |
| 7 | In-band authenticated value transfer | **Kong et al. [10]** — taxonomy explicitly includes *"agent-to-agent payment"* + **Louck et al. [11]** — *"task delegation often embeds payment or scheduling parameters directly within prompt payloads."* | **DIDComm v2 [5]** — defines an agent messaging envelope; no value-transfer payload type specified. |
| 8 | Tool-call scope binding | **Louck et al. [11]** — A2A *"coarse JSON-RPC scope definitions without nested hierarchy enforcement"*; ACP *"operation-specific JWTs, effectively binding permissions to individual tasks"* + **Kong et al. [10]** on tool-execution authority. | **OAuth 2.x scope semantics**, as characterised by Louck [11]. |
| 9 | Authenticated, signed capability discovery | **Louck et al. [11]** — *"Spoofing in Discovery Mechanisms"*; A2A *"absent end-to-end signing … forged capabilities, inject false endpoints"* + **Kong et al. [10]** on agent spoofing. | **MLS RFC 9420 [2]** has no discovery layer; **DNS / mDNS** has no cryptographic authenticity for advertisements. |
| 10 | Verifiable audit trail | **Louck et al. [11]** — *"Compliance Gaps"*; A2A *"omits persistent audit logging of sensitive events."* | **MLS RFC 9420 [2], Signal [4, 14]** — protocols do not produce forwardable audit evidence; logging deferred to applications. |

## Source coverage summary

**By agent-specific source.** All four sources cited in `Research_plan.pdf`
SQ1 success criterion are used, plus [13] Perez & Ribeiro (already in the
plan's reference list, used for completeness on the prompt-override
direction):

| Source | Anchors property |
|--------|------------------|
| Abdelnabi et al. [1] | 1, 3 |
| Kong et al. [10] | 3, 6, 7, 8, 9 |
| Louck et al. [11] | 4, 6, 7, 8, 9, 10 |
| Perez & Ribeiro [13] | 1, 3 |
| Garzon et al. [16] | 2, 5 |

Louck and Kong carry the most weight (each anchoring 5–6 properties),
Garzon is the identity/replication anchor, and Abdelnabi is the
prompt-injection foundation that motivates the "broken assumptions"
framing in the plan's Background section.

**By M2M / human anchor.**

| Source | Anchors property |
|--------|------------------|
| MLS RFC 9420 [2] | 3, 5, 9, 10 |
| TLS 1.3 (RFC 8446) | 1, 4 |
| Signal Double Ratchet [4, 14] | 6, 10 |
| MLS Architecture RFC 9750 [3] | 6 |
| DIDComm v2 [5] | 7 |
| X.509 + OIDC | 2 |
| OAuth 2.x | 8 |
| DNS / mDNS | 9 |

## Caveat — references not yet in the plan's bibliography

Three properties (1, 4, 8) and one secondary anchor (Property 2) lean on
M2M baselines that are **not currently in the `Research_plan.pdf`
reference list:**

- **TLS 1.3 (RFC 8446)** — anchors Properties 1, 4.
- **X.509 (RFC 5280)** — anchors Property 2.
- **OAuth 2.x (RFC 6749 / 9700 family)** — anchors Property 8.

Adding them to `Research_plan.pdf` is a one-line edit to the reference
list. Without that edit, the success-criterion phrase *"one cited
human/M2M protocol"* is technically unmet for those four properties — the
supervisor lock at the Friday Week-3 meeting should resolve this. See
"Open questions before lock" in `sq1_research.md`.

## Plan-cited references used here

- [[1]](https://arxiv.org/abs/2302.12173) Abdelnabi et al., *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* AISec '23.
- [[2]](https://www.rfc-editor.org/rfc/rfc9420) Barnes et al., *The Messaging Layer Security (MLS) Protocol.* RFC 9420.
- [[3]](https://www.rfc-editor.org/rfc/rfc9750) Beurdouche et al., *The Messaging Layer Security (MLS) Architecture.* RFC 9750.
- [[4]](https://doi.org/10.1007/s00145-020-09360-1) Cohn-Gordon et al., *A Formal Security Analysis of the Signal Messaging Protocol.* J. Cryptology 33.4 (2020).
- [[5]](https://identity.foundation/didcomm-messaging/spec/v2.1/) Decentralized Identity Foundation, *DIDComm Messaging Specification v2.1.*
- [[10]](https://arxiv.org/abs/2506.19676) Kong et al., *A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense Countermeasures.*
- [[11]](https://arxiv.org/abs/2511.03841) Louck et al., *Security Analysis of Agentic AI Communication Protocols: A Comparative Evaluation.*
- [[13]](https://arxiv.org/abs/2211.09527) Perez & Ribeiro, *Ignore Previous Prompt: Attack Techniques For Language Models.*
- [[14]](https://signal.org/docs/specifications/doubleratchet/) Perrin & Marlinspike, *The Double Ratchet Algorithm.*
- [[16]](https://arxiv.org/abs/2511.02841) Garzon et al., *AI Agents with Decentralized Identifiers and Verifiable Credentials.* ICAART 2026.

## Additional anchors used here, pending plan-list addition

- IETF RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3.* <https://datatracker.ietf.org/doc/html/rfc8446>
- IETF RFC 5280, *Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile.*
- IETF OAuth 2.x family (RFC 6749, RFC 9700).
