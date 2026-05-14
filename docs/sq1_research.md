# SQ1 — Research artifact

**Status:** draft, deep-research pass — not yet locked.
**Drafted:** 2026-05-08.
**Author:** Nikola Emilov (with Claude collaboration).
**Scope:** the qualitative requirements analysis that SQ1 of the research
plan calls for.

This document is the working research artifact behind SQ1. It is *not* the
final list — the final, supervisor-approved list will land in
[`docs/threat_model.md`](threat_model.md), which is currently a placeholder.
This file shows the reasoning behind each candidate property and the
verbatim-quote anchors so the supervisor and the SQ2 second-rater can
challenge, edit, or drop any property without re-doing the literature pass.

## SQ1 question and success criterion (from `Research_plan.pdf`)

> **SQ1 — Requirements (qualitative).** Which properties must an
> agent-to-agent communication channel provide that protocols designed for
> human or machine-to-machine peers do not address?
>
> *Success criterion:* an enumerated list of at least eight properties,
> each anchored to one cited human/M2M protocol where it is absent or
> partial and one cited agent-specific source where it is required
> [1, 10, 11, 16].

## Method

The pass below:

1. Read the four agent-specific anchor sources cited in the plan:
   [1] Abdelnabi et al. (AISec '23), [10] Kong et al. (arXiv 2506.19676,
   2025), [11] Louck et al. (arXiv 2511.03841, 2025), [16] Garzon et al.
   (ICAART 2026).
2. Read the M2M / human-targeted protocol specifications already cited by
   the plan: [2] MLS RFC 9420, [3] MLS Architecture RFC 9750, [4] Signal
   formal analysis, [5] DIDComm v2, [8] W3C VC Data Model 2.0, [14] Double
   Ratchet, [17, 18] SSI deployment papers. Where a property has no
   plan-cited M2M anchor, this draft falls back to TLS 1.3 (RFC 8446) or
   X.509 (RFC 5280) — both ubiquitous M2M baselines that can be added to
   the plan's reference list before locking.
3. Synthesised candidate properties. Each is one of: *required by an
   agent-specific source* and *absent or partial in an M2M protocol*. A
   property without both anchors is dropped.

The Background section of the plan explicitly identifies three assumptions
that existing M2M / human-secure-messaging analyses make and that fail
under autonomous LLM agents:

> "Existing secure-messaging analyses assume the credential holder forms
> intent independently of the messages it receives, that compromise
> propagates slowly relative to message rates, and that identity does not
> fork or replicate — assumptions that do not hold for autonomous agents."

Properties in the list below are each motivated by one or more of those
broken assumptions, plus a few additional ones surfaced by the four
agent-specific sources.

## Candidate property list (10 items)

The minimum SQ1 success criterion is **eight** properties; ten are
proposed here so the supervisor and second-rater have slack to merge or
drop without falling under the floor. Each property names a column of
the SQ2 coverage matrix.

### 1. Principal-intent binding

The channel must bind a message not merely to the credential holder's
signing key, but to the *intent* of the agent's principal at the moment of
authoring. For human peers, intent is implicit in authorship: the human
wrote the message. For LLM agents, an attacker can inject instructions
into the data the agent retrieves, and the agent will sign and send a
message that does not reflect its principal's intent.

- **M2M anchor — TLS 1.3 (RFC 8446).** TLS authenticates *the endpoint*,
  not the semantic origin of the message body: *"The TLS standard … does
  not specify how protocols add security with TLS; how to interpret the
  authentication certificates exchanged are left to the judgment of the
  designers."* TLS provides no mechanism to assert that the message body
  reflects the principal's intent rather than retrieved untrusted content.
- **Agent-specific anchor (indirect case) — Abdelnabi et al. [1].**
  Indirect prompt injection demonstrates that *"processing retrieved
  prompts can act as arbitrary code execution, manipulate the
  application's functionality, and control how and if other APIs are
  called,"* explicitly invalidating the assumption that data is
  separable from instructions in the agent setting.
- **Agent-specific anchor (direct case) — Perez & Ribeiro [13].**
  *"Ignore Previous Prompt"* documents the complementary direct
  prompt-override attack: a peer-supplied message can override the
  agent's prior instructions, again breaking the implicit binding
  between credential holder and authored intent. Together [1] and [13]
  cover both indirect (data-channel) and direct (message-channel) intent
  hijacking.
- **DelftClaw v4.0 status:** out of scope. WireFrame binds signing key to
  message bytes; intent is not attested.

### 2. Identity lineage and replication-aware delegation

The channel's identity layer must distinguish between an original agent
and its replicas/forks, and credential semantics must encode delegation
chains so receivers can reason about which principal a message reaches
them through. Human credentials assume a single principal per credential.

- **M2M anchor — X.509 / PKI (RFC 5280) and OIDC (per Garzon).** Garzon
  et al. [16] characterise the gap precisely: *"Traditional web security
  mechanisms (TLS, x.509, OIDC) carry inherent limitations when applied
  to autonomous agents, including limited support for delegation of
  authority, insufficient contextualization of trust decisions, and
  reliance on static trust models that fail to adapt dynamically."*
- **Agent-specific anchor — Garzon et al. [16].** They propose deputies
  in the DID document: *"permits declaring deputies in the DID doc, which
  allows encoding and enforcing complex human-to-agent and agent-to-agent
  owner relationships."*
- **DelftClaw v4.0 status:** partial — replication scaffolding exists
  (`replication/`) and the wire layer carries app pubkey, but the
  delegation-chain semantics in credentials are deferred.

### 3. Mid-conversation compromise containment

The channel must contain or signal compromise between consecutive
application messages. The "compromise propagates slowly" assumption holds
for humans and machines that cannot be redirected per-message; LLM agents
can.

- **M2M anchor — MLS (RFC 9420).** MLS provides post-compromise security
  but the rotation cadence is operator-driven, not per-message: *"Update
  messages SHOULD be sent at regular intervals of time as long as the
  group is active … It's left to the application to determine an
  appropriate amount of time between Updates."* In practice this is hours
  or days, not message-by-message.
- **Agent-specific anchor — Abdelnabi et al. [1] + Perez & Ribeiro [13]
  + Kong et al. [10].** Abdelnabi shows per-message compromise feasibility
  via indirect prompt injection; Perez & Ribeiro [13] document the direct
  prompt-override case (the *"Ignore Previous Prompt"* attack) — together
  they show that compromise can be triggered by a single inbound message,
  invalidating the slow-propagation assumption. Kong characterises the
  cumulative effect: *"the accumulation of tiny benign deviations on each
  step may lead to an intolerable risk in the final result."*
- **DelftClaw v4.0 status:** out of scope — the MLS / Double-Ratchet drop
  on 2026-05-05 explicitly punted forward secrecy and post-compromise
  security to deployment.

### 4. Per-message authentication and replay defence

Every application message must carry an Ed25519 signature over its
canonical bytes plus a nonce that's checked against a sliding window.
Channel-level (TLS-style) authentication is insufficient: a man-in-the-
stack at either endpoint of an established TLS connection can replace the
message body without detection.

- **M2M anchor — TLS 1.3 (RFC 8446).** TLS is point-to-point and
  message-content-agnostic above the record layer. Per Louck et al. [11],
  protocols that rely on TLS for message authenticity (A2A) are
  **VULNERABLE** to message tampering: A2A *"do not enforce per-message
  signing or nonce-based validation."*
- **Agent-specific anchor — Louck et al. [11].** Their taxonomy item
  *"Message Tampering and Man-in-the-Middle (MITM) Attacks"* finds A2A
  vulnerable; ACP **ROBUST** because *"JWS applied per MIME segment"*
  delivers *"comprehensive resilience to both passive interception and
  active message manipulation."*
- **DelftClaw v4.0 status:** ✅ satisfied — `WireFrame` carries
  per-message Ed25519 signature; `NonceCache` + 5-minute skew window in
  `communication/replay/`.

### 5. Credential-gated admission with selective disclosure

Joining a multi-party room requires a verifiable credential the joiner
holds; the channel must not require the joiner to leak the entire
credential to obtain admission.

- **M2M anchor — Mutual TLS / X.509.** mTLS reveals the entire client
  certificate to the server; selective disclosure is not in the standard.
  MLS RFC 9420 itself does not specify how members are authorized to join
  — *"Note that this does not necessarily imply that any member is
  actually allowed to evict other members; groups can enforce access
  control policies on top of these basic mechanisms."* Authorization is
  punted upward.
- **Agent-specific anchor — Garzon et al. [16].** Each agent gets a
  *"self-sovereign digital identity that combines a unique and
  ledger-anchored W3C Decentralized Identifier (DID) of an agent with a
  set of third-party issued W3C Verifiable Credentials (VCs)"* and uses
  *"verifiable presentation (VP) exchange at dialogue initiation"* with
  selective disclosure.
- **DelftClaw v4.0 status:** ✅ satisfied at the architectural level —
  `AdmissionGate` + `OpenClawAgentPolicy` + `IssuerAllowList` consume W3C
  VC presentations. SD-JWT and BBS+ format plugins are next-iteration
  work; the toy Ed25519 format is the v4.0 baseline.

### 6. Bonded participation (economic stake at admission)

Admission can require the joiner to lock economic value as a bond, raising
the cost of identity-creation attacks (Sybil, replication-spam) for which
agents are uniquely vulnerable because they replicate cheaply.

- **M2M anchor — every cited M2M secure-messaging protocol [2, 3, 4, 14].**
  None of MLS, MLS Architecture, Signal Double Ratchet, or DIDComm v2
  incorporates economic stake. Sybil resistance is delegated to the PKI
  layer above them, which has no quantitative cost.
- **Agent-specific anchor — Louck et al. [11] + Kong et al. [10].** Louck
  identifies *"Registry Pollution and Denial-of-Service (DoS)"* as a
  vulnerability category and finds A2A vulnerable; Kong notes attack
  success rates that would be amplified by cheap agent replication.
  Stake is the standard mitigation in agent-economic literature.
- **DelftClaw v4.0 status:** ✅ satisfied — `StakedAdmissionPolicy`
  composed via `CompositePolicy`; synthetic-BTC oracle in `stake/`.

### 7. In-band authenticated value transfer

The same channel that carries messages must carry verifiable value
transfer between admitted agents, so an authenticated payment or
settlement can be tied to the same agent identity that authored the
preceding negotiation messages — without crossing channel boundaries.

- **M2M anchor — DIDComm v2 [5] + traditional payment rails.** DIDComm
  defines an agent messaging envelope but does not specify a value-
  transfer payload type; cross-rail attribution (TLS chat ↔ SWIFT
  payment) requires correlation at an application layer outside both
  protocols.
- **Agent-specific anchor — Kong et al. [10] + Louck et al. [11].** Kong
  explicitly categorises *"agent-to-agent payment"* as a sub-class
  alongside coordination and task allocation; Louck observes that today,
  payment is unauthenticated within agent prompts: *"task delegation
  often embeds payment or scheduling parameters directly within prompt
  payloads,"* exposing them to LLM self-disclosure and prompt injection.
- **DelftClaw v4.0 status:** ✅ satisfied — `AgentChannel.transfer`
  produces a `StakeOp{TRANSFER}` signed by the same Ed25519 app-key that
  signs application messages; mirrored to remote oracle.

### 8. Tool-call scope binding

Credentials must encode which tools or actions the holder is authorised
to invoke, not just which group they may join. The credential should
constrain the call surface, not merely identity.

- **M2M anchor — OAuth 2.x scope semantics, as characterised by Louck
  et al. [11].** Louck shows that A2A's scope model is too coarse:
  *"coarse JSON-RPC scope definitions without nested hierarchy
  enforcement,"* and ACP achieves the *"strongest scoping model"* among
  the three evaluated protocols precisely by departing from generic
  OAuth scopes — *"operation-specific JWTs, effectively binding
  permissions to individual tasks."*
- **Agent-specific anchor — Kong et al. [10] + Louck et al. [11].** Kong
  identifies tool-execution authority as agent-specific risk; Louck's
  *"Tool Poisoning and Command Injection"* category finds A2A vulnerable
  because *"payloads are serialized and parsed without robust escaping
  or type validation."*
- **DelftClaw v4.0 status:** out of scope — `OpenClawAgentPolicy` is
  binary admit/reject; per-tool attestation is deferred.

### 9. Authenticated, signed capability discovery

When an agent advertises a capability or a room, the advertisement must
be signed by the identity that owns it. Otherwise discovery becomes a
spoofing vector — an attacker injects a fake endpoint and harvests
traffic.

- **M2M anchor — DNS / mDNS / standard service discovery.** None of the
  M2M-class discovery protocols cited by the plan provide cryptographic
  authenticity for advertisements; trust is bootstrapped out of band.
  Within the plan's cited refs, MLS RFC 9420 has *no discovery layer at
  all* — group membership is presumed.
- **Agent-specific anchor — Louck et al. [11].** *"Spoofing in Discovery
  Mechanisms"* — A2A is **VULNERABLE** because of *"absent end-to-end
  signing"* enabling *"forged capabilities, inject false endpoints, or
  impersonate trusted agents during dynamic discovery";* Kong's [10]
  category of *"agent spoofing"* covers the same surface.
- **DelftClaw v4.0 status:** deferred. The `RoomAdvertisementPayload`
  IPv8 message type exists in `communication/trustroom/advertisement.py`
  with the right shape, but the Advertiser is not yet implemented (M2
  carry-over deferral).

### 10. Verifiable, append-only audit trail of admission and revocation

The channel must produce a tamper-evident log of admission decisions and
revocations, signed by the deciding party and forwardable as evidence.
Without this, a fleet of replicating agents has no way to attribute or
contest decisions made by their peers.

- **M2M anchor — MLS RFC 9420 [2] + Signal [4, 14].** Standard secure-
  messaging protocols do not produce an audit log as a deliverable of
  the protocol — logging is deferred to the application. MLS does record
  group-state transitions in `commit` messages, but those are not
  designed for forwarding to a third-party auditor as standalone
  evidence.
- **Agent-specific anchor — Louck et al. [11].** *"Compliance Gaps"* —
  A2A *"omits persistent audit logging of sensitive events,"* CORAL is
  partial because its on-chain audit trail does not extend to
  *"off-chain threads."* Verifiable, forwardable evidence is an explicit
  requirement of every protocol they evaluate.
- **DelftClaw v4.0 status:** partial. The `redteam/primitives/signed_log.py`
  primitive provides the underlying append-only signed log; integration
  with `AgentChannel` (auto-logging admission decisions) is deferred.

## Summary table

| # | Property | M2M anchor | Agent anchor | v4.0 status |
|---|----------|-----------|--------------|-------------|
| 1 | Principal-intent binding | TLS 1.3 (RFC 8446) | Abdelnabi [1], Perez & Ribeiro [13] | out of scope |
| 2 | Identity lineage and replication-aware delegation | X.509, OIDC (per [16]) | Garzon [16] | partial |
| 3 | Mid-conversation compromise containment | MLS 9420 [2] | Abdelnabi [1], Perez & Ribeiro [13], Kong [10] | out of scope |
| 4 | Per-message auth + replay defence | TLS 1.3, A2A (per [11]) | Louck [11] | ✅ |
| 5 | Credential-gated admission with selective disclosure | mTLS, MLS 9420 [2] | Garzon [16] | ✅ |
| 6 | Bonded participation | MLS [2,3], Signal [4,14] | Louck [11], Kong [10] | ✅ |
| 7 | In-band authenticated value transfer | DIDComm v2 [5] | Kong [10], Louck [11] | ✅ |
| 8 | Tool-call scope binding | OAuth 2.x (per [11]) | Kong [10], Louck [11] | out of scope |
| 9 | Authenticated, signed discovery | DNS, MLS 9420 [2] | Louck [11], Kong [10] | deferred |
| 10 | Verifiable audit trail | MLS [2], Signal [4,14] | Louck [11] | partial |

The DelftClaw v4.0 status column is informational — SQ1 itself is
protocol-agnostic; the column simply notes how our own artefact tracks
against each property.

## Properties considered but not (yet) included

These were drafted but did not make the cut for the v0 list. Each is
either too contentious, too overlapping with an existing item, or
politically delicate; the supervisor decides whether to promote any
during the Week 3 lock.

- **Forward secrecy / post-compromise confidentiality at agent-message
  rates.** Already covered partially by Property 3. Calling it out
  explicitly forces the SQ2 matrix to mark MLS as covering it (true) and
  forces a confrontation with the project's 2026-05-05 decision to drop
  MLS. Defensible either way; flagged as politically delicate.
- **Anti-consent-fatigue.** Louck [11] identifies *"Consent Fatigue in
  Multi-Transaction Workflows"* as a unique agent-failure mode. Its M2M
  anchor (OAuth consent screens being human-attention-designed) is
  weaker than the others, and the property is more UX than channel.
- **LLM self-disclosure resistance.** Louck [11] documents *"Risk of
  Data Disclosure to the Agent Itself"* — the LLM may emit secrets
  embedded in its prompts. This is arguably an agent-runtime property
  rather than a channel property; the SQ1 question is scoped to the
  channel.
- **Multimodal input integrity.** Kong [10] identifies multimodal input
  surfaces. Same scoping concern: this lives in the agent runtime, not
  the channel.
- **Cross-protocol interoperability.** Kong [10] and Louck [11] both
  raise it. Important for SQ2 but not a property of any single channel
  in isolation.

## Open questions before lock

- The plan's reference list does not currently include TLS 1.3 (RFC 8446),
  X.509 (RFC 5280), or OAuth 2.x as cited M2M anchors. Properties 1, 2, 4,
  and 8 lean on these as the M2M baseline. Adding them to the plan's
  reference list is a one-line edit; without it, the success-criterion
  phrase *"one cited human/M2M protocol"* would be technically unmet
  for those four properties. **Decision needed at the Friday Week-3
  supervisor meeting.**
- Property 6 (Bonded participation) is a strong differentiator for
  DelftClaw — the design explicitly includes `StakedAdmissionPolicy` —
  but its agent-specific anchors are inferential rather than direct
  ("agents replicate cheaply, so stake is needed"). If the supervisor
  wants a tighter direct quote, an additional citation from the agent-
  economic literature would help — Louck [11] only mentions stake
  obliquely via *"smart contract vulnerabilities"* (her vulnerability
  #13).
- Property 10 (Verifiable audit trail) overlaps with Lucas's
  `redteam/primitives/signed_log.py`. SQ1 should claim the property at
  the *protocol* level; whether the audit-trail primitive belongs in the
  channel or in a separate accountability sub-project is a project-
  layout question, not an SQ1 question.

## Sources

Plan-cited (numbering matches `Research_plan.pdf`):

- [[1]](https://arxiv.org/abs/2302.12173) Abdelnabi et al., "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." AISec '23.
- [[2]](https://www.rfc-editor.org/rfc/rfc9420) Barnes et al., *The Messaging Layer Security (MLS) Protocol.* RFC 9420.
- [[3]](https://www.rfc-editor.org/rfc/rfc9750) Beurdouche et al., *The Messaging Layer Security (MLS) Architecture.* RFC 9750.
- [[4]](https://doi.org/10.1007/s00145-020-09360-1) Cohn-Gordon et al., *A Formal Security Analysis of the Signal Messaging Protocol.* J. Cryptology 33.4 (2020).
- [[5]](https://identity.foundation/didcomm-messaging/spec/v2.1/) Decentralized Identity Foundation, *DIDComm Messaging Specification v2.1.*
- [[8]](https://www.w3.org/TR/vc-data-model-2.0/) Herman et al., *Verifiable Credentials Data Model v2.0.* W3C Recommendation.
- [[10]](https://arxiv.org/abs/2506.19676) Kong et al., *A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense Countermeasures.*
- [[11]](https://arxiv.org/abs/2511.03841) Louck et al., *Security Analysis of Agentic AI Communication Protocols: A Comparative Evaluation.*
- [[13]](https://arxiv.org/abs/2211.09527) Perez & Ribeiro, *Ignore Previous Prompt: Attack Techniques For Language Models.*
- [[14]](https://signal.org/docs/specifications/doubleratchet/) Perrin & Marlinspike, *The Double Ratchet Algorithm.*
- [[16]](https://arxiv.org/abs/2511.02841) Garzon et al., *AI Agents with Decentralized Identifiers and Verifiable Credentials.* ICAART 2026.

Cited here but not yet in the plan's reference list (decision pending):

- IETF RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3*. Anchored by Properties 1, 4. <https://datatracker.ietf.org/doc/html/rfc8446>
- IETF RFC 5280, *Internet X.509 Public Key Infrastructure*. Anchored by Property 2.
- IETF RFC 6749 + 9700 family, *OAuth 2.x*. Anchored by Property 8 via [11].
