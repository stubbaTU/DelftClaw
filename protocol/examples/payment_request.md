# Identity

- name: payment_request
- version: 1.0.0
- description: Request fake BTC from admitted community members, offer payments, and be notified when paid or declined.
- lifecycle: peer-observer

# Messages

## PAYMENT_REQUEST

- msg_id: 1

| name | encoding | description |
|------|----------|-------------|
| amount_sats | uint64-be | satoshis the sender is asking a peer to send |
| memo | varlenH-utf8 | utf-8 free-text reason for the request; may be empty |

### Handler

On receipt of PAYMENT_REQUEST, record the request in
``self.pending_requests`` keyed by the sending peer's mid hex
(``peer.mid.hex()``); the value is a dict ``{amount_sats, memo}``. If an
entry for that mid is already present, drop the duplicate without
overwriting it (first request wins until it is settled). If
``pending_requests`` already holds ``MAX_PENDING_REQUESTS`` entries, drop
the new request. No reply is sent by this handler — the receiving agent
decides separately whether to pay, offer, or decline.

## PAYMENT_OFFER

- msg_id: 2

| name | encoding | description |
|------|----------|-------------|
| amount_sats | uint64-be | satoshis the sender is unsolicitedly offering to pay |
| memo | varlenH-utf8 | utf-8 free-text note for the offer; may be empty |

### Handler

On receipt of PAYMENT_OFFER, append a dict ``{amount_sats, memo}`` to
``self.received_offers``. An offer is an unsolicited intent to pay this
agent (no prior PAYMENT_REQUEST). No reply is sent.

## PAYMENT_NOTIFY

- msg_id: 3

| name | encoding | description |
|------|----------|-------------|
| amount_sats | uint64-be | satoshis that were sent |
| txid | varlenH-utf8 | synthetic transaction id of the payment |

### Handler

On receipt of PAYMENT_NOTIFY, append a dict ``{amount_sats, txid}`` to
``self.received_payments``. The agent runtime polls ``received_payments``
to learn it has been paid. No reply is sent.

## PAYMENT_DECLINE

- msg_id: 4

| name | encoding | description |
|------|----------|-------------|
| reason | varlenH-utf8 | utf-8 explanation of why the request will not be fulfilled; may be empty |

### Handler

On receipt of PAYMENT_DECLINE, append a dict ``{reason}`` to
``self.declined`` — a peer has refused a request this agent made, so the
agent can ask someone else. No reply is sent.

# Runtime State

| name | type | description |
|------|------|-------------|
| pending_requests | dict[str, dict] | Requests this agent has received from peers, keyed by requester mid hex. Each value is a dict with keys: amount_sats (int), memo (str). Entries are removed when settled or expired by the sweep task. |
| received_offers | list[dict] | Unsolicited PAYMENT_OFFER messages received. Each dict has keys: amount_sats (int), memo (str). |
| received_payments | list[dict] | PAYMENT_NOTIFY messages received. Each dict has keys: amount_sats (int), txid (str). Agent runtime polls this list. |
| declined | list[dict] | PAYMENT_DECLINE messages received. Each dict has key: reason (str). |

# Constants

| name | type | value | description |
|------|------|-------|-------------|
| MAX_PENDING_REQUESTS | int | 64 | Upper bound on concurrent in-flight requests held in pending_requests; a PAYMENT_REQUEST arriving when the dict is full is dropped. |
| PENDING_REQUEST_TTL_S | int | 600 | Seconds after which an unsettled pending_requests entry is swept by the expire_requests task. |

# Tasks

| name | interval_s | handler | description |
|------|------------|---------|-------------|
| expire_requests | 60 | _expire_requests | drop pending_requests entries older than PENDING_REQUEST_TTL_S |

# Errors

| code | name | policy |
|------|------|--------|
| 1 | malformed_payload | drop |

# Dependencies

(none)

# Test Vectors

## PAYMENT_REQUEST

- fields: {"amount_sats": 0, "memo": ""}
  bytes: 0000000000000000 0000

- fields: {"amount_sats": 5000, "memo": "rent"}
  bytes: 0000000000001388 0004 72656e74

## PAYMENT_OFFER

- fields: {"amount_sats": 0, "memo": ""}
  bytes: 0000000000000000 0000

- fields: {"amount_sats": 2500, "memo": "gift"}
  bytes: 00000000000009c4 0004 67696674

## PAYMENT_NOTIFY

- fields: {"amount_sats": 0, "txid": ""}
  bytes: 0000000000000000 0000

- fields: {"amount_sats": 5000, "txid": "deadbeef"}
  bytes: 0000000000001388 0008 6465616462656566

## PAYMENT_DECLINE

- fields: {"reason": ""}
  bytes: 0000

- fields: {"reason": "broke"}
  bytes: 0005 62726f6b65
