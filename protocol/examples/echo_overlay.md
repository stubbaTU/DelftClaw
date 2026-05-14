# Identity

- name: echo
- version: 1.0.0
- description: Round-trip echo overlay for compiler testing.
- lifecycle: peer-observer

# Messages

## ECHO_REQUEST

- msg_id: 1

| name | encoding | description |
|------|----------|-------------|
| payload | varlenH-utf8 | utf-8 string the receiver will echo back |

### Handler

On receipt of ECHO_REQUEST, send ECHO_RESPONSE whose payload is the
received payload (utf-8 decoded) with an exclamation mark appended,
re-encoded as utf-8 bytes.

## ECHO_RESPONSE

- msg_id: 2

| name | encoding | description |
|------|----------|-------------|
| payload | varlenH-utf8 | utf-8 string the sender originally requested, with a trailing exclamation mark |

### Handler

On receipt of ECHO_RESPONSE, append the decoded utf-8 string to
``self.received_responses``. The sender side correlates responses
out-of-band (tests poll ``received_responses`` directly).

# Runtime State

| name | type | description |
|------|------|-------------|
| received_responses | list[str] | utf-8 strings collected from ECHO_RESPONSE messages, in arrival order. Tests poll this directly. |

# Errors

| code | name | policy |
|------|------|--------|
| 1 | malformed_payload | drop |

# Dependencies

(none)

# Test Vectors

## ECHO_REQUEST

- fields: {"payload": ""}
  bytes: 0000

- fields: {"payload": "hi"}
  bytes: 00026869

- fields: {"payload": "ping"}
  bytes: 000470696e67

## ECHO_RESPONSE

- fields: {"payload": ""}
  bytes: 0000

- fields: {"payload": "hi!"}
  bytes: 0003686921

- fields: {"payload": "ping!"}
  bytes: 000570696e6721
