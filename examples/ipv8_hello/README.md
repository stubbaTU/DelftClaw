# `examples/ipv8_hello/` — minimal py-ipv8 community

Two peers, one message type, one handler. The smallest readable example of
how peer discovery and messaging fit together in py-ipv8. Use this to
understand the moving parts before reading `communication/trustroom/community.py`,
which uses the same primitives but has five message types and a real wire
format on top.

## Run it

From the repository root, with the project venv active:

```
python -m examples.ipv8_hello.run_two_peers
```

You should see something like:

```
[abc12345] HelloCommunity started
[def67890] HelloCommunity started
[def67890] received hello text='hello from A' counter=42 from peer=abc12345

example succeeded — B received the HelloPayload from A
```

The 8-character hex strings are the first bytes of each peer's IPv8 ``mid``.
A and B may print in either order at startup; the receive log line always
shows on B.

## What it demonstrates

1. **Defining a wire message.**
   `HelloPayload` (in `hello_community.py`) is a `VariablePayload` decorated
   with `@vp_compile`. It declares two on-wire fields:

   - `text: varlenH` — uint16-length-prefixed bytes
   - `counter: I` — uint32 big-endian

   `vp_compile` generates the (de)serialisation code so the handler receives
   a typed object instead of raw bytes.

2. **Subclassing `Community`.**
   `HelloCommunity` sets a 20-byte `community_id` (the IPv8 contract) and
   registers `on_hello` as the handler for `HelloPayload` via
   `add_message_handler`. The `@lazy_wrapper(HelloPayload)` decorator on
   `on_hello` deserialises the inbound bytes before calling the function.

3. **The IPv8 service lifecycle.**
   `run_two_peers.py` builds an `ipv8.IPv8` service for each peer using
   `ConfigBuilder`. The minimal config is: one curve25519 key file, one
   address, one overlay with no walkers and no bootstrappers. Once
   `await service.start()` returns, the overlay is loaded and `started()`
   has fired.

4. **Sending and receiving.**
   `say_hello` calls `self.ez_send(peer, HelloPayload(...))`. IPv8 prefixes
   the community id and message id, signs with the local Ed25519 transport
   key, and ships the UDP datagram. On the receiving side, IPv8 demuxes by
   community id and message id, runs the lazy_wrapper, and invokes
   `on_hello`.

5. **Manual peer attachment.**
   The example skips the discovery walker by calling
   `comm_a.network.add_verified_peer(peer_b)` directly. A real deployment
   uses bootstrap servers (`DispersyBootstrapper`) or DHT-based walkers
   (`RandomWalk`) — we drop those here so the script is self-contained and
   doesn't require network access beyond loopback.

## Files

| File | Purpose |
|---|---|
| `hello_community.py` | The `HelloCommunity` class and `HelloPayload` wire type. |
| `run_two_peers.py` | Boots two `IPv8` services on `127.0.0.1:9091` and `127.0.0.1:9092`, attaches A→B, sends one message, prints the result. |
| `__init__.py` | Re-exports the public surface for `import examples.ipv8_hello`. |

## How this maps to the production code

The production Trustroom code uses the same three primitives:

- `communication/trustroom/community.py:30–63` defines five `VariablePayload`
  classes (one per `MsgId`).
- `communication/trustroom/community.py:65–89` is `class TrustroomCommunity
  (Community)` with `add_message_handler` calls in `__init__`.
- `communication/trustroom/community.py:124` calls
  `self.ez_send(peer, ApplicationMessagePayload(frame=frame_bytes))` — same
  shape as `say_hello` here.
- `tests/test_ipv8_two_peer.py` exercises the whole chain on top of
  `IPv8Runtime`, the project's lifecycle adapter around the IPv8 service.

So this example is the same picture, just with one message type and no
upper layers (no admission, no encryption, no replay defense). Once it
makes sense, the production code reads as "the same pattern, plus those
upper layers."

## Suggested experiments

- Add a reply: have `on_hello` call `self.ez_send(peer, GoodbyePayload(...))`
  and watch the second message land back at A.
- Send 100 messages with sequential counters and inspect the order in which
  they arrive (UDP gives no ordering guarantee).
- Drop a sleep inside `on_hello` to see what happens to the asyncio event
  loop while a handler is busy.
- Spin up a third peer and observe how `add_verified_peer` scales — does C
  see A's traffic if you only attach C↔B?
