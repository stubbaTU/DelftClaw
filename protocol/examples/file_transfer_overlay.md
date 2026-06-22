# Identity

- name: file_transfer
- version: 1.0.0
- description: Chunked content transfer with out-of-order reassembly and whole-content hash verification — the file_share data path.
- lifecycle: peer-observer

# Messages

## FETCH_REQUEST

- msg_id: 1

| name | encoding | description |
|------|----------|-------------|
| content_id | hash20 | sha1[:20] identifier of the content the fetcher wants |

### Handler

On receipt of FETCH_REQUEST, look up ``content_id`` in ``self.served``.
If absent, drop silently. If present, split the content into
``CHUNK_SIZE``-byte chunks (the final chunk may be shorter), reply with a
FETCH_MANIFEST carrying the chunk count and ``sha256`` of the whole
content, then send one CHUNK per chunk in ascending ``seq`` order.

## FETCH_MANIFEST

- msg_id: 2

| name | encoding | description |
|------|----------|-------------|
| content_id | hash20 | identifier this manifest describes |
| total_chunks | uint16-be | number of CHUNK messages that make up the content |
| content_hash | hash32 | sha256 of the fully reassembled content |

### Handler

On receipt of FETCH_MANIFEST, create a transfer entry in
``self.transfers`` keyed by ``content_id.hex()`` recording
``total_chunks``, ``content_hash``, an empty chunk buffer, and a
not-yet-complete flag. A repeated manifest for the same content_id
resets the entry.

## CHUNK

- msg_id: 3

| name | encoding | description |
|------|----------|-------------|
| content_id | hash20 | identifier this chunk belongs to |
| seq | uint16-be | zero-based index of this chunk within the content |
| data | varlenH | raw bytes of this chunk |

### Handler

On receipt of CHUNK, find the transfer keyed by ``content_id.hex()``. If
there is none, or it is already complete, drop. If ``seq`` is not less
than the transfer's ``total_chunks``, drop. Otherwise store ``data`` at
``seq`` in the chunk buffer — a duplicate ``seq`` simply overwrites and
must not corrupt progress. When the buffer holds every chunk
(``0 .. total_chunks-1``), reassemble them in ``seq`` order, compute
``sha256`` of the result, mark the transfer complete with ``ok`` set to
whether that digest equals ``content_hash``, and send one FETCH_COMPLETE
carrying that ``ok``.

## FETCH_COMPLETE

- msg_id: 4

| name | encoding | description |
|------|----------|-------------|
| content_id | hash20 | identifier the verdict is about |
| ok | bool | true if the fetcher reassembled and verified the content |

### Handler

On receipt of FETCH_COMPLETE, record ``ok`` in ``self.completed`` keyed
by ``content_id.hex()``.

# Runtime State

| name | type | description |
|------|------|-------------|
| served | dict[bytes, bytes] | content_id -> content bytes this peer can serve (seeder side; populated out of band). |
| transfers | dict[str, dict] | content_id.hex() -> {total, content_hash, chunks (dict seq->bytes), complete, ok}; the fetcher's in-progress reassembly. |
| completed | dict[str, bool] | content_id.hex() -> ok verdict received via FETCH_COMPLETE (seeder side). |

# Constants

| name | type | value | description |
|------|------|-------|-------------|
| CHUNK_SIZE | int | 256 | maximum bytes per CHUNK message; the seeder splits served content into pieces of this size. |

# Errors

| code | name | policy |
|------|------|--------|
| 1 | malformed_payload | drop |
| 2 | unknown_content | drop |

# Dependencies

(none)

# Test Vectors

## FETCH_REQUEST

- fields: {"content_id": "0000000000000000000000000000000000000000"}
  bytes: 00000000 00000000 00000000 00000000 00000000

- fields: {"content_id": "1111111111111111111111111111111111111111"}
  bytes: 11111111 11111111 11111111 11111111 11111111

## FETCH_MANIFEST

- fields: {"content_id": "1111111111111111111111111111111111111111", "total_chunks": 3, "content_hash": "2cdf6e152315e807562e3265bea43b48fe82511242d002fc45a35d190067a3d0"}
  bytes: 11111111 11111111 11111111 11111111 11111111 0003 2cdf6e15 2315e807 562e3265 bea43b48 fe825112 42d002fc 45a35d19 0067a3d0

- fields: {"content_id": "0000000000000000000000000000000000000000", "total_chunks": 0, "content_hash": "0000000000000000000000000000000000000000000000000000000000000000"}
  bytes: 00000000 00000000 00000000 00000000 00000000 0000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

## CHUNK

- fields: {"content_id": "1111111111111111111111111111111111111111", "seq": 0, "data": "ABC"}
  bytes: 11111111 11111111 11111111 11111111 11111111 0000 0003 414243

- fields: {"content_id": "1111111111111111111111111111111111111111", "seq": 2, "data": "GHI"}
  bytes: 11111111 11111111 11111111 11111111 11111111 0002 0003 474849

## FETCH_COMPLETE

- fields: {"content_id": "1111111111111111111111111111111111111111", "ok": true}
  bytes: 11111111 11111111 11111111 11111111 11111111 01

- fields: {"content_id": "1111111111111111111111111111111111111111", "ok": false}
  bytes: 11111111 11111111 11111111 11111111 11111111 00
