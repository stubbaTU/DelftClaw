# Identity

- name: content_community
- version: 1.0.0
- description: Search the local content index of an admitted seedbox; results are BitTorrent magnet links.

# Messages

## SEARCH_REQUEST

- msg_id: 1

| name | encoding | description |
|------|----------|-------------|
| query | varlenH-utf8 | utf-8 search string; empty string returns the full index |

### Handler

On receipt of SEARCH_REQUEST, scan the local content index using a
case-insensitive substring match against each entry's ``name`` and any
free-text tags. Return up to 50 entries via SEARCH_RESPONSE in declared
order. An empty query returns the full index (truncated to 50 entries).

## SEARCH_RESPONSE

- msg_id: 2

| name | encoding | description |
|------|----------|-------------|
| results | varlenH-msgpack | msgpack-encoded list of result dicts: {magnet, name, size, mime} |

### Handler

On receipt of SEARCH_RESPONSE, decode the msgpack list and append each
entry to the requester's local search-result cache. The agent runtime
polls the cache to surface results to the user. No reply is sent.

# Errors

| code | name | policy |
|------|------|--------|
| 1 | malformed_payload | drop |

# Dependencies

(none)

# Test Vectors

## SEARCH_REQUEST

- fields: {"query": ""}
  bytes: 0000

- fields: {"query": "cc"}
  bytes: 00026363

- fields: {"query": "Creative Commons"}
  bytes: 0010 437265617469766520436f6d6d6f6e73

## SEARCH_RESPONSE

- fields: {"results": []}
  bytes: 0001 90

- fields: {"results": [{"magnet": "magnet:?xt=urn:btih:abc", "name": "test.mp3", "size": 1234567, "mime": "audio/mpeg"}]}
  bytes: 00 49 91 84 a6 6d 61 67 6e 65 74 b7 6d 61 67 6e 65 74 3a 3f 78 74 3d 75 72 6e 3a 62 74 69 68 3a 61 62 63 a4 6e 61 6d 65 a8 74 65 73 74 2e 6d 70 33 a4 73 69 7a 65 ce 00 12 d6 87 a4 6d 69 6d 65 aa 61 75 64 69 6f 2f 6d 70 65 67
