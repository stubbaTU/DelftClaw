# Goal — Bob

**Find and download a Creative Commons audio file from Alice's seedbox.**

You know one peer: Alice. Her IPv8 endpoint and your bootstrap
introduction were wired up before this scenario started, so she'll
appear in your STATE snapshot under `peers`.

Recipe (do not deviate unless the snapshot tells you a step already
succeeded):

1. **Read STATE.** Find Alice in `peers`. Note her `mid_hex`.
2. **Discover Alice's wallet address.** Call `peers_list` — no — STATE
   already shows your peers. Call `wallet_address` on yourself if you
   need your own address. For Alice's wallet, ask her seedbox via the
   bootstrap layer by invoking the content community once she has it,
   OR (simpler) call `seedbox_donate_and_join` and let it take care of
   the donation. The donation tool needs Alice's wallet address — use
   the value the operator may have left in the scenario's `peers` map
   if STATE includes it; otherwise call `seedbox_donate_and_join` with
   the address that appears in any inbound notice you've received.

   For this scenario, Alice's wallet address WILL be in your STATE
   under `peers[i].wallet_address` once she's introduced. If it isn't,
   reply with a status message saying you're waiting and the watchdog
   will tick again.
3. **Donate + join.** Call `seedbox_donate_and_join(gatekeeper_mid=...,
   sats=10000, gatekeeper_address=alice_wallet)`.
4. **Fetch the content community.** Call `overlay_fetch_and_load(
   peer_mid=alice_mid_hex, md_hash_hex=<the content_community md_hash;
   you can see it in `overlays` if you already loaded it locally>)`.
5. **Search.** Call `overlay_invoke(community_id_hex=<content_md_hash>,
   message_name="SEARCH_REQUEST", peer_mid=alice_mid_hex,
   fields={"query": "creative commons"})`.
6. **Pick the first result with mime starting with `audio/`** from
   STATE on the next tick.
7. **Fetch the magnet.** Call `torrent_fetch(magnet_uri=<the magnet>)`.

You stop when `torrent_stats` reports `progress >= 1.0` for that magnet.
The watchdog evaluates this each tick — you do not have to declare
"done" yourself.
