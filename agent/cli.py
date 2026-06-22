"""``python -m agent`` — boot one OpenClaw node.

Subcommands:

  ``info``     print this agent's identity / address / pubkey then exit.
               The printed ``--peer`` line is what the *other* agent passes
               to introduce this one.

  ``mcp``      **production mode.** Boot the agent and serve the 12-tool
               surface over FastMCP streamable-HTTP. Each OpenClaw chat
               session connects to this server; OpenClaw is the LLM brain
               picking which tools to invoke. This is the deployment
               target on a VPS.

  ``run``      *offline-test mode.* Execute one query through an internal
               LLM tool-call loop (the agent picks tools itself). Used for
               tests + offline-stub development; production traffic goes
               through ``mcp``.

  ``serve``    *offline-test mode.* Long-running stdin->stdout loop; same
               internal-LLM-loop semantics as ``run`` but interactive.

Per-agent zero-shot configuration:

  ``--publish-overlay PATH`` (repeatable) — load + serve a `.md` overlay
      descriptor at boot. Peers fetch it via OVERLAY_REQUEST and compile
      it on their side; the publisher *and* every consumer end up running
      the protocol the markdown describes.

  ``--peer HOST:PORT:PUBKEY_HEX`` (repeatable) — pre-introduce a peer
      (no walker / DispersyBootstrap). Get a peer's PUBKEY_HEX from its
      ``info`` output.

  ``--system-prompt PATH`` — override the default LLM persona. Markdown
      file with the agent's role + permitted tool semantics; orthogonal
      to the network-protocol overlays.

Example two-agent flow::

    # Terminal 1 — Alice publishes the content overlay + acts as genesis:
    python -m agent --mnemonic 'army van defense ...' --port 8090 \\
        --publish-overlay protocol/examples/content_community.md \\
        --genesis path/to/delftclaw_network.md \\
        --llm-base-url http://<llm-host>:<port>/v1 --llm-model <model-id> \\
        info

    # Terminal 2 — Bob joins via the manifest (no --peer flag needed,
    # the manifest's genesis peer list pre-introduces Alice):
    python -m agent --mnemonic 'abandon abandon abandon ...' --port 8091 \\
        --manifest path/to/delftclaw_network.md \\
        --llm-base-url http://<llm-host>:<port>/v1 --llm-model <model-id> \\
        run --query "what files are stored on our claw network?"

The ``--llm-base-url`` defaults to ``http://127.0.0.1:11434/v1`` (local
Ollama, the dev/CI fallback). In production deployments under
``deploy/scenario_boot.py`` the endpoint is the supervisor's external
GPU host reached over Tailscale (``LLM_BASE_URL=http://100.73.168.12:11434/v1``
by default); see ``deploy/README.md``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from agent import (
    AgentConfig,
    OpenAICompatibleToolLLM,
    OpenClawAgent,
    StubToolLoopLLM,
    SYSTEM_PROMPT,
    build_tools,
    run_tool_loop,
)
from identity.agent_identity import AgentIdentity
from identity.seed import EnvSeedSource, KeyfileSeedSource, MnemonicSeedSource
from protocol import community_id_from_md
from protocol.llm import OpenAICompatibleClient


def is_publish_overlay_sentinel(value: str | None) -> bool:
    """True iff ``value`` is the empty / ``"none"`` no-publish sentinel.

    ``deploy.scenario_boot`` always emits a token for ``${PUBLISH_OVERLAY}``
    in the systemd unit expansion (an empty env var would break argparse),
    so it writes the literal string ``"none"`` when an agent has nothing to
    publish at boot. Both ``_publish_overlays`` here and the watchdog's
    snapshot-agent path in ``deploy/watchdog.py`` must filter the sentinel
    the same way — without this shared helper they drifted and the watchdog
    spent each boot logging ``failed to mirror published overlays in
    snapshot agent: 'none'``.
    """
    return value is None or not value.strip() or value.strip().lower() == "none"


def _load_seed(args: argparse.Namespace):
    if args.mnemonic:
        return MnemonicSeedSource(args.mnemonic).load()
    if args.seed_file:
        return KeyfileSeedSource(args.seed_file).load()
    if args.use_env:
        return EnvSeedSource().load()
    return KeyfileSeedSource().load()


def _build_compiler_llm(args: argparse.Namespace):
    """Build the LLM client the OverlayRegistry compiles every overlay with.

    Always a live LLM: every overlay — the ones an agent publishes at boot, the
    ones it wire-fetches from a peer, and the ones it authors at runtime — is
    compiled from its markdown descriptor by the model at ``--llm-base-url``.
    There is no pre-recorded-source shortcut.
    """
    return OpenAICompatibleClient(
        base_url=args.llm_base_url,
        model_id=args.llm_model,
        api_key=args.llm_api_key or "",
    )


def _build_tool_llm(args: argparse.Namespace):
    if args.llm_stub_script:
        with open(args.llm_stub_script, "r", encoding="utf-8") as f:
            scripted = json.load(f)
        return StubToolLoopLLM(responses=scripted)
    return OpenAICompatibleToolLLM(
        base_url=args.llm_base_url,
        model_id=args.llm_model,
        api_key=args.llm_api_key or "",
    )


def _read_system_prompt(args: argparse.Namespace) -> str:
    if not args.system_prompt:
        return SYSTEM_PROMPT
    return Path(args.system_prompt).read_text(encoding="utf-8")


def _parse_peer_spec(spec: str) -> tuple[str, int, str]:
    """``host:port:pubkey_hex`` -> (host, port, pubkey_hex). pubkey_hex may itself contain ``:``? No."""
    parts = spec.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"--peer must be host:port:pubkey_hex, got {spec!r}"
        )
    host, port_s, pubkey = parts
    try:
        port = int(port_s)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"--peer port not an int: {port_s!r}") from exc
    return host, port, pubkey


def _import_class_spec(spec: str) -> type:
    """Import ``module.path:ClassName`` and return the class object.

    Used by ``--register-community`` to materialise a hand-written
    ``Community`` subclass at boot. Errors out with a helpful
    ``argparse.ArgumentTypeError`` so the CLI exits cleanly on a typo.
    """
    if ":" not in spec:
        raise argparse.ArgumentTypeError(
            f"--register-community must be module.path:ClassName, got {spec!r}"
        )
    module_path, _, class_name = spec.partition(":")
    if not module_path or not class_name:
        raise argparse.ArgumentTypeError(
            f"--register-community must be module.path:ClassName, got {spec!r}"
        )
    import importlib

    try:
        module = importlib.import_module(module_path)
    except ImportError as exc:
        raise argparse.ArgumentTypeError(
            f"--register-community: cannot import {module_path!r}: {exc}"
        ) from exc
    cls = getattr(module, class_name, None)
    if cls is None:
        raise argparse.ArgumentTypeError(
            f"--register-community: module {module_path!r} has no attribute {class_name!r}"
        )
    if not isinstance(cls, type):
        raise argparse.ArgumentTypeError(
            f"--register-community: {spec!r} resolves to {type(cls).__name__}, not a class"
        )
    return cls


def _publish_overlays(agent: OpenClawAgent, paths: list[str]) -> list[tuple[str, str]]:
    """Load + serve each .md descriptor at boot. Returns [(name, md_hash_hex), ...].

    Every descriptor is compiled from its markdown by the live LLM
    (``agent.publish_overlay`` -> ``OverlayRegistry.load(..., provenance=
    "published")``). The registry's own disk cache means an identical
    descriptor compiled before reuses the model's earlier output rather than
    re-hitting the endpoint, but the source always originates from the LLM —
    there is no hand-written shortcut.
    """
    out: list[tuple[str, str]] = []
    for p in paths:
        md_text = Path(p).read_text(encoding="utf-8")
        cid_hex = community_id_from_md(md_text).hex()
        print(
            f"[boot] publishing {Path(p).name} via live LLM (cid={cid_hex[:12]}) "
            f"— this can stall if the endpoint is unreachable",
            flush=True,
        )
        # ``agent.publish_overlay`` publishes via the SeedboxCommunity AND
        # routes the compile through ``OverlayRegistry.load(..., provenance=
        # "published")``, which emits the ``OVERLAY compile`` / ``OVERLAY
        # install`` lifecycle events and writes the per-demo overlay archive.
        md_hash = agent.publish_overlay(md_text)
        compiled = agent.registry._compiled[md_hash]
        out.append((compiled.parsed.identity.get("name", Path(p).name), md_hash.hex()))
    return out


def _apply_seed_content(agent: OpenClawAgent, seed_content_file: str | None) -> None:
    """Prime boot-time content into loaded content overlays and BT stub.

    `scenario_boot` writes this JSON for seedbox agents from
    scenario.yaml's `seed_content`. The content overlay exposes `local_index`;
    this hook makes the preloaded catalog visible to SEARCH_REQUEST handlers.
    """
    if not seed_content_file:
        return
    path = Path(seed_content_file)
    if not path.is_file():
        print(f"[boot] seed content file missing: {path}", flush=True)
        return
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[boot] failed to parse seed content file {path}: {exc}", flush=True)
        return
    if not isinstance(rows, list):
        print(f"[boot] seed content file {path} is not a list", flush=True)
        return

    from communication.community import content_id_for_bytes

    index_rows: list[dict] = []
    # content_id (sha1[:20], == magnet btih) -> file bytes, for the
    # file_transfer overlay's ``served`` state (chunked transfer source side).
    served_map: dict[bytes, bytes] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        content_path = Path(str(row.get("path", "")))
        name = str(row.get("name") or content_path.name)
        if not content_path.is_file():
            # Catalog row references a missing file. Carry the metadata so
            # SEARCH still surfaces it, but do not advertise a magnet we
            # cannot serve — peers asking for it would silently time out.
            index_rows.append({
                "magnet": "",
                "name": name,
                "size": int(row.get("size") or 0),
                "mime": str(row.get("mime") or "application/octet-stream"),
                "tags": list(row.get("tags") or []),
            })
            continue

        # Derive the magnet's btih from the file's bytes so the receiver's
        # ``on_content_delivery`` self-verifies (no out-of-band trust).
        # Replaces the legacy stub.prime() path, which was per-process in-memory
        # and silently fabricated mock downloads for cross-process fetchers.
        data = content_path.read_bytes()
        content_id = content_id_for_bytes(data)
        magnet = f"magnet:?xt=urn:btih:{content_id.hex()}&dn={name}"
        agent.seedbox.publish_content(content_id, content_path)
        served_map[content_id] = data

        index_rows.append({
            "magnet": magnet,
            "name": name,
            "size": len(data),
            "mime": str(row.get("mime") or "application/octet-stream"),
            "tags": list(row.get("tags") or []),
        })

    applied = 0
    served_applied = 0
    for community_id in agent.registry.list_loaded():
        instance = agent.registry.get(community_id)
        if instance is None:
            continue
        # content_community discovery overlay
        if hasattr(instance, "local_index"):
            instance.local_index = list(index_rows)
            applied += 1
        # file_transfer chunked-transfer overlay (seeder side)
        if hasattr(instance, "served"):
            instance.served = dict(served_map)
            served_applied += 1
    print(
        f"[boot] loaded {len(index_rows)} seed content entries into {applied} "
        f"content overlay(s); seeded {len(served_map)} files into "
        f"{served_applied} transfer overlay(s)",
        flush=True,
    )


async def _serve_loop(
    agent: OpenClawAgent,
    args: argparse.Namespace,
    system_prompt: str,
) -> int:
    """Read queries from stdin, run the tool loop on each, print answers.

    EOF / Ctrl-D ends the loop. Each query gets a fresh tool-loop conversation.
    """
    tool_llm = _build_tool_llm(args)
    tools = build_tools(agent)
    print("[serve] ready. type a query and press enter; Ctrl-D to exit.", flush=True)
    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            print()
            return 0
        if not line:
            continue
        # The stub LLM script is single-shot; warn if asked to run multiple
        # queries with one.
        try:
            answer = await run_tool_loop(
                line, tool_llm, tools, system_prompt=system_prompt,
            )
        except Exception as exc:
            print(f"[serve] error: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        print(answer, flush=True)


async def _start_signed_log_server(
    agent, *, host: str, port: int,
) -> tuple[asyncio.Task, object]:
    """Spawn a uvicorn-hosted signed_log FastAPI server in the agent's event loop.

    Built via ``signed_log.integration.server.build_app`` against the
    agent's own ``OpenClawIdentity`` (so the served entries' identity
    binding matches) + the agent's ``community_log_path`` /
    ``peer_log_dir``. Returns the asyncio task running uvicorn and the
    ``uvicorn.Server`` instance (caller sets ``.should_exit`` for clean
    shutdown).

    Important: the FastAPI server's ``SignedAppendOnlyLog`` and
    ``PeerLog`` instances are NEW objects sharing the same on-disk
    files as the agent's. Two writers in one process would race on
    ``SignedAppendOnlyLog._lock``; we mitigate this by passing
    ``peers=[]`` so the FastAPI server's own pull loop stays disabled
    (the agent's runtime owns the pull loop). Reads (GET /head, GET
    /entries) are race-free because they snapshot the file under their
    own lock.
    """
    import uvicorn
    from signed_log.integration.server import build_app
    from identity.openclaw_identity import OpenClawIdentity

    oc_identity = OpenClawIdentity.from_agent_identity(agent.identity)
    log_path = agent.config.community_log_path or (agent.config.save_dir / "community.log")
    peer_log_dir = agent.config.peer_log_dir or (agent.config.save_dir / "peer_logs")

    app = build_app(
        identity=oc_identity,
        log_path=str(log_path),
        peer_log_dir=str(peer_log_dir),
        peers=[],                     # we run the pull loop ourselves, not in FastAPI
    )
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(), name=f"signed_log_server:{port}")
    return task, server


async def _run(args: argparse.Namespace) -> int:
    # Boot-path progress logs flush to journalctl so a hang between
    # systemd-Started and serve_mcp_async() is localisable. Each `[boot]`
    # line corresponds to one synchronous step that has historically been
    # a hang candidate (seed load, identity derivation, IPv8 start, overlay
    # compile, manifest load).
    print("[boot] loading seed", flush=True)
    seed = _load_seed(args)
    print("[boot] deriving identity", flush=True)
    identity = AgentIdentity.from_seed(seed, network=args.network)

    print("[boot] building compiler LLM client", flush=True)
    compiler_llm = _build_compiler_llm(args)
    # Phase 6 env-var fallbacks. Systemd templated units can't easily
    # build repeated --peer-log-url flags from a single env var, so we
    # also read PEER_LOG_URLS (space-separated), COMMUNITY_LOG_PATH,
    # and PEER_LOG_DIR from the environment when the CLI flags aren't
    # given. The CLI flag always wins when both are set.
    import os as _os
    peer_log_urls: list[str] = list(args.peer_log_url or [])
    if not peer_log_urls:
        env_urls = _os.environ.get("PEER_LOG_URLS", "").strip()
        if env_urls:
            peer_log_urls = env_urls.split()
    community_log_path = args.community_log_path or _os.environ.get("COMMUNITY_LOG_PATH")
    peer_log_dir = args.peer_log_dir or _os.environ.get("PEER_LOG_DIR")

    config = AgentConfig(
        port=args.port,
        address=args.address,
        btc_network=args.btc_network,
        save_dir=Path(args.save_dir),
        initial_balance_sats=args.initial_balance_sats,
        community_log_path=Path(community_log_path) if community_log_path else None,
        peer_log_dir=Path(peer_log_dir) if peer_log_dir else None,
        peer_log_urls=tuple(peer_log_urls),
        pull_interval_s=args.pull_interval_s,
        pull_batch=args.pull_batch,
    )
    print(f"[boot] constructing agent (port={args.port}, btc={args.btc_network})", flush=True)
    agent = OpenClawAgent(identity=identity, llm=compiler_llm, config=config)
    print("[boot] starting IPv8 + SeedboxCommunity", flush=True)
    await agent.start()
    print("[boot] IPv8 up", flush=True)

    # Publish overlays at boot (if any). Done before peer-introduction so
    # peers immediately see the descriptor in our published map when they
    # ask. Filter the systemd-empty / sentinel ``"none"`` value so a
    # wire-distribute agent (which has nothing to publish at boot) does
    # not call _publish_overlays with a bogus path.
    overlay_paths = [
        p for p in (args.publish_overlay or [])
        if p and p.strip().lower() != "none"
    ]
    if overlay_paths:
        print(f"[boot] publishing {len(overlay_paths)} overlay(s)", flush=True)
    published = _publish_overlays(agent, overlay_paths)
    _apply_seed_content(agent, _os.environ.get("SEED_CONTENT_FILE"))

    # Register hand-written Python Community classes (if any). These are
    # LOCAL-ONLY — they do not flow over the wire because Python bytecode
    # has no canonical transmittable form. Colleagues running static
    # protocol experiments use this path instead of the markdown one.
    registered_classes: list[tuple[str, str]] = []
    for spec in args.register_community or []:
        cls = _import_class_spec(spec)
        instance = agent.registry.register_community(cls)
        registered_classes.append((cls.__name__, instance.community_id.hex()))

    # Network manifest: either consume one (--manifest) or publish one (--genesis).
    manifest_loaded: Optional[str] = None
    if args.manifest:
        print(f"[boot] loading manifest from {args.manifest}", flush=True)
        md_text = Path(args.manifest).read_text(encoding="utf-8")
        manifest = agent.load_manifest(md_text)
        manifest_loaded = f"consumed {manifest.identity.get('name', '?')} ({manifest.network_id.hex()[:8]})"
        # Wire-fetch any default_overlays this agent does not already hold
        # locally. Genesis peers were just pre-introduced by load_manifest,
        # so a fetch over the bootstrap community can succeed immediately.
        # Per-overlay failures are non-fatal: operator-driven flows
        # (overlay_fetch_and_load) can retry.
        try:
            loaded, errors = await agent.ensure_default_overlays_loaded()
            if loaded:
                print(f"[boot] wire-loaded {len(loaded)} default overlay(s)", flush=True)
            for entry in errors:
                print(f"[boot] WARN overlay fetch failed: {entry}", flush=True)
        except Exception as exc:
            print(f"[boot] WARN ensure_default_overlays_loaded raised: {exc}", flush=True)
    elif args.genesis:
        print(f"[boot] loading genesis manifest from {args.genesis}", flush=True)
        md_text = Path(args.genesis).read_text(encoding="utf-8")
        manifest = agent.load_manifest(md_text)
        manifest_loaded = f"published {manifest.identity.get('name', '?')} ({manifest.network_id.hex()[:8]})"

    # Pre-introduce peers (skip walker / DispersyBootstrap entirely).
    introduced: list[tuple[str, int, str]] = []
    for spec in args.peer or []:
        host, port, pubkey_hex = _parse_peer_spec(spec)
        peer = agent.add_peer(host, port, pubkey_hex)
        introduced.append((host, port, peer.mid.hex()))

    print(
        f"[agent] addr={agent.address[0]}:{agent.address[1]}  "
        f"mid={identity.ipv8.raw_pubkey.hex()[:16]}  "
        f"wallet={agent.wallet.address()}",
        flush=True,
    )
    if published:
        for name, md_hash_hex in published:
            print(f"[agent] published overlay: {name}  md_hash={md_hash_hex}", flush=True)
    if registered_classes:
        for cls_name, cid_hex in registered_classes:
            print(f"[agent] registered python community: {cls_name}  community_id={cid_hex}", flush=True)
    if manifest_loaded:
        print(f"[agent] manifest: {manifest_loaded}", flush=True)
    if introduced:
        for host, port, mid_hex in introduced:
            print(f"[agent] introduced peer: {host}:{port}  mid={mid_hex[:16]}", flush=True)

    system_prompt = _read_system_prompt(args)

    try:
        if args.cmd == "info":
            loaded: list[dict] = []
            for cid, compiled in agent.registry._compiled.items():
                if compiled.parsed is not None:
                    name = compiled.parsed.identity.get("name", "")
                else:
                    name = compiled.community_class.__name__
                loaded.append({
                    "name": name,
                    "community_id_hex": cid.hex(),
                    "origin": compiled.origin,
                })
            print(json.dumps({
                "agent_id": str(identity.agent_id),
                "ipv8_address": list(agent.address),
                "ipv8_pubkey_hex": agent.pubkey_hex,
                "wallet_address": agent.wallet.address(),
                "btc_network": args.btc_network,
                "loaded_overlays": loaded,
                "peer_introduce_line":
                    f"--peer {agent.address[0]}:{agent.address[1]}:{agent.pubkey_hex}",
            }, indent=2))
            return 0

        if args.cmd == "run":
            tool_llm = _build_tool_llm(args)
            tools = build_tools(agent)
            answer = await run_tool_loop(
                args.query, tool_llm, tools, system_prompt=system_prompt,
            )
            print(answer)
            return 0

        if args.cmd == "serve":
            return await _serve_loop(agent, args, system_prompt)

        if args.cmd == "mcp":
            from agent.mcp_server import serve_mcp_async
            print(
                f"[mcp] serving streamable-HTTP on {args.mcp_host}:{args.mcp_port}; "
                f"point OpenClaw at http://{args.mcp_host}:{args.mcp_port}/mcp",
                flush=True,
            )
            # Phase 6: spawn a signed_log FastAPI sub-server when requested,
            # so peers running their own pull loops can fetch our
            # community-log entries. Shares the same on-disk files as
            # the agent's own SignedAppendOnlyLog / PeerLog; the
            # FastAPI uvicorn task is cancelled in ``finally``.
            signed_log_task = None
            signed_log_server = None
            if getattr(args, "signed_log_port", 0):
                signed_log_task, signed_log_server = await _start_signed_log_server(
                    agent, host=args.signed_log_host, port=args.signed_log_port,
                )
                print(
                    f"[signed_log] serving signed-log on "
                    f"http://{args.signed_log_host}:{args.signed_log_port}",
                    flush=True,
                )
            try:
                await serve_mcp_async(agent, host=args.mcp_host, port=args.mcp_port)
            finally:
                if signed_log_server is not None and signed_log_task is not None:
                    signed_log_server.should_exit = True
                    try:
                        await asyncio.wait_for(signed_log_task, timeout=5.0)
                    except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                        signed_log_task.cancel()
            return 0

        sys.stderr.write(f"unknown cmd: {args.cmd}\n")
        return 2
    finally:
        await agent.stop()


def main() -> int:
    # Surface INFO-level structured logs (IPv8 wire events from
    # ``communication.community._log_wire``, pull-loop progress, etc.)
    # to stderr → systemd journal. Format mirrors uvicorn's access log
    # so journalctl filters look the same across HTTP + IPv8 events.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        prog="python -m agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )

    # Identity / network selection.
    parser.add_argument("--mnemonic")
    parser.add_argument("--seed-file")
    parser.add_argument("--use-env", action="store_true")
    parser.add_argument("--network", default="TESTNET",
                        help="logical IPv8/app network identifier")
    parser.add_argument("--btc-network", default="testnet",
                        help="Bitcoin network: testnet (default) or bitcoin")

    # IPv8 transport.
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--save-dir", default="./downloads")
    parser.add_argument("--initial-balance-sats", type=int, default=0,
                        help="synthetic per-agent wallet balance the LLM sees via "
                             "wallet_balance; 0 disables (legacy always-zero mock)")
    parser.add_argument("--peer-log-url", action="append", metavar="URL",
                        default=[],
                        help="repeatable; full base URL (http(s)://host:port) of a peer's "
                             "signed_log.integration.server. The agent pulls community-log "
                             "entries from each URL in a background asyncio task. "
                             "Empty list disables the pull loop entirely.")
    parser.add_argument("--pull-interval-s", type=float, default=5.0,
                        help="seconds between pull-loop iterations per peer (default 5.0)")
    parser.add_argument("--pull-batch", type=int, default=100,
                        help="max entries per pull request (default 100)")
    parser.add_argument("--community-log-path", default=None,
                        help="path to this agent's signed community-log file "
                             "(default <save_dir>/community.log)")
    parser.add_argument("--peer-log-dir", default=None,
                        help="path to this agent's peer-log cache directory "
                             "(default <save_dir>/peer_logs)")

    # Per-agent zero-shot config.
    parser.add_argument("--publish-overlay", action="append", metavar="PATH",
                        help="repeatable; load + serve a markdown overlay descriptor at boot")
    parser.add_argument("--register-community", action="append",
                        metavar="MODULE.PATH:ClassName",
                        help="repeatable; register a hand-written Community subclass "
                             "at boot. LOCAL-ONLY — the class is not advertised over "
                             "the bootstrap community (no canonical text representation).")
    parser.add_argument("--peer", action="append", metavar="HOST:PORT:PUBKEY_HEX",
                        help="repeatable; pre-introduce a peer at boot (skip walker)")
    parser.add_argument("--system-prompt", metavar="PATH",
                        help="path to a markdown file overriding the LLM persona")
    # Mutually exclusive: an agent either CONSUMES a manifest (--manifest)
    # or PUBLISHES one as genesis (--genesis). --genesis is wired in Step 9.
    manifest_group = parser.add_mutually_exclusive_group()
    manifest_group.add_argument("--manifest", metavar="PATH",
                                help="path to a network manifest .md to load + cache at boot "
                                     "(consumer side: pre-introduces genesis peers)")
    manifest_group.add_argument("--genesis", metavar="PATH",
                                help="path to a network manifest .md to PUBLISH (genesis side: "
                                     "agent advertises this network and serves its default overlays)")

    # LLM endpoint. The defaults point at the local LLM proxy (-> Claude),
    # matching ``deploy/watchdog.py``'s fallback. In production, scenario_boot
    # writes ``LLM_BASE_URL`` + ``LLM_MODEL`` into each agent's env file
    # and the systemd unit passes them on the CLI explicitly — so these
    # defaults are only hit when invoking ``python -m agent`` by hand.
    parser.add_argument("--llm-base-url", default="http://127.0.0.1:11600/v1")
    parser.add_argument("--llm-model", default="claude-haiku-4-5-20251001")
    parser.add_argument("--llm-api-key", default="")
    parser.add_argument("--llm-stub-script",
                        help="JSON file of chat-completions message dicts (offline mode for the tool loop)")

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info", help="print agent identity / address / pubkey then exit")
    mcp_p = sub.add_parser(
        "mcp",
        help="serve the 12-tool surface over FastMCP streamable-HTTP for OpenClaw",
    )
    mcp_p.add_argument("--mcp-host", default="127.0.0.1",
                       help="bind host for the MCP server (use 0.0.0.0 on a VPS)")
    mcp_p.add_argument("--mcp-port", type=int, default=8765,
                       help="bind port for the MCP server")
    mcp_p.add_argument("--signed-log-host", default="127.0.0.1",
                       help="bind host for the signed_log FastAPI server hosting our "
                            "community signed log (peers' pull loops fetch from here)")
    mcp_p.add_argument("--signed-log-port", type=int, default=0,
                       help="bind port for the signed_log FastAPI server; 0 disables "
                            "(then peers can't pull this agent's log)")
    run_p = sub.add_parser(
        "run",
        help="(offline-test) execute one query through the internal LLM tool-call loop",
    )
    run_p.add_argument("--query", required=True)
    sub.add_parser(
        "serve",
        help="(offline-test) read queries from stdin via the internal LLM loop",
    )

    args = parser.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
