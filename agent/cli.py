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
from protocol.llm import OpenAICompatibleClient, StubLLMClient


def _load_seed(args: argparse.Namespace):
    if args.mnemonic:
        return MnemonicSeedSource(args.mnemonic).load()
    if args.seed_file:
        return KeyfileSeedSource(args.seed_file).load()
    if args.use_env:
        return EnvSeedSource().load()
    return KeyfileSeedSource().load()


def _discover_stub_sources(md_paths: list[str]) -> dict[str, str]:
    """For each `foo.md` next to a `foo_stub.py` exporting an `*_SOURCE` constant,
    return ``{community_id_hex: fenced_source}`` so a ``StubLLMClient`` can route.

    When ``md_paths`` is empty (or contains only empty / sentinel entries),
    fall back to scanning every ``*_stub.py`` next to a sibling ``*.md``
    under ``protocol/examples/``. This is the wire-distribute case: an
    agent that does not publish anything at boot may still receive a
    descriptor over the wire and need to stub-compile it locally. Without
    this fallback, ``--compiler-stub`` would refuse to start.
    """
    import importlib.util
    # Treat empty strings and the literal ``"none"`` sentinel as "no path
    # given" so the systemd unit's ``--publish-overlay ${PUBLISH_OVERLAY}``
    # expansion can pass a value even when the env var is unset.
    md_paths = [p for p in md_paths if p and p.strip().lower() != "none"]
    if not md_paths:
        examples_dir = Path(__file__).resolve().parent.parent / "protocol" / "examples"
        md_paths = [str(p) for p in examples_dir.glob("*.md")]
    sources: dict[str, str] = {}
    for md_path in md_paths:
        md_path_obj = Path(md_path)
        stub_path = md_path_obj.with_name(md_path_obj.stem + "_stub.py")
        if not stub_path.exists():
            continue
        spec = importlib.util.spec_from_file_location(stub_path.stem, str(stub_path))
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Convention: a single `*_SOURCE` constant exporting the python source.
        source_const = next(
            (getattr(module, n) for n in dir(module) if n.endswith("_SOURCE") and isinstance(getattr(module, n), str)),
            None,
        )
        if source_const is None:
            continue
        cid_hex = community_id_from_md(md_path_obj.read_text(encoding="utf-8")).hex()
        sources[cid_hex] = "```python\n" + source_const + "```"
    return sources


def _build_compiler_llm(args: argparse.Namespace):
    """The OverlayRegistry uses this. In stub mode, route by community_id_hex."""
    if args.compiler_stub:
        sources = _discover_stub_sources(args.publish_overlay or [])
        if not sources:
            raise SystemExit(
                "--compiler-stub requires at least one --publish-overlay whose sibling "
                "*_stub.py file exports a *_SOURCE constant."
            )
        return StubLLMClient(sources=sources)
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

    If a ``foo.md`` has a sibling ``foo_stub.py`` exporting a ``*_SOURCE``
    constant we route the stub LLM client to it for *this descriptor*.
    That keeps boot fast: the LLM endpoint isn't hit unless a peer ships
    an overlay we've never seen.

    The agent's own LLM client (set at construction time) is preserved
    for descriptors that *don't* have a stub sibling.
    """
    from protocol import StubLLMClient, community_id_from_md, OverlayRegistry
    from protocol.compiler import compile_overlay

    out: list[tuple[str, str]] = []
    stub_sources = _discover_stub_sources(paths)
    if paths and not stub_sources:
        # Loud warning: stub discovery returned nothing despite overlays being
        # listed. Either the sibling _stub.py is missing from this deploy or
        # its *_SOURCE constant disappeared. The fallback path hits whatever
        # `agent.llm` is — under --compiler-stub that's a StubLLMClient with
        # no recorded source for this cid, so the compile raises KeyError.
        print(
            f"[boot] WARNING: no *_stub.py sibling found for any of "
            f"{paths!r}; falling back to live LLM compile",
            flush=True,
        )
    for p in paths:
        md_text = Path(p).read_text(encoding="utf-8")
        cid_hex = community_id_from_md(md_text).hex()
        # Local "publish + load" — same effect as agent.publish_overlay but
        # we route compile via the stub source if available.
        agent.seedbox.publish_overlay(md_text)
        if cid_hex in stub_sources:
            print(f"[boot] compiling {Path(p).name} from stub (cid={cid_hex[:12]})", flush=True)
            stub_llm = StubLLMClient(sources={cid_hex: stub_sources[cid_hex]})
            # Compile via stub and register manually (matches OverlayRegistry.load).
            compiled = compile_overlay(md_text, stub_llm)
            instance = compiled.community_class(agent.registry._build_settings())
            with agent.ipv8.overlay_lock:
                agent.ipv8.overlays.append(instance)
            if hasattr(instance, "started"):
                instance.started()
            agent.registry._compiled[compiled.community_id] = compiled
            agent.registry._instances[compiled.community_id] = instance
            md_hash = compiled.community_id
        else:
            # No stub sibling — the agent's normal LLM-backed registry path
            # runs and may take a while on cold start.
            print(
                f"[boot] compiling {Path(p).name} via live LLM (cid={cid_hex[:12]}) "
                f"— this can stall if the endpoint is unreachable",
                flush=True,
            )
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

    index_rows: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        content_path = Path(str(row.get("path", "")))
        magnet = str(row.get("magnet") or "")
        if content_path.is_file() and not magnet:
            magnet = agent.bittorrent.seed(content_path)
        if content_path.is_file() and hasattr(agent.bittorrent, "prime") and magnet:
            agent.bittorrent.prime(magnet, content_path)  # type: ignore[attr-defined]
        index_rows.append({
            "magnet": magnet,
            "name": str(row.get("name") or content_path.name),
            "size": int(row.get("size") or (content_path.stat().st_size if content_path.exists() else 0)),
            "mime": str(row.get("mime") or "application/octet-stream"),
            "tags": list(row.get("tags") or []),
        })

    applied = 0
    for community_id in agent.registry.list_loaded():
        instance = agent.registry.get(community_id)
        if instance is not None and hasattr(instance, "local_index"):
            instance.local_index = list(index_rows)
            applied += 1
    print(
        f"[boot] loaded {len(index_rows)} seed content entries into {applied} overlay(s)",
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


async def _start_redteam_server(
    agent, *, host: str, port: int,
) -> tuple[asyncio.Task, object]:
    """Spawn a uvicorn-hosted redteam FastAPI server in the agent's event loop.

    Built via ``redteam.integration.server.build_app`` against the
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
    from redteam.integration.server import build_app
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
    task = asyncio.create_task(server.serve(), name=f"redteam_server:{port}")
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
        seedbox_min_sats=args.seedbox_min_sats,
        seedbox_min_confirmations=args.seedbox_min_confirmations,
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
        # Per-overlay failures are non-fatal: subsequent network_join will
        # retry, and operator-driven flows (overlay_fetch_and_load) remain.
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
        agent.seedbox.publish_manifest(md_text)
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
            # Phase 6: spawn a redteam FastAPI sub-server when requested,
            # so peers running their own pull loops can fetch our
            # community-log entries. Shares the same on-disk files as
            # the agent's own SignedAppendOnlyLog / PeerLog; the
            # FastAPI uvicorn task is cancelled in ``finally``.
            redteam_task = None
            redteam_server = None
            if getattr(args, "redteam_port", 0):
                redteam_task, redteam_server = await _start_redteam_server(
                    agent, host=args.redteam_host, port=args.redteam_port,
                )
                print(
                    f"[redteam] serving signed-log on "
                    f"http://{args.redteam_host}:{args.redteam_port}",
                    flush=True,
                )
            try:
                await serve_mcp_async(agent, host=args.mcp_host, port=args.mcp_port)
            finally:
                if redteam_server is not None and redteam_task is not None:
                    redteam_server.should_exit = True
                    try:
                        await asyncio.wait_for(redteam_task, timeout=5.0)
                    except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                        redteam_task.cancel()
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
    parser.add_argument("--seedbox-min-sats", type=int, default=10_000)
    parser.add_argument("--seedbox-min-confirmations", type=int, default=0)
    parser.add_argument("--initial-balance-sats", type=int, default=0,
                        help="synthetic per-agent wallet balance the LLM sees via "
                             "wallet_balance; 0 disables (legacy always-zero mock)")
    parser.add_argument("--peer-log-url", action="append", metavar="URL",
                        default=[],
                        help="repeatable; full base URL (http(s)://host:port) of a peer's "
                             "redteam.integration.server. The agent pulls community-log "
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

    # LLM endpoint. The defaults point at a local Ollama (matches
    # ``deploy/watchdog.py``'s fallback). In production, scenario_boot
    # writes ``LLM_BASE_URL`` + ``LLM_MODEL`` into each agent's env file
    # and the systemd unit passes them on the CLI explicitly — so these
    # defaults are only hit when invoking ``python -m agent`` by hand.
    parser.add_argument("--llm-base-url", default="http://127.0.0.1:11434/v1")
    parser.add_argument("--llm-model", default="qwen2.5-coder:7b")
    parser.add_argument("--llm-api-key", default="")
    parser.add_argument("--llm-stub-script",
                        help="JSON file of chat-completions message dicts (offline mode for the tool loop)")
    parser.add_argument("--compiler-stub", action="store_true",
                        help="offline mode for the compiler: load *_stub.py source siblings of --publish-overlay files")

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
    mcp_p.add_argument("--redteam-host", default="127.0.0.1",
                       help="bind host for the redteam FastAPI server hosting our "
                            "community signed log (peers' pull loops fetch from here)")
    mcp_p.add_argument("--redteam-port", type=int, default=0,
                       help="bind port for the redteam FastAPI server; 0 disables "
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
