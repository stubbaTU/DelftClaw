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

    # Terminal 1 — Alice publishes the content overlay:
    python -m agent --mnemonic 'army van defense ...' --port 8090 \\
        --publish-overlay protocol/examples/content_community.md \\
        --llm-base-url http://gpu-host:8000/v1 --llm-model my-llm \\
        info

    # Copy Alice's --peer line from her info output, then:

    # Terminal 2 — Bob queries Alice:
    python -m agent --mnemonic 'abandon abandon abandon ...' --port 8091 \\
        --peer 127.0.0.1:8090:<alice-pubkey-hex> \\
        --llm-base-url http://gpu-host:8000/v1 --llm-model my-llm \\
        run --query "what files are stored on our claw network?"
"""

from __future__ import annotations

import argparse
import asyncio
import json
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
    """
    import importlib.util
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
    for p in paths:
        md_text = Path(p).read_text(encoding="utf-8")
        cid_hex = community_id_from_md(md_text).hex()
        # Local "publish + load" — same effect as agent.publish_overlay but
        # we route compile via the stub source if available.
        agent.seedbox.publish_overlay(md_text)
        if cid_hex in stub_sources:
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
            md_hash = agent.publish_overlay(md_text)
        compiled = agent.registry._compiled[md_hash]
        out.append((compiled.parsed.identity.get("name", Path(p).name), md_hash.hex()))
    return out


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


async def _run(args: argparse.Namespace) -> int:
    seed = _load_seed(args)
    identity = AgentIdentity.from_seed(seed, network=args.network)

    compiler_llm = _build_compiler_llm(args)
    config = AgentConfig(
        port=args.port,
        address=args.address,
        btc_network=args.btc_network,
        save_dir=Path(args.save_dir),
        seedbox_min_sats=args.seedbox_min_sats,
        seedbox_min_confirmations=args.seedbox_min_confirmations,
    )
    agent = OpenClawAgent(identity=identity, llm=compiler_llm, config=config)
    await agent.start()

    # Publish overlays at boot (if any). Done before peer-introduction so
    # peers immediately see the descriptor in our published map when they ask.
    published = _publish_overlays(agent, args.publish_overlay or [])

    # Network manifest: either consume one (--manifest) or publish one (--genesis).
    manifest_loaded: Optional[str] = None
    if args.manifest:
        md_text = Path(args.manifest).read_text(encoding="utf-8")
        manifest = agent.load_manifest(md_text)
        manifest_loaded = f"consumed {manifest.identity.get('name', '?')} ({manifest.network_id.hex()[:8]})"
    elif args.genesis:
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
    if manifest_loaded:
        print(f"[agent] manifest: {manifest_loaded}", flush=True)
    if introduced:
        for host, port, mid_hex in introduced:
            print(f"[agent] introduced peer: {host}:{port}  mid={mid_hex[:16]}", flush=True)

    system_prompt = _read_system_prompt(args)

    try:
        if args.cmd == "info":
            print(json.dumps({
                "agent_id": str(identity.agent_id),
                "ipv8_address": list(agent.address),
                "ipv8_pubkey_hex": agent.pubkey_hex,
                "wallet_address": agent.wallet.address(),
                "btc_network": args.btc_network,
                "loaded_overlays": [
                    {"name": compiled.parsed.identity.get("name", ""),
                     "community_id_hex": cid.hex()}
                    for cid, compiled in agent.registry._compiled.items()
                ],
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
            await serve_mcp_async(agent, host=args.mcp_host, port=args.mcp_port)
            return 0

        sys.stderr.write(f"unknown cmd: {args.cmd}\n")
        return 2
    finally:
        await agent.stop()


def main() -> int:
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

    # Per-agent zero-shot config.
    parser.add_argument("--publish-overlay", action="append", metavar="PATH",
                        help="repeatable; load + serve a markdown overlay descriptor at boot")
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

    # LLM endpoint.
    parser.add_argument("--llm-base-url", default="http://localhost:8000/v1")
    parser.add_argument("--llm-model", default="local-model")
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
