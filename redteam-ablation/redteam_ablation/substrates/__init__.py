"""Substrate adapters: one interceptor core, one adapter per evaluation substrate.

Architecture Y (plan 2026-06-10): Substrate 1 is the real OpenClaw runtime
(``runtime.openclaw``); Substrate 2 is AgentDojo running in its own native
harness (``substrates.agentdojo_native``). Both adapters route every proposed
tool call through the SAME ``Dispatcher``/interceptor core -- the primitives
are implemented once.

Core modules must NOT import anything from this package's third-party
dependencies; the ``agentdojo`` dependency is confined to
``substrates.agentdojo_native``.
"""
