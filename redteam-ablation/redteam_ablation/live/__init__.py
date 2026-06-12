"""Substrate-1 LIVE path: the real-OpenClaw wiring (plan 2026-06-11).

Everything here is offline-buildable and offline-testable. The ``openclaw``
binary lives only on the VPS, so the subprocess seam is injectable and tests
fake it. ``trace`` and ``provision`` are pure stdlib; only ``server.build_app``
imports ``fastmcp`` (lazily), so the offline core never needs it.
"""
