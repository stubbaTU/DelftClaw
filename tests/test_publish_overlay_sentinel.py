"""``is_publish_overlay_sentinel`` — the no-publish placeholder filter.

``deploy.scenario_boot`` always emits a token for ``${PUBLISH_OVERLAY}`` in
the systemd unit expansion (an empty env var would break argparse), so when
an agent has nothing to publish at boot it writes the literal string
``"none"``. Both the MCP entry point (``agent.cli._discover_stub_sources``)
and the watchdog's snapshot-agent setup must filter this sentinel the same
way, otherwise the watchdog tries to open ``'none'`` as a file and logs a
warning every boot.

Lifting the filter into ``agent.cli.is_publish_overlay_sentinel`` makes both
call sites share one implementation; these tests pin the contract so future
maintainers can't drift the two filters apart again.
"""

from __future__ import annotations

import pytest

from agent.cli import is_publish_overlay_sentinel


@pytest.mark.parametrize("value", ["none", "None", "NONE", "  none  ", "", None, "   "])
def test_sentinel_values_are_filtered(value):
    assert is_publish_overlay_sentinel(value) is True


@pytest.mark.parametrize("value", [
    "protocol/examples/content_community.md",
    "/etc/delftclaw/scenarios/file_share-seeder/content_community.md",
    "none.md",       # filename that contains "none" but isn't the sentinel
    "none-but-real", # likewise
])
def test_real_paths_are_not_filtered(value):
    assert is_publish_overlay_sentinel(value) is False


def test_watchdog_imports_and_uses_helper():
    """The watchdog module imports the helper symbol. Catches an accidental
    removal/rename that would otherwise only surface at deploy time."""
    import deploy.watchdog as wd
    assert wd.is_publish_overlay_sentinel is is_publish_overlay_sentinel
