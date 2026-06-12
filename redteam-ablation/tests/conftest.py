"""Suite-wide fixtures.

The CLI's ``main()`` loads the repo-root ``.env`` (which carries the real
``OPENROUTER_API_KEY`` on Lucas's machine). The keyless fail-fast tests
delete the env var and then call ``main()`` — without this fixture a real
``.env`` would re-inject the key and the suite could walk into a metered
live run. No test may load ``.env``; tests that need a key set a fake one
via ``monkeypatch.setenv``.
"""

import pytest

import redteam_ablation.cli as cli


@pytest.fixture(autouse=True)
def _no_dotenv(monkeypatch):
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **kw: None)
