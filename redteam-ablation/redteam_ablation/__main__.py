"""Package entrypoint so ``python -m redteam_ablation ...`` runs the CLI.

Mirrors ``python -m redteam_ablation.cli ...``; both dispatch to
:func:`redteam_ablation.cli.main`.
"""

from __future__ import annotations

from redteam_ablation.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
