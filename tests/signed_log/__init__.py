from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
REAL_PACKAGE = ROOT / "signed_log"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
__path__.append(str(REAL_PACKAGE))
