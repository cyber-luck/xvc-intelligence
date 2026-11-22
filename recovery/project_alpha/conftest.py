import sys
from pathlib import Path

RECOVERY_ROOT = Path(__file__).resolve().parent
for p in (str(RECOVERY_ROOT), str(RECOVERY_ROOT / ".." / ".." / "src")):
    if p not in sys.path:
        sys.path.insert(0, p)
