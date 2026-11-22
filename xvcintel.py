"""Lancador: python -I xvcintel.py <comando> ... (funciona com -I, sem instalar)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from xvcintel.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
