"""Leitor minimo de hive de registro (wrapper compativel com regf_dump.py)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from xvcintel.cli import main  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("uso: regf_dump.py HIVE")
    raise SystemExit(main(["regf", sys.argv[1]]))
