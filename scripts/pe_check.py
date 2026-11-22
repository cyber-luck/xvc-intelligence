"""Verificador PE (wrapper compativel com o pe_check.py original).

Uso: python -I scripts/pe_check.py ARQUIVO [--json SAIDA]
Codigo de saida: 0 = PE consistente, 1 = nao e PE ou estrutura inconsistente.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from xvcintel.cli import main  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("uso: pe_check.py ARQUIVO [--json SAIDA]")
    raise SystemExit(main(["pe", *sys.argv[1:]]))
