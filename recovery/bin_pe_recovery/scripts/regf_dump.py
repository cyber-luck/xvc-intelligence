"""Leitura de hive (xvcintel) e modo auxiliar de busca de referencias EXE.

Modo adicional: python scripts/regf_dump.py --find-exe ARQUIVO [--json refs.json]
A busca de strings *não* e um parser de hive completo.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))

if __name__ == "__main__":
    if "--find-exe" in sys.argv[1:]:
        from bin_pe_recovery import main
        argv = [s for s in sys.argv[1:] if s != "--find-exe"]
        raise SystemExit(main(["refs", *argv]))
    if len(sys.argv) != 2:
        sys.exit("uso: regf_dump.py HIVE | --find-exe ARQUIVO [--json SAIDA]")
    from xvcintel.cli import main
    raise SystemExit(main(["regf", sys.argv[1]]))
