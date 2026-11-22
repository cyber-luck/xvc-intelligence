"""Validação PE tradicional e nova busca de PE embutidos em BIN.

Compatibilidade: python scripts/pe_check.py arquivo.exe [--json relatorio.json]
Novo: python scripts/pe_check.py --scan-bin arquivo.bin --compressed --json relatorio.json
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))

if __name__ == "__main__":
    if "--scan-bin" in sys.argv[1:]:
        from bin_pe_recovery import main
        argv = [s for s in sys.argv[1:] if s != "--scan-bin"]
        raise SystemExit(main(["scan", *argv]))
    if len(sys.argv) < 2:
        sys.exit("uso: pe_check.py ARQUIVO [--json SAIDA] | --scan-bin ARQUIVO.bin [opcoes]")
    try:
        from xvcintel.cli import main
    except ModuleNotFoundError as exc:
        if exc.name != "xvcintel":
            raise
        from bin_pe_recovery import check_legacy
        raise SystemExit(check_legacy(sys.argv[1:]))
    raise SystemExit(main(["pe", *sys.argv[1:]]))
