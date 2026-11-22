"""Auxiliar dos testes: caminhos, pulo sem `cryptography` e um laboratorio gerado
uma unica vez por processo em diretorio temporario (nunca em fixtures/generated)."""
from __future__ import annotations

import atexit
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
if str(LAB) not in sys.path:
    sys.path.insert(0, str(LAB))

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

requires_crypto = unittest.skipUnless(HAVE_CRYPTO, "pacote 'cryptography' ausente (pip install cryptography)")

import lab_common  # noqa: E402

SEED = 777
_TMP = Path(tempfile.mkdtemp(prefix="crypto_lab_test_"))
lab_common.allow_test_root(_TMP)
atexit.register(lambda: shutil.rmtree(_TMP, ignore_errors=True))

_CACHE: dict = {}


def tmp_root() -> Path:
    return _TMP


def generated() -> dict:
    """Laboratorio deterministico (seed de teste) gerado uma vez."""
    if "gen" not in _CACHE:
        import lab_encryptor
        _CACHE["gen"] = lab_encryptor.generate(_TMP / "gen", SEED)
    return _CACHE["gen"]


def blind_report() -> dict:
    if "blind" not in _CACHE:
        import blind_forensic_analysis as BFA
        g = generated()
        _CACHE["blind"] = BFA.analyze(Path(g["public"]), _TMP / "blind_work", Path(g["sealed"]).resolve())
    return _CACHE["blind"]


def reveal_report() -> dict:
    if "reveal" not in _CACHE:
        import lab_decryptor
        g = generated()
        _CACHE["reveal"] = lab_decryptor.run_key_reveal(Path(g["root"]), _TMP / "reveal_work")
    return _CACHE["reveal"]
