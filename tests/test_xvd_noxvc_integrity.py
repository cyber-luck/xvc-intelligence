"""XVD nao-XVC: regra da folha depende do flag de cifra (achado do crypto_lab).

xvdtool XVDFile.cs:128 - DataHashEntryLength = IsEncrypted ? 0x14 : 0x18. Sem XvcInfo,
o integrity.leaf_vs_data comparava sempre 0x18 e falhava em XVD cifrado cujas folhas
guardam SHA-256[:0x14] + data unit. Nao precisa de criptografia: os bytes do drive
sao pseudoaleatorios e as folhas seguem o formato de pagina cifrada.
"""
import hashlib
import random
import struct
import uuid

from synthxvc import make_header
from xvcintel.core.reader import BytesSource
from xvcintel.engines.integrity import IntegrityOptions, run_integrity
from xvcintel.engines.package import load_package
from xvcintel.evidence.model import FAIL
from xvcintel.formats.hashtree import build_tree

PAGE = 0x1000


def _xvd(flags: int, keyed_leaves: bool) -> bytes:
    rnd = random.Random(11)
    ud = bytes(rnd.getrandbits(8) for _ in range(PAGE))
    drive = bytes(rnd.getrandbits(8) for _ in range(5 * PAGE))
    pages = [ud] + [drive[i * PAGE:(i + 1) * PAGE] for i in range(5)]
    leaves = []
    for i, p in enumerate(pages):
        d = hashlib.sha256(p).digest()
        leaves.append(d[:0x14] + struct.pack("<I", 0x7A3C1000 + i) if keyed_leaves else d[:0x18])
    tree, _ = build_tree(leaves)
    h = make_header({"flags": flags, "drive_size": len(drive), "vduid": uuid.UUID(int=0x1AB5), "content_type": 0,
                     "ud_len": PAGE})
    h[0x240:0x260] = hashlib.sha256(tree[0]).digest()
    return bytes(h) + b"".join(tree) + ud + drive


def _leaf_check(data: bytes):
    pkg = load_package(BytesSource(data)).value
    assert pkg.xvcinfo is None
    return {c.id: c for c in run_integrity(pkg, IntegrityOptions())}["integrity.leaf_vs_data"]


def test_encrypted_xvd_compares_0x14_bytes():
    c = _leaf_check(_xvd(flags=0x01, keyed_leaves=True))          # cifra ligada
    assert c.status != FAIL
    assert c.counts["keyed_ok"] > 0 and c.counts["keyed_bad"] == 0


def test_unencrypted_xvd_still_compares_0x18_bytes():
    c = _leaf_check(_xvd(flags=0x03, keyed_leaves=False))         # EncryptionDisabled
    assert c.status != FAIL
    assert c.counts["plain_ok"] > 0 and c.counts["keyed_ok"] == 0


def test_unencrypted_xvd_with_data_unit_leaves_fails():
    """Controle negativo: sem cifra, uma folha 0x14+data unit nao confere com SHA-256[:0x18]."""
    c = _leaf_check(_xvd(flags=0x03, keyed_leaves=True))
    assert c.status == FAIL
