"""Utilitarios comuns do laboratorio criptografico (PROJECT_ALPHA CRYPTO LAB).

Tudo aqui e SINTETICO. Nenhuma chave, byte ou identificador de pacote real e usado.

- caminhos do repositorio e importacao do xvcintel / project_alpha;
- gerador deterministico rotulado (para --seed) e gerador seguro (padrao);
- SHA-256, entropia, escrita de JSON;
- guarda que impede apagar ou escrever fora das pastas do proprio laboratorio.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent
REPO_ROOT = LAB_ROOT.parents[1]                    # recovery/crypto_lab -> raiz
SRC_ROOT = REPO_ROOT / "src"
ALPHA_ROOT = REPO_ROOT / "recovery" / "project_alpha"
BIN_PE_SCRIPTS = REPO_ROOT / "recovery" / "bin_pe_recovery" / "scripts"
TOOLS_ROOT = LAB_ROOT / "tools"
FIXTURES = LAB_ROOT / "fixtures"
GENERATED = FIXTURES / "generated"
REPORTS = LAB_ROOT / "reports"

for _p in (SRC_ROOT, ALPHA_ROOT, LAB_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

PAGE = 0x1000
LAB_MARKER = b"LAB_SYNTHETIC"
LAB_MARKER_STR = LAB_MARKER.decode()
LAB_BANNER = ("LAB_SYNTHETIC - PROJECT_ALPHA CRYPTO LAB - conteiner sintetico de teste; "
              "NAO e um pacote Xbox oficial; chaves sinteticas geradas localmente")

# separacao ENCRYPTOR x FORENSIC ANALYZER
PUBLIC_DIRNAME = "public"
SEALED_DIRNAME = "sealed"
GROUND_TRUTH_NAME = "lab_ground_truth.json"
KEYSTORE_NAME = "lab_keystore.json"


class LabSafetyError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(buf: bytes) -> float:
    """Entropia de Shannon em bits/byte. Entropia alta NAO prova criptografia."""
    if not buf:
        return 0.0
    counts = [0] * 256
    for x in buf:
        counts[x] += 1
    n = len(buf)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def pages_of(n: int) -> int:
    return (n + PAGE - 1) // PAGE


def pad_page(b: bytes) -> bytes:
    return b.ljust(pages_of(len(b)) * PAGE, b"\0")


class Rng:
    """Fonte de bytes.

    seed=None  -> bytes de secrets.token_bytes (chaves seguras, padrao).
    seed=int   -> HMAC-SHA256(seed, rotulo || contador): deterministico e
                  separado por rotulo, para que trocar a ordem das chamadas de um
                  rotulo nao altere os outros. SOMENTE PARA TESTE.
    """

    def __init__(self, seed: int | None):
        self.seed = seed
        self._ctr: dict[str, int] = {}

    @property
    def deterministic(self) -> bool:
        return self.seed is not None

    def bytes(self, label: str, n: int) -> bytes:
        if self.seed is None:
            return secrets.token_bytes(n)
        key = f"crypto_lab-seed-{self.seed}".encode()
        out = bytearray()
        while len(out) < n:
            c = self._ctr.get(label, 0)
            self._ctr[label] = c + 1
            out += hmac.new(key, f"{label}|{c}".encode(), hashlib.sha256).digest()
        return bytes(out[:n])

    def stream(self, label: str, n: int) -> bytes:
        """Dados de conteudo (sempre reproduziveis): funcao pura de (semente, rotulo, n) -
        duas chamadas com o mesmo rotulo devolvem os mesmos bytes (o build B depende
        disso para diferir do A so onde deve). Com seed=None usa uma semente de
        conteudo aleatoria, gravada na verdade de referencia."""
        if self.seed is None:
            if not hasattr(self, "_content_seed"):
                self._content_seed = int.from_bytes(secrets.token_bytes(8), "little")
            return Rng(self._content_seed).bytes(label, n)
        return Rng(self.seed).bytes("content:" + label, n)

    @property
    def content_seed(self) -> int | None:
        return self.seed if self.seed is not None else getattr(self, "_content_seed", None)

    def u32(self, label: str) -> int:
        return int.from_bytes(self.bytes(label, 4), "little")


def write_json(path: Path, obj) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=_json_default) + "\n", encoding="utf-8")
    return path


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, set):
        return sorted(o)
    raise TypeError(f"nao serializavel: {type(o)}")


def assert_inside_lab(path: Path) -> Path:
    """Toda escrita/remocao do laboratorio fica dentro de recovery/crypto_lab
    ou de diretorios temporarios de teste (CRYPTO_LAB_ALLOW_ROOT, separados por os.pathsep)."""
    p = Path(path).resolve()
    roots = [LAB_ROOT]
    for extra in os.environ.get("CRYPTO_LAB_ALLOW_ROOT", "").split(os.pathsep):
        if extra:
            roots.append(Path(extra).resolve())
    if not any(p == r or r in p.parents for r in roots):
        raise LabSafetyError(f"{p} fora das pastas permitidas do laboratorio")
    return p


def allow_test_root(path: Path) -> None:
    """Acrescenta uma raiz temporaria de teste (sem remover as que ja existem)."""
    cur = [x for x in os.environ.get("CRYPTO_LAB_ALLOW_ROOT", "").split(os.pathsep) if x]
    if str(path) not in cur:
        os.environ["CRYPTO_LAB_ALLOW_ROOT"] = os.pathsep.join(cur + [str(path)])


def fresh_dir(path: Path) -> Path:
    """Recria uma pasta de trabalho do laboratorio (somente dentro do laboratorio)."""
    p = assert_inside_lab(path)
    if p == LAB_ROOT:
        raise LabSafetyError("recusado: tentativa de recriar a raiz do laboratorio")
    if p.exists():
        shutil.rmtree(p)
    p.mkdir(parents=True)
    return p


def hexdump_head(b: bytes, n: int = 32) -> str:
    return b[:n].hex()
