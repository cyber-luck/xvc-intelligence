"""Bootstrap comum: caminhos, importacao do xvcintel e politicas de seguranca.

Regras impostas aqui:
  - leitura sempre "rb"; nenhuma escrita em artefatos originais;
  - gravacao de saidas apenas em arquivos novos (modo "xb"), sem sobrescrita;
  - destino de extracao nunca dentro da pasta de um artefato original;
  - limites de leitura unica (streaming por blocos) para arquivos grandes.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

RECOVERY_ROOT = Path(__file__).resolve().parent
REPO_ROOT = RECOVERY_ROOT.parents[1]  # recovery/project_alpha -> raiz do repo
SRC_ROOT = REPO_ROOT / "src"
SCRIPTS_ROOT = REPO_ROOT / "scripts"
BIN_PE_RECOVERY = REPO_ROOT / "recovery" / "bin_pe_recovery" / "scripts" / "bin_pe_recovery.py"

if str(RECOVERY_ROOT) not in sys.path:
    sys.path.insert(0, str(RECOVERY_ROOT))
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

for name in ("scanners", "correlation", "reconstruction", "validation"):
    p = RECOVERY_ROOT / name
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

PAGE = 0x1000
MAX_SINGLE_READ = 64 * 1024 * 1024
DEFAULT_CHUNK = 4 * 1024 * 1024


class SafetyError(Exception):
    pass


def load_bin_pe_recovery():
    """Carrega recovery/bin_pe_recovery/scripts/bin_pe_recovery.py sem duplicar codigo."""
    path = BIN_PE_RECOVERY
    if not path.is_file():
        raise SafetyError(f"bin_pe_recovery.py ausente: {path}")
    spec = importlib.util.spec_from_file_location("bin_pe_recovery", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def guard_output_dir(out: Path, protected: list[Path]) -> Path:
    """Recusa gravar dentro (ou no proprio caminho) de um artefato original."""
    out = Path(out).resolve()
    for prot in protected:
        prot = Path(prot).resolve()
        if out == prot:
            raise SafetyError(f"saida {out} e o proprio artefato original")
        if prot.is_dir() and (out == prot or prot in out.parents):
            raise SafetyError(f"saida {out} fica dentro de {prot}")
        if prot.is_file() and prot.parent == out:
            raise SafetyError(f"saida {out} e a pasta que contem o artefato original {prot}")
    return out


def safe_child(out_dir: Path, name: str) -> Path:
    """Nome de saida derivado so de offsets/valores controlados; sem traversal."""
    clean = "".join(c for c in name if c.isalnum() or c in "._-")
    if not clean or clean.startswith("."):
        raise SafetyError(f"nome de saida invalido: {name!r}")
    dest = (out_dir / clean).resolve()
    top = Path(out_dir).resolve()
    if top != dest and top not in dest.parents:
        raise SafetyError(f"destino fora do diretorio de saida: {dest}")
    return dest


def write_exclusive(path: Path, data: bytes) -> Path:
    """Grava apenas se o arquivo nao existir; recusa sobrescrever."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as fh:
            fh.write(data)
    except FileExistsError:
        raise SafetyError(f"recusado sobrescrever: {path}")
    return path


def write_json_exclusive(path: Path, obj, *, allow_overwrite: bool = False) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8") + b"\n"
    if allow_overwrite:
        with path.open("wb") as fh:
            fh.write(data)
    else:
        try:
            with path.open("xb") as fh:
                fh.write(data)
        except FileExistsError:
            raise SafetyError(f"recusado sobrescrever: {path}")
    return path


def read_head(path: Path, length: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(length)


def iter_file(path: Path, offset: int, length: int, chunk: int = DEFAULT_CHUNK):
    """Streaming por blocos; nunca carrega o arquivo inteiro."""
    with open(path, "rb") as fh:
        fh.seek(offset)
        remaining = length
        while remaining > 0:
            b = fh.read(min(chunk, remaining))
            if not b:
                break
            remaining -= len(b)
            yield b


def sha256_file(path: Path, offset: int = 0, length: int | None = None) -> str:
    import hashlib
    h = hashlib.sha256()
    size = os.path.getsize(path)
    if length is None:
        length = size - offset
    for b in iter_file(path, offset, length):
        h.update(b)
    return h.hexdigest()


def entropy(buf: bytes) -> float:
    import math
    if not buf:
        return 0.0
    counts = [0] * 256
    for x in buf:
        counts[x] += 1
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in counts if v)


def utc_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def json_dump_sorted(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=str)
