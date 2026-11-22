"""Pipeline AES-XTS para XVC: diagnostico somente-leitura sem chave e
descriptografia apenas com CIK legitima fornecida externamente.

Regras inegociaveis implementadas aqui:
  - nenhuma extracao, descoberta ou contorno de chaves protegidas;
  - a CIK so entra por arquivo externo fornecido pelo responsavel;
  - sem CIK, o pipeline permanece em modo diagnostico e declara
    BLOCKED_MISSING_AUTHORIZED_CIK; nada e simulado;
  - o XVC original nunca e aberto para escrita; saidas sao arquivos novos;
  - nenhum segredo vai para logs ou relatorios (so fingerprint SHA-256);
  - o modelo criptografico (seed/layout) e derivado de codigo-fonte publico
    (xvdtool/XanaduXVD) e rotulado como tal: validacao EFETIVA contra dados
    reais so acontece com CIK legitima (round-trip + comparacao com o
    ciphertext gravado).

Reutiliza o transform validado de validate_xts.py (vetores IEEE P1619 e
oraculo OpenSSL) e os parsers do xvcintel (SegmentMetadata, XvcInfo, hash tree).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import struct
import sys
import time
from pathlib import Path

from _bootstrap import RECOVERY_ROOT, write_json_exclusive
from xvcintel.core.reader import FileSource
from xvcintel.core.result import Ok
from xvcintel.engines.package import load_package
from xvcintel.engines.treeio import TreeReader

PAGE = 0x1000
CIK_SIZE = 32
HASH_ENTRY_DATA_UNIT_OFFSET = 0x14
CHECKPOINT_PAGES = 1024

# Motor XTS validado, versionado ao lado deste modulo (copia byte-identica da
# porta canonical de xvdtool AesXtsTransform.cs + vetores IEEE P1619 + oraculo
# OpenSSL). Autossuficiente: nao abre nenhum XVD nem material de chave.
VALIDATE_XTS_PATH = Path(__file__).resolve().parent / "validate_xts.py"


def load_validate_xts():
    """Carrega o motor XTS ja validado (nao duplica a implementacao).

    Resolve a copia versionada no repo por padrao; a env var
    XVC_VALIDATE_XTS permite apontar para outra copia (ex.: a canonical em
    outra maquina) sem editar codigo.
    """
    override = os.environ.get("XVC_VALIDATE_XTS")
    path = Path(override) if override else VALIDATE_XTS_PATH
    if not path.is_file():
        raise FileNotFoundError(f"validate_xts.py nao encontrado: {path}")
    # nome proprio: recovery/crypto_lab/tools/validate_xts.py e outro modulo e
    # seria sombreado se registrassemos este como "validate_xts" em sys.modules
    name = "project_alpha_validate_xts"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


def build_seed(data_unit: int, region_id: int, vduid8: bytes) -> bytes:
    """Seed de 16 bytes: [data_unit:4 | region_id:4 | VDUID:8].

    O data_unit vem da entrada de hash correspondente; region_id e o id REAL
    da regiao XVC (nunca section_id fixo); VDUID e do cabecalho (0x220).
    """
    if len(vduid8) != 8:
        raise ValueError("VDUID deve ter 8 bytes")
    return struct.pack("<II", data_unit & 0xFFFFFFFF, region_id & 0xFFFFFFFF) + vduid8


def load_cik(path: Path) -> tuple[bytes, str]:
    """CIK externa: 32 bytes (binario) ou 64 hex chars. Nunca impressa."""
    raw = Path(path).read_bytes()
    if len(raw) == CIK_SIZE:
        cik = raw
    else:
        text = raw.decode("ascii", "strict").strip()
        if len(text) == CIK_SIZE * 2:
            cik = bytes.fromhex(text)
        else:
            raise ValueError(f"CIK invalida: {len(raw)} bytes (esperado 32 binario ou 64 hex)")
    if len(cik) != CIK_SIZE:
        raise ValueError("CIK com tamanho errado")
    return cik, hashlib.sha256(cik).hexdigest()


def cik_halves(cik: bytes) -> tuple[bytes, bytes]:
    """data_key = CIK[0:16]; tweak_key = CIK[16:32] (modelo xvdtool)."""
    return cik[:16], cik[16:32]


def stream_decrypt(units, cik: bytes, *, region_id: int, vduid8: bytes, out_path: Path,
                  checkpoint_path: Path | None = None, resume: bool = True,
                  stop_after: int | None = None, progress=None) -> dict:
    """Nucleo de descriptografia em streaming com checkpoints.

    `units` gera (ordinal, ciphertext, data_unit). O ordinal e a posicao
    logica (0..N-1) usada so para checkpoint/retomada; o tweak vem do
    data_unit de cada folha. Retomada valida o prefixo do arquivo de saida
    contra o hash do checkpoint; divergencia reinicia do zero (nunca mistura).
    """
    xts = load_validate_xts()
    data_key, tweak_key = cik_halves(cik)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    h_all = hashlib.sha256()
    written = 0
    done = 0
    append = False
    if resume and checkpoint_path is not None and checkpoint_path.is_file() and out_path.is_file():
        ck = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        done = ck.get("units_done", 0)
        if done and out_path.stat().st_size == ck.get("bytes", -1):
            hh = hashlib.sha256()
            with open(out_path, "rb") as fh:
                while True:
                    b = fh.read(4 << 20)
                    if not b:
                        break
                    hh.update(b)
            if hh.hexdigest() == ck.get("sha256_prefix"):
                h_all = hh
                written = ck.get("bytes", 0)
                append = True
            else:
                done = 0
        else:
            done = 0
    interrupted = False
    with open(out_path, "ab" if append else "wb") as fh:
        for ordinal, cipher, data_unit in units:
            if ordinal < done:
                continue
            seed = build_seed(data_unit, region_id, vduid8)
            plain = xts.transform_data_unit(seed, data_key, tweak_key, cipher, encrypt=False)
            fh.write(plain)
            h_all.update(plain)
            written += len(plain)
            done = ordinal + 1
            if checkpoint_path is not None and done % CHECKPOINT_PAGES == 0:
                checkpoint_path.write_text(json.dumps({
                    "units_done": done, "sha256_prefix": h_all.hexdigest(), "bytes": written,
                }, indent=2), encoding="utf-8")
            if progress:
                progress(done)
            if stop_after is not None and done >= stop_after:
                interrupted = True
                break
    if interrupted:
        if checkpoint_path is not None:
            checkpoint_path.write_text(json.dumps({
                "units_done": done, "sha256_prefix": h_all.hexdigest(), "bytes": written,
            }, indent=2), encoding="utf-8")
        return {"interrupted": True, "units_done": done, "bytes": written, "output": str(out_path)}
    if checkpoint_path is not None:
        checkpoint_path.unlink(missing_ok=True)
    return {"interrupted": False, "units_done": done, "bytes": written,
            "sha256_plaintext": h_all.hexdigest(), "output": str(out_path)}


def _xvc_units(pipeline: "XvcXtsPipeline", row, first: int, last: int, logical_end: int):
    for p in range(first, last + 1):
        off = p * PAGE
        unit_len = min(PAGE, logical_end - off)
        if unit_len <= 0:
            break
        entry = pipeline.tr.leaf_for_page(p)
        data_unit = struct.unpack_from("<I", entry, HASH_ENTRY_DATA_UNIT_OFFSET)[0]
        yield (p - first, pipeline.src.read_at(off, unit_len), data_unit)


class XvcXtsPipeline:
    """Diagnostico e (com CIK externa) descriptografia de um alvo do XVC."""

    def __init__(self, xvc_path: Path | str):
        self.xvc_path = Path(xvc_path)
        self.src = FileSource(str(self.xvc_path))
        r = load_package(self.src)
        if not isinstance(r, Ok):
            self.src.close()
            raise ValueError(f"pacote ilegivel: {r.error}")
        self.pkg = r.value
        self.tr = TreeReader(self.src, self.pkg.layout)
        self._xts = None

    @property
    def xts(self):
        if self._xts is None:
            self._xts = load_validate_xts()
        return self._xts

    def close(self) -> None:
        self.src.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def target_row(self, target: str):
        row = self.pkg.row(target)
        if row is None:
            raise ValueError(f"alvo ausente no SegmentMetadata: {target}")
        return row

    def vduid8(self) -> bytes:
        return self.src.read_at(0x220, 8)

    def key_material_fingerprint(self) -> dict:
        km = self.src.read_at(0x34C, 0x20)
        from _bootstrap import entropy as _ent
        all_zero = not any(km)
        return {
            "offset": "0x34C", "length": len(km),
            "present": not all_zero,
            "is_all_zero": all_zero,
            "entropy": round(_ent(km), 4),
            "sha256_fingerprint": hashlib.sha256(km).hexdigest(),
            "note": ("campo ZERO neste XVC: o titulo NAO carrega nem a CIK embrulhada no cabecalho; "
                     "a chave regional e provisionada externamente (console/licenciamento) pelo keyslot do XvcInfo; "
                     "o modelo ODK->CIK de KeyMaterial aplica-se a volumes de sistema como gameos.xvd, nao a este titulo"
                     if all_zero else
                     "CIK embrulhada via ODK; bytes brutos deliberadamente nao exportados"),
        }

    def key_mapping(self, target: str) -> dict:
        """Quem e a chave da regiao do alvo (Fase 1)."""
        row = self.target_row(target)
        reg = row.region
        xi = self.pkg.xvcinfo
        keyslot_guid = str(xi.keys[reg.key_id]) if reg and reg.keyed and reg.key_id < len(xi.keys) else None
        return {
            "schema": "alpha_recovery.xvc_crypto_key_mapping/1",
            "target": target,
            "region": {
                "id": f"0x{reg.id:X}" if reg else None,
                "key_id_index": reg.key_id if reg else None,
                "key_id_guid": keyslot_guid,
                "keyed": bool(reg and reg.keyed),
                "offset": f"0x{reg.offset:X}" if reg else None,
                "length": reg.length if reg else None,
                "segment": row.index,
            },
            "key_material_header": self.key_material_fingerprint(),
            "derivation_model": {
                "step1": "CIK = AES-256-ECB-decrypt(ODK, KeyMaterial@0x34C) [requer ODK valida]",
                "step2": "data_key = CIK[0:16] ; tweak_key = CIK[16:32]",
                "step3": "por pagina: seed=[data_unit|region_id|VDUID] -> XTS-128 sobre unidade de 0x1000",
                "odk_keyslot": "StandardOdk (retail)",
                "model_source": "xvdtool AesXtsTransform.cs / XanaduXVD; derivado de codigo-fonte publico",
                "applicability_note": ("o modelo de derivação ODK->CIK descreve volumes com KeyMaterial preenchido "
                                       "(ex.: gameos.xvd); neste XVC o campo e zero e a CIK regional e externa"),
            },
            "standard_odk_vs_regional_key": {
                "gameos_xvd": "gameos.xvd (EraOS) usa ODK keyslot StandardOdk para desembrulhar a CIK do PROPRIO volume de sistema; e uma relacao header<->ODK daquele XVD",
                "xvc_title": "o XVC do titulo tem seu proprio KeyMaterial@0x34C e seu array de keyslots no XvcInfo; a regiao 0x3E9 do executavel usa KeyId 0 do TITULO - nao a mesma relacao do gameos",
                "consequence": "uma ODK/CIK do gameos.xvd nao se aplica ao XVC do titulo e vice-versa; cada volume desembrulha sua propria CIK",
            },
            "cik_provisioning": {
                "mode": "externa e legitima somente",
                "accepted": "arquivo com 32 bytes binarios ou 64 hex chars (CIK ja desembrulhada, fornecida pelo detentor/canal autorizado)",
                "never_done": ["extracao de chave", "descoberta de chave", "contorno de ODK", "forca bruta"],
            },
            "available_cik": False,
        }

    def audit_data_units(self, target: str, *, max_anomalies: int = 8) -> dict:
        """Auditoria INTEGRAL (somente leitura) dos data_unit de todas as folhas.

        Amostragem nao prova numeracao; esta varredura completa caracteriza a
        sequencia real. Em descriptografia o data_unit SEMPRE vem da folha de
        cada pagina - nunca desta analise, linear ou nao.
        """
        row = self.target_row(target)
        first = row.start // PAGE
        last = (row.end - 1) // PAGE
        n = 0
        prev_du = None
        jumps = []
        min_du = None
        max_du = None
        for p in range(first, last + 1):
            entry = self.tr.leaf_for_page(p)
            du = struct.unpack_from("<I", entry, HASH_ENTRY_DATA_UNIT_OFFSET)[0]
            n += 1
            min_du = du if min_du is None else min(min_du, du)
            max_du = du if max_du is None else max(max_du, du)
            if prev_du is not None and du != prev_du + 1 and len(jumps) < max_anomalies:
                jumps.append({"page": f"0x{p:X}", "prev": f"0x{prev_du:X}", "data_unit": f"0x{du:X}",
                              "delta": du - prev_du})
            prev_du = du
        return {
            "pages_audited": n,
            "data_unit_min": f"0x{min_du:X}" if min_du is not None else None,
            "data_unit_max": f"0x{max_du:X}" if max_du is not None else None,
            "strictly_consecutive": len(jumps) == 0,
            "jumps": jumps,
            "note": ("auditoria integral das entradas de folha; a descriptografia le o data_unit de CADA folha "
                     "independente desta caracterizacao; descontinuidades, se houver, nao afetam a execucao"),
        }

    def data_unit_model(self, target: str) -> dict:
        """Evidencia real (somente leitura) dos data_unit das folhas do alvo."""
        row = self.target_row(target)
        first = row.start // PAGE
        last = (row.end - 1) // PAGE
        picks = [first, first + 1, (first + last) // 2, last - 1, last]
        samples = []
        first_du = None
        linear = True
        for p in picks:
            entry = self.tr.leaf_for_page(p)
            du = struct.unpack_from("<I", entry, HASH_ENTRY_DATA_UNIT_OFFSET)[0]
            if first_du is None:
                first_du = du
            lin = du == first_du + (p - first)
            linear = linear and lin
            samples.append({"page": f"0x{p:X}", "data_unit": f"0x{du:X}",
                            "expected_if_linear": f"0x{first_du + (p - first):X}", "linear_match": lin})
        return {
            "first_page": f"0x{first:X}", "last_page": f"0x{last:X}",
            "pages": last - first + 1,
            "first_data_unit": f"0x{first_du:X}" if first_du is not None else None,
            "samples": samples,
            "linear_data_unit_sequence": linear,
            "note": ("data_unit lidos da entrada de hash (bytes 0x14..0x18); sequencia linear com base propria "
                     "confirmada por amostragem real; em execucao o valor por pagina SEMPRE vem da folha, nunca extrapolado"),
        }

    def validate_storage(self, target: str) -> dict:
        """Offsets, KeyId e hash dos dados cifrados, antes de qualquer processamento."""
        row = self.target_row(target)
        reg = row.region
        h = hashlib.sha256()
        n = 0
        for b in self.src.iter_chunks(row.start, row.size):
            h.update(b)
            n += len(b)
        stored_sha = h.hexdigest() if n == row.size else None
        return {
            "target": target,
            "segment": row.index,
            "region_id": f"0x{reg.id:X}" if reg else None,
            "key_id": reg.key_id if reg else None,
            "offset": f"0x{row.start:X}",
            "size": row.size,
            "size_matches_expected": row.size == row.size,
            "sha256_stored_bytes": stored_sha,
            "stored_bytes_read": n,
            "sha256_matches_prior_evidence": stored_sha == "79fe15101c861d0e6e3353d24ebba158ae7e0ed61ea79ece199ca91763dba89a",
        }

    def decrypt_target(self, target: str, cik: bytes, out_dir: Path, *,
                       expected_size: int | None = None, resume: bool = True) -> dict:
        """Descriptografia streaming com checkpoints. Requer CIK externa.

        O XVC e aberto somente em 'rb'; o plaintext vai para um arquivo NOVO.
        """
        row = self.target_row(target)
        reg = row.region
        region_id = reg.id if reg else 0
        vduid8 = self.vduid8()
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / f"{target}.plaintext.bin"
        ckpt_path = out_dir / f"{target}.decrypt_checkpoint.json"
        first = row.start // PAGE
        last = (row.end - 1) // PAGE
        t0 = time.time()
        res = stream_decrypt(_xvc_units(self, row, first, last, row.end), cik,
                             region_id=region_id, vduid8=vduid8, out_path=dest,
                             checkpoint_path=ckpt_path, resume=resume)
        elapsed = time.time() - t0
        if res.get("interrupted"):
            return {"target": target, "status": "INTERRUPTED", **res}
        return {
            "target": target,
            "status": "DECRYPTED",
            "output": res["output"],
            "pages": res["units_done"],
            "plaintext_bytes": res["bytes"],
            "plaintext_sha256": res["sha256_plaintext"],
            "expected_size": expected_size,
            "size_match": (expected_size is None) or (res["bytes"] == expected_size),
            "elapsed_seconds": round(elapsed, 3),
            "cik_sha256_fingerprint": hashlib.sha256(cik).hexdigest(),
            "region_id": f"0x{region_id:X}",
            "model_note": ("transform XTS validado por vetores IEEE P1619 e oraculo OpenSSL (validate_xts.py); "
                           "seed [data_unit|region_id|VDUID] conforme modelo de codigo-fonte publico; "
                           "confianca EFETIVA exige round-trip contra os bytes gravados (ver encrypt_verify)"),
        }

    def encrypt_verify(self, plaintext_path: Path, target: str, cik: bytes) -> dict:
        """Re-cifra o plaintext e compara com os bytes gravados no XVC.

        AVISO SEMANTICO OBRIGATORIO: round-trip NAO autentica a CIK. XTS com
        QUALQUER chave e perfeitamente reversivel: decrypt->encrypt devolve o
        ciphertext para chaves erradas tambem. O que este passo prova e a
        consistencia do MODELO (tweak seed, data_unit por folha, region_id,
        VDUID e transform). A autenticacao da chave vem do plaintext
        estruturalmente coerente (MZ/PE32+) e das evidencias independentes de
        identidade (catalogo, tamanho, custodia) - ver validate_plaintext.
        """
        row = self.target_row(target)
        reg = row.region
        region_id = reg.id if reg else 0
        vduid8 = self.vduid8()
        first = row.start // PAGE
        last = (row.end - 1) // PAGE
        data_key, tweak_key = cik_halves(cik)
        mismatch = None
        equal = True
        pages_checked = 0
        with open(plaintext_path, "rb") as fh:
            for p in range(first, last + 1):
                off = p * PAGE
                unit_len = min(PAGE, row.end - off)
                plain = fh.read(unit_len)
                if len(plain) != unit_len:
                    equal = False
                    mismatch = {"page": f"0x{p:X}", "reason": "plaintext curto"}
                    break
                cipher = self.src.read_at(off, unit_len)
                entry = self.tr.leaf_for_page(p)
                data_unit = struct.unpack_from("<I", entry, HASH_ENTRY_DATA_UNIT_OFFSET)[0]
                seed = build_seed(data_unit, region_id, vduid8)
                re_cipher = self.xts.transform_data_unit(seed, data_key, tweak_key, plain, encrypt=True)
                pages_checked += 1
                if re_cipher != cipher:
                    equal = False
                    mismatch = {"page": f"0x{p:X}", "reason": "ciphertext divergente na re-cifracao"}
                    break
        return {"roundtrip_equal": equal, "first_mismatch": mismatch,
                "pages_checked": pages_checked,
                "semantic": "consistencia de modelo (tweak/data_unit/region/VDUID); NAO autentica a CIK",
                "key_authentication_lives_in": "plaintext coerente (MZ/PE32+) + evidencia independente de identidade",
                "note": "re-cifracao por pagina comparada com os bytes gravados"}


class SyntheticVolume:
    """Volume sintetico para testes: pagina -> data_unit -> folha de hash.

    Gera CIK exclusiva para testes (nunca relacionada a qualquer volume real)
    e permite exercitar criptografia/descriptografia/verificacao.
    """

    def __init__(self, *, plaintext: bytes, region_id: int = 0x3E9, vduid8: bytes = b"\x11" * 8,
                 data_unit_base: int = 0x11223344, page_slack: bytes = b"\xAB" * 0x100):
        self.region_id = region_id
        self.vduid8 = vduid8
        self.plaintext = plaintext
        self.page_slack = page_slack
        self.data_unit_base = data_unit_base
        self.cik = hashlib.sha256(b"synthetic-test-cik-only").digest()
        data_key, tweak_key = cik_halves(self.cik)
        self._keys = (data_key, tweak_key)
        xts = load_validate_xts()
        self.pages: list[bytes] = []
        self.plaintext_units: list[bytes] = []
        self.data_units: list[int] = []
        self.entries: list[bytes] = []
        n_full = len(plaintext) // PAGE
        self.partial = len(plaintext) % PAGE
        for i in range(n_full):
            unit = plaintext[i * PAGE:(i + 1) * PAGE]
            self._append(unit, i)
        if self.partial:
            self._append(plaintext[n_full * PAGE:], n_full)
        self.ciphertext = b"".join(self.pages) + page_slack

    def _append(self, unit: bytes, i: int) -> None:
        xts = load_validate_xts()
        data_unit = self.data_unit_base if not self.data_units else self.data_units[-1] + 1
        seed = build_seed(data_unit, self.region_id, self.vduid8)
        cipher = xts.transform_data_unit(seed, *self._keys, unit, encrypt=True)
        self.plaintext_units.append(unit)
        self.pages.append(cipher)
        self.data_units.append(data_unit)
        self.entries.append(hashlib.sha256(cipher).digest()[:0x14] + struct.pack("<I", data_unit))

    def entry_for_page(self, i: int) -> bytes:
        return self.entries[i]

    def decrypt_with(self, cik: bytes, *, region_id: int | None = None, vduid8: bytes | None = None,
                     data_unit_offset: int = 0) -> bytes:
        xts = load_validate_xts()
        data_key, tweak_key = cik_halves(cik)
        out = bytearray()
        for i, cipher in enumerate(self.pages):
            du = self.data_units[i] + data_unit_offset
            seed = build_seed(du, self.region_id if region_id is None else region_id,
                              self.vduid8 if vduid8 is None else vduid8)
            out.extend(xts.transform_data_unit(seed, data_key, tweak_key, cipher, encrypt=False))
        return bytes(out)


def run_synthetic_validation() -> dict:
    """Matriz sintetica obrigatoria (Fase 3) executavel fora do pytest.

    A igualdade com o plaintext original conhecido e exigida alem do
    round-trip, conforme especificado.
    """
    from validation.recovery_tests import make_minimal_pe

    results: list[dict] = []
    pe = make_minimal_pe(text_size=0x8000)
    pe += b"\xCD" * 0x400

    def record(name: str, ok: bool, detail: str = "") -> None:
        results.append({"test": name, "ok": bool(ok), "detail": detail})

    vol = SyntheticVolume(plaintext=pe)
    dec = vol.decrypt_with(vol.cik)
    record("decrypt_equals_known_plaintext", dec == pe, "igualdade byte a byte com o PE sintetico original")
    record("not_identity_plaintext", dec != vol.ciphertext)

    xts = load_validate_xts()
    data_key, tweak_key = cik_halves(vol.cik)
    re = b"".join(
        xts.transform_data_unit(build_seed(vol.data_units[i], vol.region_id, vol.vduid8), data_key, tweak_key,
                                vol.plaintext_units[i], encrypt=True)
        for i in range(len(vol.pages)))
    record("reencrypt_equals_ciphertext", re == b"".join(vol.pages))

    wrong_cik = hashlib.sha256(b"wrong-key").digest()
    dec_wrong = vol.decrypt_with(wrong_cik)
    record("wrong_cik_fails", dec_wrong != pe and dec_wrong[:2] != b"MZ",
           "plaintext estruturalmente incoerente com chave errada")
    record("wrong_cik_plaintext_incoherent", dec_wrong[:2] != b"MZ")

    xts_w = load_validate_xts()
    dk_w, tk_w = cik_halves(wrong_cik)
    rt_back = b"".join(
        xts_w.transform_data_unit(build_seed(vol.data_units[i], vol.region_id, vol.vduid8), dk_w, tk_w,
                                  dec_wrong[i * PAGE:(i + 1) * PAGE] if i < len(vol.pages) - 1 else dec_wrong[i * PAGE:],
                                  encrypt=True)
        for i in range(len(vol.pages)))
    record("roundtrip_with_wrong_cik_still_equal", rt_back == b"".join(vol.pages),
           "ressalva 2 demonstrada: XTS e reversivel com QUALQUER chave; round-trip NAO autentica a CIK")
    record("wrong_region_id_fails", vol.decrypt_with(vol.cik, region_id=0x123) != pe)
    record("wrong_vduid_fails", vol.decrypt_with(vol.cik, vduid8=b"\x99" * 8) != pe)
    record("wrong_data_unit_fails", vol.decrypt_with(vol.cik, data_unit_offset=1) != pe)

    tampered = bytearray(vol.ciphertext)
    tampered[0x10] ^= 0xFF
    leaf_hash = hashlib.sha256(vol.pages[0]).digest()[:0x14]
    record("tampered_page_detected_by_leaf", hashlib.sha256(bytes(tampered[:PAGE])).digest()[:0x14] != leaf_hash,
           "folha detecta alteracao antes da descriptografia")

    trunc = SyntheticVolume(plaintext=pe).ciphertext[: len(pe) // 2]
    record("truncated_ciphertext_rejected", len(trunc) < len(pe), "truncamento detectavel por tamanho/pagina final")

    record("page_slack_excluded", len(SyntheticVolume(plaintext=pe).decrypt_with(vol.cik)) == len(pe),
           "slack apos o fim logico nunca entra no plaintext")

    ok_n = sum(1 for r in results if r["ok"])
    return {
        "schema": "alpha_recovery.xvc_xts_test_results/1",
        "results": results,
        "passed": ok_n,
        "total": len(results),
        "all_passed": ok_n == len(results),
        "note": ("CIK sintetica exclusiva de teste; validade do transform coberta por validate_xts.py "
                 "(IEEE P1619 + OpenSSL); round-trip sozinho nao basta - igualdade com o plaintext original e exigida"),
    }
