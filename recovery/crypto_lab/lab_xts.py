"""Reproducao do AesXtsTransform do xvdtool (LibXboxOne/Crypto/AesXts.cs).

Comportamento confirmado no codigo de referencia (emoose/xvdtool @ 6fc2886):

  * unidade criptografica = 1 pagina (0x1000 bytes), um "data unit" por pagina;
  * chave composta de 256 bits = CIK; CIK[0:16] = chave AES-128 do tweak,
    CIK[16:32] = chave AES-128 dos dados (XVDFile.cs:CryptSectionXts, linhas 349-350);
  * seed do tweak (16 bytes):  [0:4] data_unit u32 LE | [4:8] header/section id u32 LE |
    [8:16] VDUID[0:8]  (CryptSectionXts linhas 353-355 + TransformDataUnit linha 64);
  * T0 = AES-ECB(tweak_key, seed); para cada bloco i: C = E_data(P ^ T_i) ^ T_i;
    T_{i+1} = T_i * x em GF(2^128), little-endian por byte, reducao 0x87
    (MultiplyTweak, AesXts.cs linhas 38-56);
  * NAO ha ciphertext stealing: so blocos inteiros de 16 bytes (AesXts.cs linha 72).

Isso e exatamente o XTS-AES do IEEE 1619 com chave (Key1=dados, Key2=tweak):
a funcao `xts_page_openssl` usa o modo XTS nativo da biblioteca `cryptography`
(OpenSSL) como implementacao independente para verificacao cruzada.

O AES de bloco vem de `cryptography` (AES-ECB). Nenhuma etapa "difusiva"
adicional e aplicada: nenhuma das referencias a implementa (ver lab_reference.py).
"""
from __future__ import annotations

import struct

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTOGRAPHY = True
except ImportError:          # pragma: no cover - ambiente sem a dependencia
    HAVE_CRYPTOGRAPHY = False

BLOCK = 16
DATA_UNIT_SIZE = 0x1000
GF_REDUCTION = 0x87
MASK128 = (1 << 128) - 1


def _require():
    if not HAVE_CRYPTOGRAPHY:
        raise RuntimeError("o pacote 'cryptography' e necessario para o laboratorio (pip install cryptography)")


# ----------------------------------------------------------------- AES-ECB
def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    _require()
    if len(data) % BLOCK:
        raise ValueError("AES-ECB sem padding exige multiplo de 16 bytes")
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    _require()
    if len(data) % BLOCK:
        raise ValueError("AES-ECB sem padding exige multiplo de 16 bytes")
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(data) + d.finalize()


# ----------------------------------------------------------------- tweak
def build_tweak_seed(data_unit: int, section_id: int, vduid_bytes_le: bytes) -> bytes:
    """Seed de 16 bytes do xvdtool. vduid_bytes_le = VDUID como gravado no cabecalho
    (Guid.ToByteArray / bytes_le); somente os 8 primeiros bytes entram."""
    if len(vduid_bytes_le) < 8:
        raise ValueError("VDUID precisa de pelo menos 8 bytes")
    return struct.pack("<II", data_unit & 0xFFFFFFFF, section_id & 0xFFFFFFFF) + bytes(vduid_bytes_le[:8])


def multiply_tweak_xvdtool(tweak: bytes) -> bytes:
    """Porte literal de AesXtsTransform.MultiplyTweak (operacoes de byte do C#)."""
    dl = 0
    new = bytearray(16)
    for i in range(16):
        cl = tweak[i]
        al = (cl + cl) & 0xFF
        al = al | dl
        dl = cl
        new[i] = al
        dl = (dl >> 7) & 0xFF
    if dl != 0:
        new[0] ^= GF_REDUCTION
    return bytes(new)


def multiply_tweak_int(t: int) -> int:
    """Mesma multiplicacao por x em GF(2^128), sobre o inteiro little-endian."""
    carry = t >> 127
    t = (t << 1) & MASK128
    return t ^ GF_REDUCTION if carry else t


def tweak_stream(t0: bytes, blocks: int) -> bytes:
    t = int.from_bytes(t0, "little")
    out = bytearray()
    for _ in range(blocks):
        out += t.to_bytes(16, "little")
        t = multiply_tweak_int(t)
    return bytes(out)


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(len(a), "little")


# ----------------------------------------------------------------- transformacao
class AesXtsTransform:
    """Equivalente a LibXboxOne.AesXtsTransform(tweakBytes, dataAesKey, tweakAesKey, encrypt)."""

    def __init__(self, tweak_seed: bytes, data_key: bytes, tweak_key: bytes, encrypt: bool):
        if len(tweak_seed) != 16:
            raise ValueError("Tweak bytes not 16 bytes")
        if len(data_key) != 16:
            raise ValueError("Data AES key not 16 bytes")
        if len(tweak_key) != 16:
            raise ValueError("Tweak AES not 16 bytes")
        _require()
        self._seed = bytearray(tweak_seed)
        self._tweak_enc = Cipher(algorithms.AES(tweak_key), modes.ECB()).encryptor()
        c = Cipher(algorithms.AES(data_key), modes.ECB())
        self._data = c.encryptor() if encrypt else c.decryptor()

    def transform_data_unit(self, data: bytes, data_unit: int) -> bytes:
        if len(data) % BLOCK:
            raise ValueError("xvdtool processa apenas blocos inteiros (sem ciphertext stealing)")
        # Array.Copy(BitConverter.GetBytes(dataUnit), tweak, 4)
        self._seed[0:4] = struct.pack("<I", data_unit & 0xFFFFFFFF)
        t0 = self._tweak_enc.update(bytes(self._seed))
        ts = tweak_stream(t0, len(data) // BLOCK)
        x = _xor(data, ts)
        y = self._data.update(x)
        return _xor(y, ts)


class AesXtsTransformLiteral:
    """Porte literal, laco por laco, para provar a equivalencia com a versao rapida."""

    def __init__(self, tweak_seed: bytes, data_key: bytes, tweak_key: bytes, encrypt: bool):
        _require()
        self._seed = bytearray(tweak_seed)
        self._tweak_key, self._data_key, self._encrypt = tweak_key, data_key, encrypt

    def transform_data_unit(self, data: bytes, data_unit: int) -> bytes:
        self._seed[0:4] = struct.pack("<I", data_unit & 0xFFFFFFFF)
        enc_tweak = aes_ecb_encrypt(self._tweak_key, bytes(self._seed))
        orig = enc_tweak
        blocks = len(data) // BLOCK
        out = bytearray(len(data))
        for i in range(blocks):                       # input-tweak
            for y in range(BLOCK):
                out[i * BLOCK + y] = data[i * BLOCK + y] ^ enc_tweak[y]
            enc_tweak = multiply_tweak_xvdtool(enc_tweak)
        f = aes_ecb_encrypt if self._encrypt else aes_ecb_decrypt
        out = bytearray(f(self._data_key, bytes(out)))
        enc_tweak = orig                              # output-tweak
        for i in range(blocks):
            for y in range(BLOCK):
                out[i * BLOCK + y] ^= enc_tweak[y]
            enc_tweak = multiply_tweak_xvdtool(enc_tweak)
        return bytes(out)


def split_cik(cik: bytes) -> tuple[bytes, bytes]:
    """(tweak_key, data_key) na ordem do xvdtool: CIK[0:16] tweak, CIK[16:32] dados."""
    if len(cik) != 32:
        raise ValueError("CIK deve ter 32 bytes")
    return cik[:16], cik[16:]


def xts_page(cik: bytes, data: bytes, data_unit: int, section_id: int, vduid_le: bytes, encrypt: bool) -> bytes:
    tk, dk = split_cik(cik)
    return AesXtsTransform(build_tweak_seed(data_unit, section_id, vduid_le), dk, tk, encrypt).transform_data_unit(
        data, data_unit)


def xts_page_openssl(cik: bytes, data: bytes, data_unit: int, section_id: int, vduid_le: bytes,
                     encrypt: bool) -> bytes:
    """Implementacao independente: modo XTS do OpenSSL com chave = dados || tweak."""
    _require()
    tk, dk = split_cik(cik)
    c = Cipher(algorithms.AES(dk + tk), modes.XTS(build_tweak_seed(data_unit, section_id, vduid_le)))
    t = c.encryptor() if encrypt else c.decryptor()
    return t.update(data) + t.finalize()


def crypt_section(cik: bytes, data: bytes, data_units: list[int], section_id: int, vduid_le: bytes,
                  encrypt: bool) -> bytes:
    """CryptSectionXts sobre um buffer ja alinhado em paginas: um data unit por pagina."""
    if len(data) % DATA_UNIT_SIZE:
        raise ValueError("secao deve ser multipla de 0x1000")
    n = len(data) // DATA_UNIT_SIZE
    if len(data_units) != n:
        raise ValueError(f"{n} paginas, {len(data_units)} data units")
    tk, dk = split_cik(cik)
    tr = AesXtsTransform(build_tweak_seed(0, section_id, vduid_le), dk, tk, encrypt)
    out = bytearray()
    for i in range(n):
        out += tr.transform_data_unit(data[i * DATA_UNIT_SIZE:(i + 1) * DATA_UNIT_SIZE], data_units[i])
    return bytes(out)
