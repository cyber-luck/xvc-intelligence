"""Leitor minimo de hive de registro (regf), somente leitura."""
import struct, sys, datetime

TYPES = {0: "NONE", 1: "SZ", 2: "EXPAND_SZ", 3: "BINARY", 4: "DWORD", 5: "DWORD_BE", 7: "MULTI_SZ", 11: "QWORD"}

def filetime(v):
    return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)).isoformat() if v else "0"

class Hive:
    def __init__(self, b):
        if b[:4] != b"regf":
            raise ValueError("assinatura regf ausente")
        self.b = b
        self.root = struct.unpack_from("<I", b, 0x24)[0]
        self.name = b[0x30:0x70].decode("utf-16-le", "replace").split("\0")[0]

    def cell(self, off):
        o = 0x1000 + off
        size = struct.unpack_from("<i", self.b, o)[0]
        return self.b[o + 4:o + 4 + abs(size) - 4]

    def subkeys(self, off):
        c = self.cell(off)
        sig, n = c[:2], struct.unpack_from("<H", c, 2)[0]
        if sig in (b"lf", b"lh"):
            return [struct.unpack_from("<I", c, 4 + 8 * i)[0] for i in range(n)]
        if sig == b"li":
            return [struct.unpack_from("<I", c, 4 + 4 * i)[0] for i in range(n)]
        if sig == b"ri":
            return [k for i in range(n) for k in self.subkeys(struct.unpack_from("<I", c, 4 + 4 * i)[0])]
        raise ValueError(f"lista de subchaves desconhecida {sig!r}")

    def value(self, off):
        c = self.cell(off)
        assert c[:2] == b"vk", c[:2]
        nlen, dsize, doff, vtype, flags = struct.unpack_from("<HIIIH", c, 2)
        name = c[0x14:0x14 + nlen]
        name = name.decode("latin-1") if flags & 1 else name.decode("utf-16-le")
        inline = bool(dsize & 0x80000000)
        dsize &= 0x7FFFFFFF
        data = struct.pack("<I", doff)[:dsize] if inline else self.cell(doff)[:dsize]
        return name or "(padrao)", vtype, data

    def walk(self, off=None, depth=0, out=print):
        off = self.root if off is None else off
        c = self.cell(off)
        assert c[:2] == b"nk", c[:2]
        flags, ts = struct.unpack_from("<HQ", c, 2)
        nsub, = struct.unpack_from("<I", c, 0x14)
        lsub, = struct.unpack_from("<I", c, 0x1C)
        nval, lval = struct.unpack_from("<II", c, 0x24)
        nlen, = struct.unpack_from("<H", c, 0x48)
        raw = c[0x4C:0x4C + nlen]
        name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le")
        pad = "  " * depth
        out(f"{pad}[{name}]  ({filetime(ts)})")
        if nval:
            vl = self.cell(lval)
            for i in range(nval):
                vn, vt, data = self.value(struct.unpack_from("<I", vl, 4 * i)[0])
                out(f"{pad}  {vn} = {fmt(vt, data)}")
        if nsub:
            for k in self.subkeys(lsub):
                self.walk(k, depth + 1, out)

def fmt(vt, d):
    t = TYPES.get(vt, f"type{vt}")
    if vt in (1, 2):
        return f"{t} {d.decode('utf-16-le', 'replace').rstrip(chr(0))!r}"
    if vt == 7:
        return f"{t} {[s for s in d.decode('utf-16-le', 'replace').split(chr(0)) if s]}"
    if vt == 4 and len(d) == 4:
        return f"{t} {struct.unpack('<I', d)[0]:#x}"
    if vt == 11 and len(d) == 8:
        return f"{t} {struct.unpack('<Q', d)[0]:#x}"
    return f"{t} {d.hex(' ')}"

if __name__ == "__main__":
    h = Hive(open(sys.argv[1], "rb").read())
    print(f"hive: raiz 0x{h.root:x}, nome interno {h.name!r}")
    h.walk()
