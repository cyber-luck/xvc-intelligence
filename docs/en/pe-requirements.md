# What is needed to analyse the internal PE structures of `game_scarlett_master.exe`

**Language / Idioma:** English · [Português](../pt/pe-requisitos.md)

## Situation

All of the executable's storage is verified against the package's bytes (CONFIRMED):

- segment 12, region 0x3E9 (a region with a single file), KeyId 0;
- offset 0x64917000, 120,181,760 bytes, 29,342 pages;
- segment and region hashes match (3b221181d8be52ba);
- 16 sampled hash-tree leaves match;
- a single entry in the page table.

The executable's **content** is not readable:

- the stored bytes do not start with `MZ`, and `parse_pe` returns `bad_magic`;
- entropy is about 7.997 bits/byte across 16 windows of 64 KB spread through the file;
- the region has KeyId 0, while regions with readable content have KeyId 0xFFFF;
- the header does not have the `EncryptionDisabled` bit.

This is **consistent** with encrypted content, but it is not proof: high entropy does not show encryption (rule 8).

**Conclusion:** no internal PE structure (headers, sections, imports, exports, resources, debug/PDB, TLS, load config, functions, strings) can be obtained from this package without the content keys. This project does not have those keys, does not look for them, does not derive keys and does not try to get around the protection (rules 5 and 6). The names of the 16 shipped DLLs are **not** evidence of imports.

## What is needed

A **readable PE of `game_scarlett_master.exe`, obtained legitimately**. For example:

- a development build supplied by the rights holder;
- a matching symbol file (PDB), when available;
- a decrypted copy obtained through a process authorized by the rights holder.

Its provenance must be documented. Copies of unestablished origin (for example, those in `G:\MyGame_v1\PROJECT_ALPHA`) were **not** opened. Deciding about them is up to the user.

## How to check that the PE matches this package (without a key)

With a readable PE in hand, the match can only be shown indirectly:

1. The size must be exactly 120,181,760 bytes (CONFIRMED by SegmentMetadata). This is necessary but not sufficient.
2. The SHA-256 of the **stored** bytes (79fe1510…) and the segment hash refer to the ciphertext. They are therefore **not** usable to compare with a decrypted PE.
3. A useful comparison: look for the PE's hashes (SHA-1, SHA-256 and Authenticode) inside `Catalog000.bin`, which is a readable Xbox code catalog. Today the search for the hashes of the stored bytes comes back negative (F-EXE-04), which is expected if the catalog describes the decrypted content.
4. Version: the PE or PDB should match package version 1.0.2.1 (the header's PackageVersion, already CONFIRMED against MicrosoftGame.config).

## What becomes possible with the readable PE

`formats/pe.py` is ready and was tested on Windows PEs against `pefile`:

| Structure | Command | Already implemented |
|---|---|---|
| DOS, COFF and optional headers (PE32+ AMD64 expected), alignments, subsystem | `python -I xvcintel.py pe FILE --json out.json` | Yes |
| Section table, RVA → offset mapping, overlaps | same | Yes |
| Imports by DLL and by function (by name or ordinal), delay imports | same | Yes |
| Exports, including forwarders | same | Yes |
| Resource tree (count by type) | same | Yes |
| Debug directory, CodeView RSDS (GUID, age, PDB path, symbol-server key) | same | Yes |
| Security directory (WIN_CERTIFICATE, presence of PKCS#7) | same | Yes |
| COFF symbol table (pointer, count, string table) | same | Yes |
| Cross-reference imports with the package's 16 DLLs (CONFIRMED instead of UNKNOWN) | to do: feed `graph.py` with `pe.imports` | Partial (the IMPORTS edges exist as UNKNOWN) |
| Disassembly and functions | external tools (Ghidra/IDA) on the readable PE | Out of scope |

## Recommended next step

The step most likely to produce new information about the executable is to obtain the legitimate artifact described above and run `xvcintel pe` on it. Without the artifact, what can still be investigated is structural, such as the origin of the data-unit reuse and the exceptions in segments 78 and 90. That requires comparing with another version of the same package. It reveals nothing about the code.
