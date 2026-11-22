# XVD/XVC format notes (with confidence labels)

**Language / Idioma:** English · [Português](../pt/formato.md)

Offsets are absolute in the file unless stated otherwise. The "Test" column points to the check id (in `reports/findings.json`) or to the matching pytest test.

## Header (xvdtool `XvdHeader`; xvdtool comment + 0x200 = absolute offset)

| Offset | Field | In this package | Confidence | Test |
|---|---|---|---|---|
| 0x208 | VolumeFlags | 0x41 = ReadOnly \| RegionIdInXts | value CONFIRMED; names INFERRED (xvdtool) | F-HDR-05 |
| 0x240 | TopHashBlockHash | = SHA-256(hash-tree page 0) | CONFIRMED | integrity.top_hash |
| 0x260 | OriginalXvcDataHash | not reproduced by 9 serializations (incl. xvdtool's VerifyXvcHash) | UNKNOWN | hypothesis.metadata_hash |
| 0x30C | PECatalogHash | ≠ SHA-256(Catalog000.bin) | UNKNOWN (relationship) | F-EXE-04 |
| 0x32C | EmbeddedXVD_PDUID | = PDUID of the embedded XVD = hash of the XVC-EXVD region | CONFIRMED | embedded.pduid_link, F-RG-02 |
| 0x39C | ProductId | contains the 12 ASCII characters of the StoreId (positions 0–6 and 9–13) | CONFIRMED (bytes); encoding INFERRED | F-HDR-08 |
| 0x3BC | PackageVersion 4×u16 | (1,2,0,1), which read in reverse gives 1.0.2.1 = manifest | CONFIRMED | F-HDR-03 |
| 0x46C | PersistentLocalStorageSize | 0x800 = SizeMB 2048 | CONFIRMED | F-HDR-04 |
| 0x470 | MutableDataPageCount | 1 = length of XVC-MDU (the old probe read 0x5E0) | CONFIRMED | layout.mdu_vs_region |
| 0x471 | Unknown471 | 0x04 | value CONFIRMED; meaning UNKNOWN | F-HDR-07 |
| 0x494 | MinSysVersion 4×u16 | (0x25AF, 0x65F4, 0, 0x800A) | value CONFIRMED; reading as 10.0.26100.9647 + bit 0x8000 INFERRED | F-HDR-06 |

## Layout

The layout is header 0x3000 | embedded XVD | MDU | hash tree | user data | XvcInfo | dynamic header | drive data. It is calculated only from the header and ends exactly at the file size. CONFIRMED (layout.*).

## Hash tree

- Entries are 0x18 bytes, with 170 entries per page and the highest level stored first.
- Hashed pages: drive + user data + XvcInfo + dynamic header = 54,605,734. Hashed page 0 is the start of the user data.
- Pages per level: L0..L3 = 321211, 1890, 12, 1. Each level starts, in hash-tree pages, at 1903, 13, 1 and 0.
- The links were fully verified at every level (--full-leaf). CONFIRMED (F-HT-01..03).
- Leaves:
  - in regions with KeyId ≠ 0xFFFF, `entry[:0x14] = SHA-256(stored page)[:0x14]` and `entry[0x14:0x18]` is a u32 ("data unit");
  - in 0xFFFF regions and in the metadata, `entry = SHA-256[:0x18]`;
  - verified by sampling 116 pages. CONFIRMED (F-HT-04).
- According to xvdtool the u32 is the XTS tweak. This stays INFERRED and is documented **as structure only**: no cryptographic experiment was done.

## XvcInfo

- 0xD10..0xDA8: xvdtool fields. Values: RegionSpecifierCount (0xD50) = 0; PageTableCount (0xD54, "ReservedD54" in xvdtool) = 76,469.
- 0xDA8: 31 region headers of 0x80 bytes each. They are followed by 108 update segments of 12 bytes each, starting at +0x1D28.
- +0x2238: one u32 per segment. It equals the data unit of the segment's first page in 105/108 (CONFIRMED). Exceptions:

  | Segment | File | Difference |
  |---|---|---|
  | 78 | anim.rpf | −1 |
  | 90 | story000_script.rpf | −37 |
  | 107 | Update.alignmentchunk | no relation |

  None of the three values is the data unit of any page (neither in a ±2000-page window nor inside any run of the table). The cause is UNKNOWN (F-PT-07-*).
- +0x23E8: a (u32 PageNum, u32 Value) table, strictly increasing. It is a **run-length encoding of the data units**: unit(p) = Value + (p − PageNum) of the entry that governs the page.
  - All 54,601,906 pages with a KeyId follow the rule; among the 3,401 pages without a KeyId, 3,390 are exceptions.
  - There are no redundant entries.
  - CONFIRMED (F-PT-01..03), with a full scan.
- Data units **repeat** within the same region: 44,179,883 pages share their value with another page, for 13,233,733 distinct values. In 400 sampled pairs (same unit, same region) the stored hash is never equal. CONFIRMED (F-PT-04); reason UNKNOWN.
- Region hash (+0x60, 8 bytes) = SHA-256(stored bytes of the region)[:8]. CONFIRMED for all 28 tested regions at full coverage (previously only 13 regions ≤ 160 MB); the XVC-EXVD region uses the PDUID; XVC-HD and XVC-MD share 5c2b65ad36990544 (UNKNOWN). See [full-hash-verification.md](full-hash-verification.md).
- Update-segment hash = SHA-256(segment pages)[:8]. CONFIRMED for 108/108 segments at full coverage (previously only the 49 segments ≤ 160 MB).
- Region flags: 0x1 on metadata regions, 0x0 on content regions and 0x4 on the InitialPlay region. The names in xvdtool's enum do not match this use. UNKNOWN (F-RG-04).
- InitialPlayOffset = end of the InitialPlay region = file size. CONFIRMED (F-RG-05).

## User data and SegmentMetadata (" PFX")

- Formats described in `formats/userdata.py`: 6 files and 108 entries.
- The 108 relative pages equal the segment's PageNum minus the drive's start page. CONFIRMED (F-FM-01).
- The GUID b364c736-… does not appear in the header, the XvcInfo or the other user-data files. CONFIRMED (F-FM-02); meaning UNKNOWN.

## Embedded XVD (XVC-EXVD region)

- The header and layout parser works on it: it is EraOS, Dynamic, DriveSize 512 MB.
- Top hash, L0→L1 link and user-data leaf 0 match. In the leaf, `entry[:0x14]` is the hash and `entry[0x14:0x18]` is 0.
- The end of the calculated layout does not match EmbeddedXVDLength. That is expected for a dynamic XVD, but the BAT has not been decoded. UNKNOWN.
