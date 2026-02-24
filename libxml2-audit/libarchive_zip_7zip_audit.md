# Security Audit: libarchive ZIP and 7-Zip Parsers

**Files:**
- `/home/user/libarchive/libarchive/archive_read_support_format_zip.c` (4,412 lines)
- `/home/user/libarchive/libarchive/archive_read_support_format_7zip.c` (4,532 lines)

**Audit Date:** 2026-02-24
**Auditor:** Automated Security Review

---

## Executive Summary

The ZIP and 7-Zip parsers in libarchive handle complex, nested archive formats with
multiple compression methods. The 7-Zip parser in particular has a rich history of
OOB read vulnerabilities in its SFX (self-extracting) detection code. Several new
issues were found, including a critical header desynchronization bug in 7-Zip and
a never-matching encryption switch in ZIP.

---

# ZIP Parser Findings

## Finding 1: Unchecked Error Return in `zip_read_mac_metadata` (Position Corruption)

**Severity:** HIGH
**Location:** `archive_read_support_format_zip.c:4183-4184`

### Description

```c
hsize = zip_get_local_file_header_size(a, 0);  // returns ARCHIVE_WARN (-20) on failure
__archive_read_consume(a, hsize);               // passes -20 to consume
```

`zip_get_local_file_header_size()` returns `ARCHIVE_WARN` (-20) on failure. This negative
value is passed directly to `__archive_read_consume`, corrupting the read position. The
subsequent loop reads `rsrc->compressed_size` bytes from the wrong (potentially arbitrary)
location in the archive stream.

---

## Finding 2: Encryption Flags Switch/Case Never Matches (Logic Bug)

**Severity:** HIGH (Functional Bug)
**Location:** `archive_read_support_format_zip.c:2784-2794`

### Description

```c
switch (zip->flags & 0xf000) {
case 0x0001: /* Password is required to decrypt. */
case 0x0002: /* Certificates only. */
case 0x0003: /* Password or certificate required to decrypt. */
    break;
default:
    ...return (ARCHIVE_FAILED);
}
```

The mask `& 0xf000` zeroes the low 12 bits, so case values `0x0001`, `0x0002`, `0x0003`
can **never** match. Every input hits the `default` branch. Strong encryption always
fails with an error, regardless of the archive's encryption flags.

The cases should likely be `0x1000`, `0x2000`, `0x3000`, or the mask should be `& 0x000f`.

### Impact

This is a functional bug preventing strong-encrypted ZIP archives from ever being
processed. Not a security vulnerability per se, but indicates the encryption code
path may be untested and could harbor other issues.

---

## Finding 3: No ZIP Bomb Detection

**Severity:** MEDIUM
**Location:** `archive_read_support_format_zip.c` (entire file)

### Description

No compression ratio limit exists. The decompression buffer is fixed at 256KB, but the
parser produces unlimited output. A small compressed stream can decompress to gigabytes.
The `ZIP_MAX_METADATA` limit (10 MiB) only applies to Mac metadata, not regular entries.

### Impact

- **Denial of Service**: Resource exhaustion via crafted ZIP bombs
- Caller must implement their own decompression ratio limiting

---

## Finding 4: Unbounded Central Directory Entry Allocation

**Severity:** LOW
**Location:** `archive_read_support_format_zip.c:3936-3964`

### Description

The `slurp_central_directory` loop allocates one `struct zip_entry` per record with no
upper bound (unlike 7-Zip's `UMAX_ENTRY` limit). A crafted ZIP with millions of tiny
entries can exhaust memory.

---

## Finding 5: Decryption Buffer Underflow Risk

**Severity:** LOW
**Location:** `archive_read_support_format_zip.c:2674-2678`

### Description

```c
zip->decrypted_bytes_remaining -= to_consume;  // size_t subtraction
```

`decrypted_bytes_remaining` is `size_t` (unsigned). If `to_consume` exceeds it due to
corrupted data, the subtraction wraps to a huge value, and `decrypted_ptr` advances past
the buffer end. The next decryption pass computes a large `buff_remaining` and could
overflow the buffer.

---

# 7-Zip Parser Findings

## Finding 6: `kArchiveProperties` Data Never Consumed (Header Desync)

**Severity:** HIGH
**Location:** `archive_read_support_format_7zip.c:2767-2776`

### Description

```c
if (*p == kArchiveProperties) {
    for (;;) {
        uint64_t size;
        if ((p = header_bytes(a, 1)) == NULL) return (-1);
        if (*p == 0) break;
        if (parse_7zip_uint64(a, &size) < 0) return (-1);
        // BUG: 'size' bytes of property data are NEVER consumed/skipped
    }
```

The property ID and size are read, but the `size` bytes of actual property data are
never skipped via `header_bytes()`. This desynchronizes the header parser. All subsequent
reads interpret property data as header structure, controlling allocation sizes, coder
configs, and file counts.

### Impact

- **Memory Corruption**: A crafted archive with `kArchiveProperties` entries can cause
  the parser to interpret arbitrary data as folder counts, coder configs, allocation
  sizes — potentially leading to heap overflow via controlled allocation sizes
- **Reachable**: Any 7z archive with an ArchiveProperties header triggers this path

---

## Finding 7: Directory Entry Name Heap OOB Write

**Severity:** MEDIUM
**Location:** `archive_read_support_format_7zip.c:3049-3051`

### Description

```c
entries[i].utf16name[entries[i].name_len] = '/';
entries[i].utf16name[entries[i].name_len+1] = 0;
entries[i].name_len += 2;
```

Appends 2 bytes past `name_len` into a packed buffer (`zip->entry_names`, allocated at
line 2897 as exactly `ll` bytes). If the last entry is a directory without a trailing
slash, this writes 2 bytes past the heap allocation.

---

## Finding 8: `numDigests` uint32_t Overflow

**Severity:** MEDIUM
**Location:** `archive_read_support_format_7zip.c:2599-2603`

### Description

```c
uint32_t numDigests;
numDigests += (uint32_t)f[i].numUnpackStreams;
```

Each `numUnpackStreams` can be up to `UMAX_ENTRY` (100,000,000). Across multiple folders,
`numDigests` wraps around 32 bits. The wrapped value sizes the allocation in
`read_Digests()`, causing a small allocation followed by writes for the actual number
of entries — a heap overflow.

---

## Finding 9: PE Overlay Integer Overflow on 32-bit (SFX Detection)

**Severity:** MEDIUM
**Location:** `archive_read_support_format_7zip.c:683,705,713,722-725`

### Description

`offset` is derived from attacker-controlled PE header fields. The computation
`offset + sec_cnt * PE_SEC_HDR_LEN` and `archive_le32dec(raw_sz) + archive_le32dec(raw_addr)`
can overflow `ssize_t` on 32-bit platforms, producing a negative `sec_end` or incorrect
`max_offset`. This misdirects the SFX scanner.

---

## Finding 10: ELF Section Table Size Overflow on 32-bit (SFX Detection)

**Severity:** MEDIUM
**Location:** `archive_read_support_format_7zip.c:801-803`

### Description

```c
request = (size_t)e_shnum * (size_t)e_shentsize + 0x28;
```

On 32-bit, `65535 * 65535` overflows `size_t`, causing `__archive_read_ahead` to request
fewer bytes than needed. Subsequent accesses read past the returned buffer.

---

## Summary Table

| # | Severity | Parser | Finding | Exploitable? |
|---|----------|--------|---------|-------------|
| 1 | HIGH | ZIP | Unchecked error return corrupts read position | Position corruption, wrong data read |
| 2 | HIGH | ZIP | Encryption switch cases never match | Logic bug, encryption path untested |
| 3 | MEDIUM | ZIP | No ZIP bomb detection | DoS via resource exhaustion |
| 4 | LOW | ZIP | Unbounded central directory allocation | OOM DoS |
| 5 | LOW | ZIP | Decryption buffer underflow on corrupted data | Potential buffer overflow |
| 6 | HIGH | 7-Zip | kArchiveProperties data never consumed | Header desync → memory corruption |
| 7 | MEDIUM | 7-Zip | Directory entry name heap OOB write | 2-byte heap overflow |
| 8 | MEDIUM | 7-Zip | numDigests uint32_t overflow | Heap overflow via small allocation |
| 9 | MEDIUM | 7-Zip | PE overlay integer overflow on 32-bit | SFX scanner misdirection |
| 10 | MEDIUM | 7-Zip | ELF section table size overflow on 32-bit | OOB read in SFX detection |
