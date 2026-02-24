# Security Audit: libarchive RAR v4 Parser (archive_read_support_format_rar.c)

**File:** `/home/user/libarchive/libarchive/archive_read_support_format_rar.c`
**Lines:** 3,918
**Audit Date:** 2026-02-24
**Auditor:** Automated Security Review

---

## Executive Summary

This audit examines the RAR v4 format parser in libarchive, which handles decompression
of RAR archives via LZSS, PPMd, Huffman coding, and a filter system (RARVM replacement).
The RAR v4 parser has been the source of multiple CVEs (CVE-2024-20696, CVE-2024-20697,
CVE-2024-26256, CVE-2024-48957, CVE-2024-48958, CVE-2025-5914). Apple ships libarchive
as part of macOS and iOS.

The filter execution functions have been hardened after the 2024 CVEs — bounds checks now
exist in all five filter types. However, several issues remain.

---

## Finding 1: NULL Pointer Dereference in `read_exttime` (Crash/DoS)

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar.c:1938`

### Description

The `read_exttime()` function calls `localtime()` / `localtime_r()` with attacker-controlled
time values derived from the RAR archive, but never checks the return value for NULL before
dereferencing.

```c
// Line 1919: t comes from attacker-controlled archive data
t = get_time(ttime);  // get_time calls mktime(), can return -1
// ...
// Line 1932-1936: localtime can return NULL for invalid time_t values
#if defined(HAVE_LOCALTIME_S)
      tm = localtime_s(&tmbuf, &t) ? NULL : &tmbuf;
#elif defined(HAVE_LOCALTIME_R)
      tm = localtime_r(&t, &tmbuf);
#else
      tm = localtime(&t);
#endif
      nsec = tm->tm_sec + rem / NS_UNIT;  // Line 1938: NULL DEREF if tm is NULL
      if (rmode & 4)
      {
        tm->tm_sec++;       // Line 1941: also NULL deref
        t = mktime(tm);     // Line 1942: also NULL deref
      }
```

### Trigger Conditions

- Craft a RAR archive with `FHD_EXTTIME` flag set
- Set the time fields to values where `get_time()` returns a `time_t` value that
  `localtime()` cannot convert (e.g., very large negative values, or values beyond
  the system's `time_t` range)
- On many platforms, `localtime()` returns NULL for `time_t` values outside the
  representable calendar range
- `localtime_s` explicitly returns non-zero (error) for invalid times on Windows

### Impact

- **Denial of Service**: Crash via NULL pointer dereference
- **Reachable**: Any code path that opens/lists a RAR archive with extended time
  fields triggers this (no need to extract file contents)
- **Platform-dependent**: Some `localtime` implementations may not return NULL for
  any `time_t` value (e.g., glibc accepts negative values), but Windows
  `localtime_s` and macOS `localtime_r` can return NULL/error for out-of-range values

### Suggested Fix

```c
tm = localtime_r(&t, &tmbuf);
if (tm == NULL) {
    // Use epoch time as fallback, or skip this time field
    continue;
}
nsec = tm->tm_sec + rem / NS_UNIT;
```

---

## Finding 2: Uninitialized Heap Memory in Filter Global Data

**Severity:** LOW (Info Leak)
**Location:** `archive_read_support_format_rar.c:3367,3419`

### Description

In `parse_filter()`, global data for RARVM filters is allocated with `malloc()` (not
`calloc()`), and user data is written starting at offset `PROGRAM_SYSTEM_GLOBAL_SIZE`
(0x40). The first 0x40 bytes of the allocation remain uninitialized:

```c
// Line 3367: malloc, not calloc
globaldata = malloc(globaldatalen + PROGRAM_SYSTEM_GLOBAL_SIZE);
// Line 3370-3371: data written at offset 0x40+
for (i = 0; i < globaldatalen; i++)
    globaldata[i + PROGRAM_SYSTEM_GLOBAL_SIZE] = (uint8_t)membr_bits(&br, 8);
```

Then in `create_filter()` at line 3419:
```c
memcpy(filter->globaldata, globaldata, globaldatalen);
```

This copies `globaldatalen` bytes starting from offset 0 of `globaldata` — the
uninitialized portion.

### Impact

- The uninitialized bytes are largely overwritten by register values at lines 3385-3389
  (bytes 0x00-0x2F), but bytes 0x24-0x2B and 0x30-0x3F may remain uninitialized
- This data flows into the filter's VM state but is not directly output to the user in
  the current filter implementations (delta, e8, e9, rgb, audio)
- Theoretical info leak if a custom RARVM program could access this data — but the
  current code only supports fingerprint-matched built-in filters
- Low practical impact

### Suggested Fix

Replace `malloc` with `calloc` at line 3367, or use `memset(globaldata, 0, PROGRAM_SYSTEM_GLOBAL_SIZE)` after allocation.

---

## Finding 3: `copy_from_lzss_window` Takes Signed `int` Length Parameter

**Severity:** LOW (Code Quality / Defense in Depth)
**Location:** `archive_read_support_format_rar.c:3145`

### Description

```c
static int
copy_from_lzss_window(struct archive_read *a, uint8_t *buffer,
                      int64_t startpos, int length)  // <-- signed int
```

The `length` parameter is signed `int`. If a `uint32_t` value > `INT_MAX` were passed,
it would become negative. A negative `length` would bypass the `firstpart < length`
comparison and then be passed to `memcpy()` where it's converted to a very large `size_t`,
causing a massive heap buffer overflow.

### Current Mitigation

The only call site (line 3487) passes `filter->blocklength` which is bounded by
`VM_MEMORY_SIZE` (0x40000) at line 3481. This is well within `int` range.

### Impact

- Not currently exploitable due to the VM_MEMORY_SIZE bound
- Defense-in-depth concern: the function signature is inherently unsafe

### Suggested Fix

Change parameter type to `uint32_t` or `size_t`.

---

## Finding 4: `read_data_compressed` Recursive Call via PPMd (Stack Depth)

**Severity:** LOW
**Location:** `archive_read_support_format_rar.c:2196`

### Description

```c
case 0:
    rar->start_new_table = 1;
    return read_data_compressed(a, buff, size, offset, looper);  // recursive
```

The PPMd code path in `read_data_compressed` recursively calls itself. A `looper`
counter limits recursion to `MAX_COMPRESS_DEPTH` (1024) at line 2060.

### Impact

Each recursion frame is ~100-150 bytes of stack. 1024 recursions ≈ 100-150KB of stack.
Default thread stack is typically 1-8MB, so this should be safe, but on embedded systems
with small stacks, this could stack overflow.

---

## Finding 5: `staticdatalen` Integer Overflow in `compile_program` (DoS)

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar.c:3552`

### Description

```c
prog->staticdatalen = membr_next_rarvm_number(&br) + 1;
prog->staticdata = malloc(prog->staticdatalen);
```

`membr_next_rarvm_number()` returns a `uint32_t`. If it returns `0xFFFFFFFE`,
`staticdatalen` becomes `0xFFFFFFFF` (~4GB). No upper bound check exists. A crafted
RAR file can force a multi-gigabyte allocation causing OOM / denial of service.

If it returns `0xFFFFFFFF`, the `+1` wraps `staticdatalen` to 0. `malloc(0)` returns
either NULL (handled) or a minimal allocation. The subsequent loop runs 0 times, so
no memory corruption — but this is a logic bug.

### Suggested Fix

Add `if (prog->staticdatalen > VM_MEMORY_SIZE) { delete_program_code(prog); return NULL; }`.

---

## Finding 6: `numchannels == 0` Leaks Stale VM Memory

**Severity:** LOW (Info Leak)
**Location:** `archive_read_support_format_rar.c:3697,3812`

### Description

In `execute_filter_delta` and `execute_filter_audio`:
```c
uint32_t numchannels = filter->initialregisters[0]; // attacker-controlled
for (i = 0; i < numchannels; i++)  // skipped entirely when 0
```

When `numchannels == 0`, no data is processed. The output points to
`&vm->memory[length]` for `length` bytes of stale, unwritten VM memory from
prior decompression/filter operations.

### Suggested Fix

Add `if (numchannels == 0) return 0;` at the top of both functions.

---

## Finding 7: `blocklength` Bounds Check Mismatch Between Parser and Executor

**Severity:** LOW (Code Quality)
**Location:** `archive_read_support_format_rar.c:3318,3481`

### Description

In `parse_filter` (line 3318): `if (blocklength > rar->dictionary_size) return 0;`
allows `blocklength` up to `dictionary_size` (max 4MB).

In `run_filters` (line 3481): `if (filter->blocklength > VM_MEMORY_SIZE)` rejects
`blocklength` over `VM_MEMORY_SIZE` (256KB).

Filters with `blocklength` between 256KB and 4MB are parsed and queued, only to be
rejected at execution time. This wastes resources and could be tightened.

---

## Areas Confirmed Safe

### Filter Execution (Post-2024 Fixes)
- `execute_filter_e8`: Length checked `<= PROGRAM_WORK_SIZE`, `length > 4` check prevents
  underflow in `length - 5` loop. The 2024 fix (CVE-2024-20697) addressed this correctly.
- `execute_filter_delta`: `length <= PROGRAM_WORK_SIZE / 2` check, `src >= dst` overlap
  check on each iteration (CVE-2024-48957 fix)
- `execute_filter_audio`: Same `PROGRAM_WORK_SIZE / 2` and `src >= dst` checks
  (CVE-2024-48958 fix)
- `execute_filter_rgb`: `blocklength <= PROGRAM_WORK_SIZE / 2`, `stride <= blocklength`,
  `blocklength >= 3`, `byteoffset <= 2` checks

### LZSS Window Management
- `lzss_emit_match`: All offsets masked with `lzss_mask`, wrapping is correct
- `lzss_emit_literal`: Single byte write to masked position
- Window allocation: Capped at `DICTIONARY_MAX_SIZE` (4MB), `rar_fls` handles edge cases,
  `new_size == 0` is caught

### VM Memory Bounds
- VM memory size: `VM_MEMORY_SIZE + sizeof(uint32_t)` = 0x40004 bytes
- `vm_read_32` and `vm_write_32` only called from `execute_filter_e8` where max offset is
  `PROGRAM_WORK_SIZE - 4` = 0x3BFFC — well within bounds
- `run_filters` checks `blocklength <= VM_MEMORY_SIZE` before copy

### Header Parsing
- Header size validated against minimum (`sizeof(file_header) + 7`)
- Filename size checked against `endp` bounds
- Extended header sizes checked for INT64_MAX overflow
- CRC validation of headers (when not disabled)
- Unicode filename decoding bounded by `fn_end = filename_size * 2` with proper
  loop termination checks

### Dictionary Allocation
- PPMd dictionary: `(bits + 1) << 20`, max 256MB. Bounded by system memory.
- LZSS window: Capped at `DICTIONARY_MAX_SIZE` (4MB). `new_size == 0` caught.

### Huffman Decoding
- `read_next_symbol`: Table-based with tree fallback, proper EOF handling
- Symbol values bounds-checked against array sizes (`lengthb_min`, `offsetb_min`)

---

## Summary Table

| # | Severity | Finding | Exploitable? |
|---|----------|---------|-------------|
| 1 | MEDIUM | NULL deref in `read_exttime` — `localtime()` return unchecked | DoS on platforms where localtime returns NULL for OOB times |
| 2 | LOW | Uninitialized heap in filter globaldata | Theoretical info leak, not directly output |
| 3 | LOW | `copy_from_lzss_window` signed int length | Not exploitable due to VM_MEMORY_SIZE bound |
| 4 | LOW | PPMd recursive call, 1024-deep stack | Stack overflow on small-stack systems only |
| 5 | MEDIUM | `staticdatalen` integer overflow in `compile_program` | DoS via multi-GB allocation |
| 6 | LOW | `numchannels == 0` leaks stale VM memory | Stale data in output stream |
| 7 | LOW | `blocklength` bounds mismatch parser vs executor | Wasted resources, code quality |
