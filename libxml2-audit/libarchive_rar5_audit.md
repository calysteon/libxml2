# Security Audit: libarchive RAR v5 Parser (archive_read_support_format_rar5.c)

**File:** `/home/user/libarchive/libarchive/archive_read_support_format_rar5.c`
**Lines:** 4,411
**Audit Date:** 2026-02-24
**Auditor:** Automated Security Review

---

## Executive Summary

The RAR5 parser is a separate, newer implementation written by Grzegorz Antoniak.
It handles RAR5 format archives with LZSS decompression, filters (delta, E8/E9, ARM),
and solid stream support. Several significant issues were found, particularly around
signed/unsigned type confusion and missing NULL checks on allocations.

---

## Finding 1: Missing NULL Checks After `calloc` in `init_unpack` (Crash)

**Severity:** HIGH
**Location:** `archive_read_support_format_rar5.c:2568-2569`

### Description

Both `calloc(1, window_size)` calls for decompression window buffers (up to 64MB each)
have no NULL check. The function returns `void` and cannot signal failure. A failed
allocation leads to NULL `window_buf`, which is dereferenced at line 3186:

```c
rar->cstate.window_buf[write_idx & cmask] = (uint8_t) num;
```

### Impact

- **Crash/DoS**: Any OOM condition during RAR5 decompression crashes the process
- A crafted archive requesting max window size (64MB) increases likelihood of OOM

---

## Finding 2: Signed Truncation of `unpacked_size` on 32-bit (Safety Bypass)

**Severity:** HIGH
**Location:** `archive_read_support_format_rar5.c:2029`

### Description

```c
rar->file.unpacked_size = (ssize_t) unpacked_size;  // uint64_t → ssize_t
```

On 32-bit systems, any `unpacked_size >= 2^31` becomes negative. This breaks the
safety check at line 4217 (`last_write_ptr > unpacked_size`) and the EOF check at
line 4238, potentially allowing unbounded decompression output.

---

## Finding 3: OOB Read in `read_bits_32` and `read_bits_16`

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar5.c:1038-1067`

### Description

`read_bits_32` checks `in_addr >= cur_block_size` but reads up to `p[in_addr + 4]`.
When `in_addr == cur_block_size - 1`, four bytes are read past the validated boundary.

Mitigated by callers over-allocating buffers by 8 bytes (lines 3500, 3668), but this
is a fragile implicit contract — any new caller could introduce OOB reads.

---

## Finding 4: Signed Truncation of `bytes_remaining` on 32-bit

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar5.c:1789`

### Description

`size_t data_size` assigned to `ssize_t bytes_remaining`. On 32-bit, values >= 2^31
become negative, causing the solid-skip loop to exit immediately and `consume` to
receive a sign-extended negative value as a huge positive `int64_t`.

---

## Finding 5: Memory Leak DoS via Filter Accumulation

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar5.c:557`

### Description

`cdeque_push_back` return value is ignored in `add_new_filter`. If the deque is full
(capacity 8192), the allocated `filter_info` is leaked. A crafted archive declaring
thousands of filters causes unbounded memory growth — denial of service.

---

## Finding 6: `extra_field_size` Underflow in Header Parsing

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar5.c:1640`

### Description

`extra_field_size -= var_size` is `uint64_t - uint64_t`. If `var_size > extra_field_size`
(possible with a crafted archive), the result wraps to a huge value. This is passed to
subsequent size calculations and `consume` calls.

---

## Finding 7: `read_var_sized` Truncation on 32-bit

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar5.c:1024`

### Description

`*pvalue = (size_t) v` silently truncates 64-bit varints to 32 bits on 32-bit platforms.
This affects `name_size`, `data_size`, `file_flags`, and other header fields. A crafted
value can pass size checks after truncation while actual consumed bytes differ.

---

## Finding 8: `circular_memcpy` with Potential Negative Length

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar5.c:527-532`

### Description

`(size_t)(end - start)` wraps to a huge value if `end < start`. This can occur when
`solid_offset + block_start + block_length` overflows. Callers (`run_e8e9_filter`,
`run_arm_filter`) pass accumulated signed arithmetic that can overflow in long solid
streams.

---

## Finding 9: Unbounded `solid_offset` Accumulation

**Severity:** LOW
**Location:** `archive_read_support_format_rar5.c:876`

### Description

`rar->cstate.solid_offset += rar->cstate.write_ptr` in `reset_file_context` has no
overflow check. After many solid entries, `solid_offset` can overflow `INT64_MAX`,
corrupting all window buffer index calculations.

---

## Finding 10: `block_start` Overflow on 32-bit in Filter Validation

**Severity:** MEDIUM
**Location:** `archive_read_support_format_rar5.c:2995,3059`

### Description

`uint32_t start` is cast to `ssize_t` at line 2995. On 32-bit, values >= 0x80000000
become negative, bypassing filter block start validation. The resulting negative
`filt->block_start` causes out-of-bounds reads in filter execution functions.

---

## Positive: CVE-2025-5914 Not Applicable

The RAR5 `rar5_seek_data` function (lines 4309-4319) is a stub that always returns
`ARCHIVE_FATAL`. The integer-overflow-leading-to-double-free pattern from CVE-2025-5914
in the RAR v4 seek function does not apply here.

---

## Summary Table

| # | Severity | Finding | Exploitable? |
|---|----------|---------|-------------|
| 1 | HIGH | Missing NULL checks after calloc in init_unpack | Crash on OOM |
| 2 | HIGH | Signed truncation of unpacked_size on 32-bit | Unbounded decompression |
| 3 | MEDIUM | OOB read in read_bits_32/16 | Fragile implicit contract |
| 4 | MEDIUM | Signed truncation of bytes_remaining on 32-bit | Incorrect consume behavior |
| 5 | MEDIUM | Memory leak DoS via filter accumulation | Unbounded memory growth |
| 6 | MEDIUM | extra_field_size underflow in header parsing | Corrupted size calculations |
| 7 | MEDIUM | read_var_sized truncation on 32-bit | Size check bypass |
| 8 | MEDIUM | circular_memcpy with negative length | OOB access in filter execution |
| 9 | LOW | Unbounded solid_offset accumulation | Index corruption after overflow |
| 10 | MEDIUM | block_start overflow on 32-bit | OOB reads in filter execution |
