# Candidate: Remaining `int` Type Usage in URI Functions

## Status: UNCONFIRMED — bounded by limits, unlikely exploitable

## CWE Classification: CWE-190 (Integer Overflow)

## Vulnerable Code
- **File:** `uri.c`
- **Functions:** `xmlSaveUri()`, `xmlURIEscapeStr()`, `xmlBuildURISafe()`, `xmlResolvePath()`
- **Pattern:** `int` variables used for string lengths and buffer sizes

## Description

Following the fix in commit `538b2e3` for `xmlBuildRelativeURISafe`, several other URI functions still use `int` for length/size variables:

### xmlSaveUri() (line 1095-1320)
```c
int len;  // Line 1099
int max;  // Line 1100
```
`len` and `max` are bounded by `MAX_URI_LENGTH` (1,048,576 = 1MB) via `xmlSaveUriRealloc` → `xmlGrowCapacity`. **Not exploitable** because the URI is capped at 1MB.

### xmlURIEscapeStr() (line 1637-1696)
```c
int len, out;  // Line 1640
```
`len` grows via `xmlGrowCapacity(len, 1, 1, XML_MAX_ITEMS)`. `XML_MAX_ITEMS` is 1 billion, which fits in `int`. **Not directly exploitable** but the `int` type for the initial `xmlStrlen()` call returns 0 for strings > INT_MAX, causing truncated processing.

### xmlBuildURISafe() (line 1970-2318)
```c
int ret, len, indx, cur, out;  // Line 1972
```
At lines 2243-2248:
```c
len = 2;
if (ref->path != NULL) len += strlen(ref->path);
if (bas->path != NULL) len += strlen(bas->path);
res->path = xmlMalloc(len);
```
`strlen()` returns `size_t`, implicitly truncated to `int`. If both paths are > INT_MAX/2, `len` overflows. However, `xmlMalloc` with a negative `int` argument gets sign-extended to a huge `size_t`, causing allocation failure (not undersized allocation). **Not exploitable** as a buffer overflow, but could cause unexpected NULL returns.

### xmlResolvePath() (line 1861-1936)
```c
int refLen = xmlStrlen(ref);  // Line 1917
result = xmlMalloc(i + refLen + 1);  // Line 1919
```
Same pattern as above. `xmlStrlen` returns 0 for huge strings, and `int` arithmetic overflow leads to allocation failure rather than undersized allocation.

## WebKit Reachability

URI functions are called from:
- `xmlBuildURI()` during document URI resolution
- `xmlSaveUri()` during URI serialization
- `xmlURIEscapeStr()` during URI escaping
- XSLT `document()` function calls

However, URIs in WebKit are typically bounded by WebKit's own URL processing before reaching libxml2. Extremely long URIs (> INT_MAX) are unlikely to reach these functions in practice.

## Why Not Confirmed

1. `xmlSaveUri` is bounded by `MAX_URI_LENGTH` (1MB) — cannot overflow
2. `xmlURIEscapeStr` is bounded by `XML_MAX_ITEMS` (1B) — fits in `int`
3. `xmlBuildURISafe`/`xmlResolvePath` — overflow in allocation size causes failure, not undersized allocation
4. WebKit performs URL processing that limits URI component sizes
5. No ASan trigger with any test input

## Recommendation

While these are not exploitable vulnerabilities, the `int` types should be converted to `size_t` for defense-in-depth, following the pattern of commit `538b2e3`. This would prevent future issues if limits are changed.

Specific functions to update:
- `xmlSaveUri()`: `len` and `max` → `size_t`
- `xmlURIEscapeStr()`: `len` and `out` → `size_t`
- `xmlBuildURISafe()`: `len`, `indx`, `cur`, `out` → `size_t`
- `xmlResolvePath()`: `refLen` → `size_t`
