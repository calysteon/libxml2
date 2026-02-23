# Confirmed Findings

## Summary

After thorough analysis of the libxml2 codebase along WebKit-reachable code paths, **no new confirmed memory corruption vulnerabilities were found** that:

1. Are reachable from WebKit's usage of libxml2
2. Trigger under ASan/UBSan
3. Have a constructible proof-of-concept
4. Are not already known/fixed

This is a significant negative result that reflects the maturity of the libxml2 codebase after years of fuzzing and security hardening.

## Context

The audit was conducted against libxml2 at commit `538b2e3`, which includes very recent security fixes (February 2026):

- **538b2e3**: Integer overflow in `xmlBuildRelativeURISafe` (CWE-122/CWE-125)
- **e334a9d**: `int` to `size_t` fix in `xmlIO.c` buffer reallocation

These fixes demonstrate that integer overflow in size calculations is still an active vulnerability class in libxml2. The audit specifically looked for similar patterns throughout the codebase.

## What Was Examined

### Reachable Code (WebKit → libxml2)
- **Parser core** (`parser.c`): Push parser state machine, entity expansion, attribute parsing, DTD handling
- **SAX2 layer** (`SAX2.c`): Text coalescing, node construction, entity callbacks
- **Buffer management** (`buf.c`, `xmlIO.c`): Buffer growth, encoding conversion buffering
- **Encoding** (`encoding.c`): UTF-16↔UTF-8 conversion, encoding switching
- **Entity handling** (`entities.c`): Entity creation, expansion tracking, recursive expansion
- **URI processing** (`uri.c`): URI building, escaping, resolution
- **Tree operations** (`tree.c`): Node manipulation, document management
- **String operations** (`xmlstring.c`): String allocation, concatenation
- **Dictionary** (`dict.c`): String interning, hash operations
- **Parser internals** (`parserInternals.c`): Character reading, input management

### Bug Classes Checked
- Heap buffer overflow
- Integer overflow/underflow in size calculations
- Use-after-free (especially in error paths)
- Double-free
- Null pointer dereference leading to write
- Stack overflow from recursion
- Type confusion
- Uninitialized memory use
- Stale pointer after buffer reallocation

### Testing Performed
- 22 existing libxml2 tests with ASan: All passed
- 26 custom PoC inputs × 4 parsing modes = 104 ASan test runs: All clean
- 6 push parser chunk-boundary tests with ASan: All clean
- Custom harness mimicking WebKit's exact parser configuration

## Unconfirmed Candidates

Three candidates were documented in `../unconfirmed/`:

1. **Remaining `int` type usage in URI functions** — bounded by limits, not exploitable but should be hardened
2. **Entity namespace resolution reuse** — correctness issue, not memory corruption
3. **Default amplification limit** — 100x default is enforced, could be more restrictive

## Why No Confirmed Findings

1. **Extensive fuzzing:** The project has libFuzzer harnesses and has been fuzzed extensively with ASan. Common memory safety bugs have been found and fixed.
2. **Recent hardening:** The codebase has been actively hardened, with `int` → `size_t` conversions and overflow checks being added (commits 538b2e3, e334a9d).
3. **Bounds checking:** The `xmlSBuf` and `xmlBuf` APIs have proper overflow checks.
4. **Growth functions:** `xmlGrowCapacity` includes overflow-safe arithmetic.
5. **Entity limits:** Amplification checking (`xmlParserEntityCheck`) and nesting depth limits prevent most entity-based attacks.
6. **Encoding conversion:** UTF-16 converters have proper bounds checking on every output.
