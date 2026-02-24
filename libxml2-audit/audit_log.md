# libxml2 Security Audit Log

## Audit Scope
- **Target:** libxml2 (HEAD at commit 538b2e3)
- **Focus:** Memory corruption vulnerabilities reachable from WebKit
- **Date:** 2026-02-23

## Phase 1: WebKit Attack Surface Mapping

### Files Analyzed
- `WebKit/Source/WebCore/xml/parser/XMLDocumentParserLibxml2.cpp`
- `WebKit/Source/WebCore/xml/parser/XMLDocumentParser.cpp`
- `WebKit/Source/WebCore/xml/parser/XMLDocumentParser.h`
- `WebKit/Source/WebCore/xml/XSLTProcessorLibxslt.cpp`
- `WebKit/Source/WebCore/xml/XSLTProcessor.cpp`
- `WebKit/Source/WebCore/xml/XSLStyleSheetLibxslt.cpp`
- `WebKit/Source/WebCore/xml/XPathParser.cpp`
- `WebKit/Source/WebCore/xml/XPathExpression.cpp`
- `WebKit/Source/WebCore/xml/XMLHttpRequest.cpp`
- `WebKit/Source/WebCore/xml/DOMParser.cpp`

### Key Findings
1. WebKit uses `XML_PARSE_NOENT | XML_PARSE_HUGE` for document parsing
2. WebKit uses `XML_PARSE_NODICT | XML_PARSE_NOENT | XML_PARSE_HUGE` for fragment parsing
3. XSLT uses `XML_PARSE_NOENT | XML_PARSE_DTDLOAD | XML_PARSE_DTDATTR | XML_PARSE_NOCDATA`
4. WebKit has its own XPath engine — libxml2's xpath.c is NOT reachable
5. Push-mode parsing with UTF-16 input
6. No explicit entity amplification limit (relies on libxml2 default)
7. External entity loading gated by same-origin policy
8. Tree depth limited to 5000

## Phase 2: Targeted libxml2 Code Audit

### Files Audited (Reachable Paths)

| File | Lines | Focus Areas | Issues Found |
|---|---|---|---|
| `parser.c` | ~12,000 | Push parser, entity expansion, attribute parsing | See findings |
| `parserInternals.c` | ~2,200 | xmlCurrentChar, xmlNextChar, encoding | No issues |
| `SAX2.c` | ~2,600 | Text coalescing, node construction | No issues |
| `buf.c` | ~600 | Buffer growth, xmlBuf API | Clean |
| `encoding.c` | ~2,700 | UTF-16 conversion, encoding switching | Clean |
| `entities.c` | ~900 | Entity creation, expansion tracking | Clean |
| `dict.c` | ~900 | String dictionary, hash operations | Clean |
| `tree.c` | ~8,000 | Node manipulation, tree operations | Clean |
| `uri.c` | ~2,400 | URI building, escaping, resolution | See findings |
| `xmlIO.c` | ~2,400 | Input buffer management | Recently fixed (e334a9d) |
| `xmlstring.c` | ~500 | String operations | Clean |

### Audit Methodology
1. Searched for `int` variables used for sizes/lengths in allocation-related code
2. Checked for integer overflow in arithmetic before `xmlMalloc`/`xmlRealloc`
3. Analyzed error paths for use-after-free patterns
4. Verified buffer bounds in encoding conversion
5. Checked entity expansion depth/amplification limits
6. Analyzed push parser state machine for stale pointer issues
7. Verified SAX callback implementations for memory safety

### Areas Confirmed Safe
- **xmlSBuf** (parser.c): Uses `unsigned`, proper overflow checks, bounded by max length
- **xmlBuf** (buf.c): Uses `size_t`, proper growth logic
- **UTF-16→UTF-8 conversion** (encoding.c): Proper bounds checking on every write
- **xmlCharEncInput** (encoding.c): Proper size_t usage, INT_MAX/2 capping
- **Entity amplification**: Default limit enforced via `xmlParserEntityCheck`
- **SAX2 text coalescing** (SAX2.c): `int` sizes bounded by XML_MAX_HUGE_LENGTH (1B), within int range
- **xmlGrowCapacity** (memory.h): Correct overflow-safe growth calculation
- **Namespace handling** (parser.c): Clean push/pop/lookup with proper bounds
- **Attribute handling** (parser.c): `xmlCtxtGrowAttrs` uses `xmlGrowCapacity` correctly

### Negative Results (Important)
- No use-after-free found in error paths
- No stack overflow beyond configured depth limits
- No type confusion in reachable code paths
- No double-free in cleanup code
- No uninitialized memory use in reachable paths
- Push parser state machine appears correct for boundary conditions
- UTF-16 surrogate pair handling is correct

## Phase 3: ASan/UBSan Testing

### Build Configuration
```bash
cmake -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DLIBXML2_WITH_PYTHON=OFF -DBUILD_SHARED_LIBS=OFF
```

### Test Results
- **libxml2 test suite:** 22/22 tests passed with ASan (0 errors)
- **Custom PoC inputs:** 26 test files, 4 modes each = 104 test runs, 0 ASan errors
- **Push parser chunking:** 6 chunk boundary tests, 0 ASan errors
- **Existing fuzz corpus:** Extensive coverage already via libFuzzer

### PoC Files Tested
- Entity expansion (billion laughs variants)
- Deep entity nesting (up to 40 levels)
- Deep element nesting (256 levels)
- Entity expansion in attributes
- Namespace flooding
- Entity in namespace URIs
- Mixed entity/text content
- CDATA boundary conditions
- Entity redefinition
- PI/comment edge cases
- Encoding switching
- Character reference boundaries
- Long attribute values (10MB)
- Many attributes (10,000)
- Entity with markup content
- Entity in different namespace contexts
- Empty entity expansion chains
- Deep entity chain in attributes
- Large CDATA sections
- Mixed attribute entity types
- UTF-16 LE/BE with BOM
- Truncated UTF-16
- Invalid UTF-8 sequences
- UTF-16 surrogate pairs
- Invalid surrogate pairs

## Phase 4: XPath Engine Audit (xpath.c)

### Key Correction
The Phase 1 assessment that "WebKit has its own XPath engine — libxml2's xpath.c is NOT reachable" is **incomplete**. WebKit uses libxslt for XSLT processing, and libxslt calls `xmlXPathCompiledEval()` extensively. Attacker-controlled XPath expressions in XSLT stylesheets reach xpath.c.

### Files Audited

| File | Lines | Focus Areas | Issues Found |
|---|---|---|---|
| `xpath.c` | 12,153 | Value stack, node-sets, compilation, evaluation, string functions, axis traversal | 1 medium + 8 low-severity findings |
| `timsort.h` | ~400 | Timsort sort algorithm (used by xpath.c) | Included in xpath.c findings |

### Findings
1. **LOW** — Potential NULL dereference in XSLT result tree fragment transfer (line 10347): `ctxt->value` may be NULL when `obj->boolval && obj->user` — requires unlikely object state
2. **LOW** — Timsort comparison function propagates error code -2, violating total ordering — theoretical concern for cross-document node-sets
3. **LOW** — Locale-dependent `toupper()` in `lang()` function (line 7966) — correctness issue, not memory safety
4. **LOW** — O(n²) node-set equality comparison not covered by `opLimit` — bounded by `XPATH_MAX_NODESET_LENGTH`
5. **MEDIUM** — **Timsort calls `exit(1)` on merge-buffer allocation failure** (`timsort.h:365`) — process-killing DoS reachable from any XPath sort with >64 nodes under memory pressure
6. **LOW** — `concat()` continues after OOM, producing corrupt output — error flag is set, not exploitable beyond OOM
7. **LOW** — `xmlXPathFreeObject` instead of `xmlXPathReleaseObject` in `xmlXPathEqualValues` — cache bypass
8. **LOW** — `xmlNodeGetContent` NULL not checked before `xmlStrEqual` in `xmlXPathEqualNodeSets` — incorrect equality on OOM
9. **LOW** — `xmlXPathFormatNumber` uses `snprintf` which produces locale-dependent decimal separators — garbled XPath number output in non-C locales (e.g., `de_DE` uses comma)

### Areas Confirmed Safe
- Value stack: `xmlGrowCapacity` + `XPATH_MAX_STACK_DEPTH` (1M limit)
- Node-set growth: `xmlGrowCapacity` + `XPATH_MAX_NODESET_LENGTH` (10M limit)
- Compiled step array: `xmlGrowCapacity` + `XPATH_MAX_STEPS` (1M limit)
- Recursion depth: Bounded in both compiler and evaluator by `XPATH_MAX_RECURSION_DEPTH`
- Operation count: `xmlXPathCheckOpLimit` throughout traversal and evaluation
- Object caching: Bounded by `maxNodeset`/`maxMisc`, no UAF from cache
- Number formatting: `snprintf` with proper buffer sizes
- String functions: All handle NaN, overflow, and boundary cases correctly
- Axis traversal: Iterative, `OP_LIMIT_EXCEEDED` checked per iteration

See `libxml2-audit/xpath_audit.md` for full details.

## Phase 5: libarchive Audit

### Overview
libarchive is shipped by Apple as part of macOS and iOS. It processes untrusted archive
formats (RAR, ZIP, 7-Zip, tar, etc.). The RAR format parsers have had the highest CVE
density (CVE-2024-20696, CVE-2024-20697, CVE-2024-26256, CVE-2024-48957, CVE-2024-48958,
CVE-2025-5914, CVE-2025-25724, and more). libarchive is ~125K lines of C.

### Files Audited

| File | Lines | Focus Areas | Issues Found |
|---|---|---|---|
| `archive_read_support_format_rar.c` | 3,918 | RAR v4: LZSS, PPMd, filter VM, header parsing | 2 medium + 5 low |
| `archive_read_support_format_rar5.c` | 4,411 | RAR v5: decompression, filters, solid streams, header parsing | 2 high + 6 medium + 2 low |
| `archive_read_support_format_zip.c` | 4,412 | ZIP: central directory, local headers, encryption, decompression | 2 high + 1 medium + 2 low |
| `archive_read_support_format_7zip.c` | 4,532 | 7-Zip: header parsing, SFX detection, coder chains | 1 high + 4 medium |

### Highest-Priority Findings

1. **HIGH** — 7-Zip: `kArchiveProperties` data never consumed → header parser desync → potential memory corruption via controlled allocation sizes
2. **HIGH** — RAR v5: Missing NULL checks after `calloc` in `init_unpack` → crash on OOM
3. **HIGH** — RAR v5: Signed truncation of `unpacked_size` on 32-bit → unbounded decompression
4. **HIGH** — ZIP: Unchecked error return in `zip_read_mac_metadata` → read position corruption
5. **HIGH** — ZIP: Encryption flags switch/case never matches (logic bug — `& 0xf000` masks used with case values `0x0001-0x0003`)
6. **MEDIUM** — RAR v4: NULL pointer deref in `read_exttime` — `localtime()` return unchecked
7. **MEDIUM** — RAR v4: `staticdatalen` integer overflow in `compile_program` → multi-GB allocation DoS
8. **MEDIUM** — RAR v5: Multiple signed truncation issues on 32-bit (bytes_remaining, read_var_sized, block_start)
9. **MEDIUM** — 7-Zip: `numDigests` uint32_t overflow → heap overflow via small allocation
10. **MEDIUM** — 7-Zip: Directory entry name heap OOB write (2-byte overflow)

See `libxml2-audit/libarchive_rar_audit.md`, `libarchive_rar5_audit.md`, and `libarchive_zip_7zip_audit.md` for full details.

## ANGLE Metal Backend — Reconnaissance

ANGLE is WebKit's bundled graphics translation layer for WebGL. The Metal backend
(~50K lines) runs in the GPU process on macOS/iOS. Three exploited zero-days in 2025:
- CVE-2025-14174: OOB memory access via pixelsDepthPitch sizing (exploited ITW)
- CVE-2025-9478: Use-after-free (found by AI agent "Big Sleep")
- CVE-2025-6558: Sandbox escape via input validation failure

Key audit targets identified: `ContextMtl.mm`, `TextureMtl.mm`, `BufferMtl.mm`,
`TransformFeedbackMtl.mm`. Standalone clone: `git clone https://github.com/google/angle`.

See `libxml2-audit/angle_recon.md` for full reconnaissance report.

## Phase 6: ANGLE Metal Backend Full Audit

### Overview
Full source code audit of the ANGLE Metal backend (~25,000+ lines across 30+ files) plus the
MSL shader compiler (~10,000+ lines, 38 files). Source retrieved via Chromium source viewer
from `chromium.googlesource.com/angle/angle` HEAD of main branch.

### Files Audited

| Component | Key Files | Lines |
|-----------|----------|-------|
| **Texture (P0)** | TextureMtl.mm, TextureMtl.h, mtl_resources.h | ~3,300 |
| **Context (P0)** | ContextMtl.mm, ContextMtl.h | ~3,000 |
| **Buffer (P0)** | BufferMtl.mm, mtl_buffer_pool.*, mtl_buffer_manager.* | ~2,500 |
| **XFB (P1)** | TransformFeedbackMtl.*, ProvokingVertexHelper.*, rewrite_indices.metal | ~850 |
| **Infra (P1)** | mtl_command_buffer.*, mtl_resources.*, mtl_state_cache.* | ~6,900 |
| **MSL Compiler (P1)** | src/compiler/translator/msl/ (38 files) | ~10,000+ |
| **Utils (P2)** | mtl_render_utils.*, mtl_format_utils.*, VertexArrayMtl.* | ~5,600 |
| **FBO (P2)** | FrameBufferMtl.*, IOSurfaceSurfaceMtl.*, RenderTargetMtl.* | ~2,500 |

### Finding Summary

| Severity | Count |
|----------|-------|
| HIGH | 11 |
| MEDIUM | 34 |
| LOW | 32 |
| **Total** | **77** |

### Highest-Priority Findings (HIGH)

1. **TextureMtl: CopyTextureData lacks source/dest bounds validation** — Exact CVE-2025-14174 pattern.
   `pixelsDepthPitch` from GL unpack params controls source pointer arithmetic without bounds checking.
   Reachable from WebGL via `pixelStorei` + 3D texture upload.

2. **MSL Compiler: Stack overflow via deep AST recursion** — `GenMetalTraverser` has no recursion
   depth limit. Crafted GLSL shader with thousands of nested expressions blows the call stack.
   Reachable from WebGL `compileShader()`.

3. **VertexArrayMtl: Integer overflow in vertex buffer GPU conversion** — GPU compute shader uses
   `uint32_t` offsets that overflow when `vertexCount * dstStride` exceeds 32 bits.

4. **mtl_render_utils: Integer overflow in triangle fan index generation** — `(count-2)*3` overflows
   `uint32_t`, causing undersized allocation followed by heap buffer overflow.

5. **BufferPool: uint32_t truncation of allocation offset** — `mNextAllocationOffset` wraps at 4GB,
   causing allocation overlap and data aliasing.

6. **mtl_resources: Race condition in multi-context CPU/GPU access** — Non-atomic check-then-act
   with developer-flagged TODO comment.

7. **MSL Compiler: Debug env var allows arbitrary shader injection** — `GMD_FIXED_EMIT` environment
   variable bypasses all shader compilation, reading arbitrary files as shader output.

8. **TextureMtl: Integer overflow in staging buffer size (32-bit)** — `size_t` overflow on 32-bit
   platforms produces undersized allocation for subsequent massive `memcpy`.

9. **ContextMtl: Null return from getRenderPassCommandEncoder** — Immediate dereference without null
   check in XFB render pass setup.

10. **TextureMtl: pixelsDepthPitch mismatch in staging buffer reads** — Source data read using
    `pixelsDepthPitch` which can be smaller than actual image stride.

### Systemic Issues

1. **`#pragma allow_unsafe_buffers`** — Every `.mm` file disables Chromium's buffer safety analysis
2. **ASSERT-only validation** — Critical safety checks stripped in release builds
3. **Pervasive uint32_t truncation** — size_t to uint32_t casts throughout Metal encoder paths

### CVE Pattern Analysis

| CVE | Pattern | Current Status |
|-----|---------|----------------|
| CVE-2025-14174 | pixelsDepthPitch sizing | Core pattern still in `CopyTextureData` — relies on frontend validation |
| CVE-2022-26717 | XFB buffer UAF | Fixed (ref-counting). Dormant `#if 0` code would reintroduce if re-enabled |
| CVE-2025-9478 | Buffer management UAF | shared_ptr mitigates; timing issues remain |
| CVE-2025-10502 | Heap buffer overflow | Integer overflow patterns could produce similar bugs |

See `libxml2-audit/angle_metal_audit.md` for the full audit report with detailed findings.

## Recent Security Fixes (Context)
- `538b2e3` (2026-02-20): Integer overflow in `xmlBuildRelativeURISafe` — `int` variables for path indices
- `e334a9d` (2026-02-19): `int` to `size_t` fix in `xmlIO.c` buffer reallocation
- `5dfd906`: Use-after-free mitigation in RelaxNG (not WebKit-reachable)
- `3590835`: Entity hash table fix
- `19549c6`: RelaxNG include limit (not WebKit-reachable)
