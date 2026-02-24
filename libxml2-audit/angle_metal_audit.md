# ANGLE Metal Backend — Defensive Security Audit Report

**Date:** 2026-02-24
**Target:** ANGLE Metal backend (HEAD of `main` branch, `chromium.googlesource.com/angle/angle`)
**Focus:** Memory corruption vulnerabilities reachable from WebGL/WebKit
**Methodology:** Manual source code review of ~25,000+ lines across 30+ files

---

## Executive Summary

This audit examined the ANGLE Metal backend — the graphics translation layer used by Chrome and Safari
to implement WebGL on Apple platforms. The Metal backend translates OpenGL ES API calls to Apple's
Metal graphics API. It runs in the GPU process, making vulnerabilities here high-value targets for
sandbox escape chains.

**Scope:** All P0/P1/P2 files in `src/libANGLE/renderer/metal/` plus the MSL shader compiler
(`src/compiler/translator/msl/`).

### Finding Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **HIGH** | 10 | Memory corruption, OOB access, stack overflow |
| **MEDIUM** | 25 | Integer overflow, truncation, state inconsistency |
| **LOW** | 27 | Missing validation, code quality, DoS |
| **INFO** | 3 | Debug code, pragmas |
| **Total** | **65** | |

### Top 5 Most Exploitable Findings

1. **TextureMtl: CopyTextureData has no bounds validation on source/dest** — The exact CVE-2025-14174 pattern. `pixelsDepthPitch` from GL unpack parameters controls source pointer arithmetic without bounds checking. Directly reachable from WebGL via `pixelStorei` + 3D texture upload. (HIGH)

2. **MSL Compiler: Stack overflow via deep AST recursion** — `GenMetalTraverser` has no recursion depth limit. A crafted GLSL shader with thousands of nested expressions blows the call stack during MSL emission. Directly reachable from `compileShader()`. (HIGH)

3. **VertexArrayMtl: Integer overflow in vertex buffer conversion** — GPU compute shader uses `uint32_t` offsets that can overflow when `vertexCount * dstStride` exceeds 32 bits. Reachable via vertex format conversion triggered by `drawElements`. (HIGH)

4. **mtl_render_utils: Integer overflow in triangle fan index generation** — Destination buffer sized with 32-bit arithmetic that can wrap for large `count` values. Heap buffer overflow via `drawElements(GL_TRIANGLE_FAN, largeCount, ...)`. (HIGH)

5. **BufferMtl: uint32_t truncation of allocation offset in BufferPool** — `mNextAllocationOffset` is `uint32_t` but `mSize` is `size_t`. Pools exceeding 4GB cause offset wraparound and data aliasing between allocations. (HIGH)

---

## Files Audited

### P0 — Critical Attack Surface

| File | Lines | Findings |
|------|-------|----------|
| `TextureMtl.mm` / `.h` | ~3,300 | 3 HIGH, 5 MEDIUM, 1 LOW |
| `ContextMtl.mm` / `.h` | ~3,000 | 1 HIGH, 4 MEDIUM, 4 LOW |
| `BufferMtl.mm` / `.h` + `mtl_buffer_pool.*` + `mtl_buffer_manager.*` | ~2,500 | 1 HIGH, 5 MEDIUM, 5 LOW |

### P1 — High-Priority

| File | Lines | Findings |
|------|-------|----------|
| `TransformFeedbackMtl.mm` / `.h` + `ProvokingVertexHelper.*` | ~500 | 0 HIGH, 2 MEDIUM, 5 LOW |
| `mtl_command_buffer.*` + `mtl_resources.*` + `mtl_state_cache.*` | ~6,900 | 1 HIGH, 3 MEDIUM, 4 LOW |
| MSL Compiler (`src/compiler/translator/msl/`, 38 files) | ~10,000+ | 2 HIGH, 4 MEDIUM, 4 LOW |

### P2 — Secondary

| File | Lines | Findings |
|------|-------|----------|
| `mtl_render_utils.*` + `mtl_format_utils.*` + `VertexArrayMtl.*` | ~5,600 | 2 HIGH, 4 MEDIUM, 4 LOW |
| `FrameBufferMtl.*` + `IOSurfaceSurfaceMtl.*` + `RenderTargetMtl.*` | ~2,500 | (pending) |

---

## HIGH Severity Findings

### H1: CopyTextureData — No Source/Destination Bounds Validation (CVE-2025-14174 Pattern)

**File:** `TextureMtl.mm`, `CopyTextureData()` (lines 187-207)
**WebGL Reachable:** Yes

```cpp
void CopyTextureData(const MTLSize &regionSize, size_t srcRowPitch, size_t src2DImageSize,
                     const uint8_t *psrc, size_t destRowPitch, size_t dest2DImageSize, uint8_t *pdst)
{
    size_t rowCopySize = std::min(srcRowPitch, destRowPitch);
    for (NSUInteger d = 0; d < regionSize.depth; ++d) {
        for (NSUInteger r = 0; r < regionSize.height; ++r) {
            const uint8_t *pCopySrc = psrc + d * src2DImageSize + r * srcRowPitch;
            uint8_t *pCopyDst       = pdst + d * dest2DImageSize + r * destRowPitch;
            memcpy(pCopyDst, pCopySrc, rowCopySize);
        }
    }
}
```

Raw pointer arithmetic with no bounds checking on either source or destination. `src2DImageSize`
(derived from `GL_UNPACK_IMAGE_HEIGHT` via `pixelsDepthPitch`) controls source offsets. If
`GL_UNPACK_IMAGE_HEIGHT < area.height`, `src2DImageSize` is smaller than the actual 2D image
stride, causing subsequent depth slices to read from wrong memory. This is the exact mechanism
exploited by CVE-2025-14174 (in-the-wild exploit, CISA KEV).

The `std::min(srcRowPitch, destRowPitch)` for `rowCopySize` is a partial mitigation that prevents
per-row overflows, but depth/height iteration using potentially wrong pitches remains dangerous.

### H2: CVE-2025-14174 Pattern — pixelsDepthPitch Mismatch in Staging Buffer Reads

**File:** `TextureMtl.mm`, `CopyTextureContentsToStagingBuffer()` → `CopyTextureData()`
**WebGL Reachable:** Yes (if frontend validation is insufficient)

The staging buffer is correctly sized using actual region dimensions. But the source data is read
using `pixelsDepthPitch` (from `GL_UNPACK_IMAGE_HEIGHT`), which can be smaller. When uploading a
3D texture with `depth > 1`, source pointer arithmetic with the smaller pitch reads overlapping
or out-of-bounds data. With PBOs (unpack buffers), this could read from GPU-accessible buffer memory.

### H3: Integer Overflow in Staging Buffer Size Calculations (32-bit targets)

**File:** `TextureMtl.mm`, `CopyTextureContentsToStagingBuffer()` (lines 327-329)
**WebGL Reachable:** Yes (32-bit iOS devices)

```cpp
size_t stagingBufferRowPitch    = regionSize.width * textureAngleFormat.pixelBytes;
size_t stagingBuffer2DImageSize = stagingBufferRowPitch * regionSize.height;
size_t stagingBufferSize        = stagingBuffer2DImageSize * regionSize.depth;
```

On 32-bit platforms, `size_t` is 32-bit. `width=65536 × height=65536 × pixelBytes=4` overflows,
allocating a tiny buffer. Subsequent `memcpy` loop writes massively out of bounds.

### H4: Unchecked Null Return from getRenderPassCommandEncoder

**File:** `ContextMtl.mm`, `handleDirtyRenderPass()` (lines 2700-2704)
**WebGL Reachable:** Low probability currently

```cpp
mtl::RenderCommandEncoder *encoder = getTextureRenderCommandEncoder(...);
encoder->setColorLoadAction(MTLLoadActionDontCare, MTLClearColor(), 0);  // NULL deref if encoder==nullptr
```

`getTextureRenderCommandEncoder` can return `nullptr` when render target size exceeds device maximum.
The immediate dereference without null check is a crash.

### H5: uint32_t Truncation of BufferPool Allocation Offset

**File:** `mtl_buffer_pool.mm`, `BufferPool::allocate()` (line ~240)
**WebGL Reachable:** Low (requires large unified memory)

`mNextAllocationOffset` is `uint32_t` but `sizeToAllocate` is `size_t`. Assignment
`mNextAllocationOffset += static_cast<uint32_t>(sizeToAllocate)` silently truncates. Pools
exceeding 4GB cause offset wraparound, making subsequent allocations overlap earlier ones.

### H6: Race Condition in Texture/Buffer CPU Access with Multi-Context Usage

**File:** `mtl_resources.mm`, `Texture::replaceRegion()` / `Buffer::mapWithOpt()`
**WebGL Reachable:** Via OffscreenCanvas + shared resources

Non-atomic check-then-act for CPU/GPU synchronization. Developer flagged concern with comment:
`"NOTE(hqle): what if multiple contexts on multiple threads are using this texture?"` Between
flush and wait, another thread could submit new GPU work using the same resource.

### H7: Stack Overflow via Deep AST Recursion in MSL Emitter

**File:** `EmitMetal.cpp`, `GenMetalTraverser::groupedTraverse()` (line 802)
**WebGL Reachable:** Directly via `compileShader()`

```cpp
void GenMetalTraverser::groupedTraverse(TIntermNode &node) {
    node.traverse(this);  // RECURSIVE — no depth guard
}
```

No recursion depth limit. Deeply nested GLSL expressions (thousands of nested ternary operators)
blow the call stack during MSL emission. The GLSL frontend parser has some nesting limits, but
AST rewriting passes (RewritePipelines) can deepen the tree further.

### H8: Debug Environment Variable Allows Arbitrary Shader Injection

**File:** `EmitMetal.cpp`, `sh::EmitMetal()` (lines 2736-2773)
**WebGL Reachable:** If attacker can set environment variables

If `GMD_FIXED_EMIT` environment variable is set, the entire MSL emission is replaced by reading
an arbitrary file from disk. The content is output as the compiled shader, bypassing all safety
checks. The injected shader code runs on the GPU. In sandboxed Chromium this is mitigated; in
WebKit the sandboxing model may not prevent this.

### H9: Integer Overflow in Triangle Fan Index Buffer Generation

**File:** `mtl_render_utils.mm`, `GenTriFanFromClientElements` (lines 300-384)
**WebGL Reachable:** Yes, via `drawElements(GL_TRIANGLE_FAN, ...)`

`(count - 2) * 3` can overflow `uint32_t` for large counts. `indicesGenerated` is `uint32_t`
and `dstTriangle * 3` can overflow. Destination buffer allocation may use 32-bit arithmetic that
wraps, allocating a tiny buffer for subsequent large writes.

### H10: Integer Overflow in Vertex Buffer Conversion Size

**File:** `VertexArrayMtl.mm`, `convertVertexBufferGPU` (lines 1085-1086)
**WebGL Reachable:** Yes, via vertex format conversion

GPU compute shader uses `uint32_t` offsets. `vertexCount * dstStride` is validated individually
but their product is not checked against `uint32_t` limits. The shader computes
`vertex_id * dstStride + dstBufferStartOffset` which can overflow 32 bits, writing to incorrect
buffer offsets.

---

## MEDIUM Severity Findings (Summary)

| # | File | Finding |
|---|------|---------|
| M1 | ContextMtl.mm | Dormant CVE-2022-26717 UAF in `#if 0` transform feedback block |
| M2 | ContextMtl.mm | LineLoopLastSegmentHelper destructor draws with null encoder in release |
| M3 | ContextMtl.mm | Integer overflow in line loop index count (`count + 1`, `count * 2`) |
| M4 | ContextMtl.mm | Stale `mDrawFramebuffer` raw pointer, no null check |
| M5 | ContextMtl.mm | setupDraw retry with complex dirty bit state could leak state |
| M6 | BufferMtl.mm | Missing bounds validation in `copySubData` blit path |
| M7 | BufferMtl.mm | Unsynchronized CPU/GPU access with `GL_MAP_UNSYNCHRONIZED_BIT` |
| M8 | BufferMtl.mm | Old buffer return timing in `putDataInNewBufferAndStartUsingNewBuffer` |
| M9 | BufferMtl.mm | Raw pointer from `getBufferDataReadOnly` without lifetime tracking |
| M10 | BufferMtl.mm | `size_t` to `uint32_t` truncation in `updateAlignment` |
| M11 | TextureMtl.mm | Integer overflow in `generateMipmapCPU` buffer allocation |
| M12 | TextureMtl.mm | Hardcoded block size 16 in compressed texture upload |
| M13 | TextureMtl.mm | `uint32_t` truncation of `size_t` pitch values in shader params |
| M14 | TextureMtl.mm | `int` type for row pitch in `copySubTextureCPU` |
| M15 | TextureMtl.mm | Row-by-row conversion uses user-controlled depth pitch |
| M16 | TransformFeedbackMtl.mm | Integer overflow in XFB offset calculation (truncation to int32_t) |
| M17 | ProvokingVertexHelper.mm | `uint32_t` truncation of `size_t` offsets |
| M18 | mtl_state_cache.mm | memcmp/memset on bitfield-packed descriptors — hash collisions / cache DoS |
| M19 | mtl_command_buffer.mm | IntermediateCommandStream type-unsafe deserialization (ASSERT-only bounds) |
| M20 | mtl_command_buffer.mm | Resource release after commit creates window for stale references |
| M21 | mtl_state_cache.h | RenderPassAttachmentDesc holds strong TextureRef that can outlive texture validity |
| M22 | mtl_render_utils.mm | Integer overflow in stencil blit intermediate buffer (uint32_t) |
| M23 | VertexArrayMtl.mm | Signed/unsigned mismatch in GetVertexCountWithConversion |
| M24 | VertexArrayMtl.mm | Buffer offset truncation to uint32_t in setupDraw |
| M25 | mtl_render_utils.mm | GPU shader reads with unvalidated stride/offset (OOB reads) |
| M26 | EmitMetal.cpp | Integer overflow in Layout size calculations |
| M27 | EmitMetal.cpp | Unvalidated array index in getDirectField() (ASSERT-only) |
| M28 | Pipeline.cpp | Missing switch default cases — uninitialized variables |
| M29 | RewritePipelines.cpp | Resource exhaustion via pipeline struct proliferation |
| M30 | EmitMetal.cpp | Unbounded output string growth in TInfoSinkBase |

---

## Systemic Issues

### 1. `#pragma allow_unsafe_buffers` Everywhere

Every single `.mm` implementation file in the Metal backend contains:
```cpp
#ifdef UNSAFE_BUFFERS_BUILD
#    pragma allow_unsafe_buffers
#endif
```

This disables Chromium's buffer safety analysis for the entire file. Given that these files handle
attacker-controlled data from WebGL, this is a significant defense-in-depth gap.

### 2. ASSERT-Only Validation Pattern

Throughout the codebase, critical safety checks (null pointer guards, bounds checks, invariant
validation) use `ASSERT()` which is stripped in release builds. Examples:
- `ASSERT(encoder)` before encoder dereference (ContextMtl.mm)
- `ASSERT(buffer != nullptr)` before buffer dereference (ProgramExecutableMtl.mm)
- `ASSERT(mReadPtr <= mBuffer.size() - sizeof(T))` in command stream deserializer
- `ASSERT(sampleBitCount < 32)` before shift operation

These should be `ANGLE_CHECK` or `ANGLE_CHECK_GL_*` macros that return errors in release builds.

### 3. Pervasive uint32_t Truncation of size_t

Multiple code paths truncate 64-bit `size_t` values to 32-bit `uint32_t` via `static_cast`:
- Buffer pool allocation offsets
- Metal encoder buffer/offset parameters
- Compute shader uniform parameters (stride, offset, count)
- Provoking vertex helper offsets

On 64-bit platforms with large memory, these truncations can silently corrupt address calculations.

---

## Well-Defended Areas

1. **shared_ptr (BufferRef/TextureRef):** Buffer and texture lifecycle uses `std::shared_ptr`,
   providing strong protection against classical use-after-free.

2. **ANGLE_TRY error propagation:** Consistent use of `ANGLE_TRY` macro throughout the codebase
   ensures failures in sub-operations cause early returns.

3. **Transform feedback ref-counting:** `OffsetBindingPointer<Buffer>` properly ref-counts all
   XFB buffer bindings, preventing the exact CVE-2022-26717 pattern.

4. **Array bounds clamping (ANGLE_int_clamp):** The MSL emitter wraps all dynamic array indices
   in `ANGLE_int_clamp()`, preventing OOB GPU memory access in generated Metal shaders.

5. **Serial-based resource tracking:** The queue serial system provides sound tracking of resource
   usage across committed and pending command buffers.

6. **Scissor rect clamping:** Metal encoder clamps scissor rects to render pass dimensions.

7. **Encoder index bounds checking:** All `setBuffer`/`setTexture`/`setSamplerState` methods
   check indices against `kMaxShaderBuffers`/`kMaxShaderSamplers`.

8. **Frontend validation layer:** ANGLE's GL validation layer catches many attack vectors before
   they reach the Metal backend.

---

## Comparison with Known CVE Patterns

| CVE | Pattern | Still Present? |
|-----|---------|----------------|
| CVE-2025-14174 | pixelsDepthPitch sizing mismatch in texture upload | Core pattern (H1/H2) still present in `CopyTextureData` — relies on frontend validation |
| CVE-2022-26717 | UAF in XFB buffer binding | Fixed — ref-counting + frontend validation prevents it. Dormant `#if 0` code (M1) would reintroduce it if re-enabled |
| CVE-2025-9478 | UAF in buffer management | BufferRef (shared_ptr) mitigates this class; timing-dependent issues remain (H6, M7) |
| CVE-2025-10502 | Heap buffer overflow | Integer overflow patterns (H3, H9, H10) could lead to similar bugs |
| CVE-2025-6558 | Input validation failure | ASSERT-only validation (systemic issue #2) leaves gaps in release builds |

---

## Recommendations

### Critical (should fix before next release)

1. **Add bounds validation to `CopyTextureData` and `ConvertDepthStencilData`** — Validate that
   `(depth-1) * src2DImageSize + (height-1) * srcRowPitch + rowCopySize` does not exceed source
   buffer size. Same for destination.

2. **Add recursion depth limit to GenMetalTraverser** — Increment/decrement a depth counter in
   visitor methods, return error at configurable max (256-512).

3. **Use checked arithmetic for all buffer size calculations** — Replace bare multiplication with
   `base::CheckedNumeric` or `__builtin_mul_overflow` in staging buffer allocation, triangle fan
   index generation, and vertex conversion.

4. **Change `mNextAllocationOffset` from `uint32_t` to `size_t`** in `mtl_buffer_pool.h`.

### High Priority

5. **Replace ASSERT-only safety checks with runtime checks** in security-critical paths (null
   pointer guards before dereference, bounds checks on command stream reads).

6. **Guard or remove `GMD_FIXED_EMIT` debug path** behind compile-time `#ifdef NDEBUG`.

7. **Validate `srcBufferStartOffset + (vertexCount-1) * srcStride + srcFormatSize <= srcBuffer->size()`**
   before dispatching GPU vertex conversion.

### Medium Priority

8. **Add null check after `getRenderPassCommandEncoder`** in `handleDirtyRenderPass`.
9. **Refactor LineLoopLastSegmentHelper** to not issue draws from destructor.
10. **Tag dormant CVE-2022-26717 code** (`#if 0` block) with comment requiring null check if re-enabled.
11. **Incrementally remove `#pragma allow_unsafe_buffers`** from security-critical files.
