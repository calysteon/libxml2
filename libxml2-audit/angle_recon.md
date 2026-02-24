# ANGLE Metal Backend — Reconnaissance Report

**Date:** 2026-02-24
**Purpose:** Map attack surface for future defensive security audit

---

## Overview

ANGLE (Almost Native Graphics Layer Engine) is an open-source graphics translation
layer used by both Chrome and WebKit/Safari to implement WebGL. It translates
OpenGL ES API calls to platform-native APIs (Metal on macOS/iOS, Vulkan, D3D, etc.).

- **Upstream:** `https://chromium.googlesource.com/angle/angle`
- **GitHub mirror:** `https://github.com/google/angle` (Apache 2.0)
- **WebKit copy:** `Source/ThirdParty/ANGLE/` in the WebKit tree
- **Cloneable standalone:** Yes

---

## Metal Backend Structure

**Path:** `src/libANGLE/renderer/metal/`
**Estimated size:** ~40,000–55,000 lines (35 .mm/.cpp files + 37 headers)

### Key Files (Priority Order for Audit)

| Priority | File | Why |
|----------|------|-----|
| **P0** | `ContextMtl.mm` | CVE-2022-26717 was here (transform feedback UAF). Main state machine, dirty-bit handling |
| **P0** | `TextureMtl.mm` | CVE-2025-14174 was here (OOB via pixelsDepthPitch sizing). Texture upload/unpack |
| **P0** | `BufferMtl.mm` | Buffer lifecycle management — UAF patterns |
| **P1** | `TransformFeedbackMtl.mm` | Transform feedback emulation — known exploit vector |
| **P1** | `mtl_buffer_manager.mm` | Buffer allocation strategy |
| **P1** | `mtl_buffer_pool.mm` | Buffer pooling — object reuse after free |
| **P1** | `mtl_resources.mm` | MTLTexture/MTLBuffer wrappers — lifecycle |
| **P1** | `mtl_command_buffer.mm` | Command encoder management |
| **P2** | `FrameBufferMtl.mm` | Framebuffer object handling |
| **P2** | `ProvokingVertexHelper.mm` | Index buffer rewriting on-the-fly |
| **P2** | `IOSurfaceSurfaceMtl.mm` | Cross-framework surface sharing |

### Shader Compiler (Separate Attack Surface)

**Path:** `src/compiler/translator/msl/` (~20 files)

Processes untrusted GLSL ES shaders from web content. Translates to MSL (Metal Shading
Language). Chromium runs this in its own sandboxed process, reducing severity. Key files:
`TranslatorMSL.cpp`, `EmitMetal.cpp`, `Pipeline.cpp`.

---

## Historical Vulnerability Patterns

| Category | CVE Examples | Description |
|----------|-------------|-------------|
| **OOB Memory Access** | CVE-2025-14174 (exploited ITW) | Buffer sizing errors, incorrect pitch calculations |
| **Use-After-Free** | CVE-2022-26717, CVE-2025-9478 | Object lifetime errors in buffer/resource management |
| **Heap Buffer Overflow** | CVE-2025-10502 | Insufficient bounds checking on graphics data |
| **Input Validation** | CVE-2025-6558 | Untrusted shader/API parameter validation failures |

### CVE-2025-14174 (Exploited In-The-Wild)

Root cause: `pixelsDepthPitch` (based on `GL_UNPACK_IMAGE_HEIGHT`, which can be smaller
than actual image height) was used to size Metal staging buffers, causing a buffer overflow
during texture upload. Found by Apple SEAR + Google TAG. Added to CISA KEV catalog.

### CVE-2022-26717 (Safari/WebKit)

Root cause: In `ContextMtl::handleDirtyGraphicsTransformFeedbackBuffersEmulation()`,
a `BufferMtl` object was retrieved from buffer handles without checking if the underlying
buffer had been freed. Exploitable via WebGL2 Transform Feedback binding → delete → draw
sequence. Full exploitation achieved heap spray + arbitrary read/write.

---

## Bounty Impact

- WebContent code execution via ANGLE: **$10,000+**
- ANGLE → GPU process sandbox escape: **$300,000+**
- Full chain (WebContent → kernel): **$1,000,000+**

---

## Audit Feasibility Assessment

| Factor | Assessment |
|--------|-----------|
| **Codebase size** | ~50K lines Metal backend — manageable for focused audit |
| **Language** | Objective-C++ (.mm) — more complex than C, but readable |
| **Build requirements** | Needs `depot_tools` (GN + Ninja + gclient) |
| **Fuzzing coverage** | Extensively fuzzed by Google's ClusterFuzz, but Metal-specific paths may have gaps |
| **Competition** | Actively targeted by Google Project Zero, Apple SEAR, Theori |
| **Freshness of bugs** | 3 exploited zero-days in 2025 — bugs are still being found |

### Recommended Approach

1. Clone standalone ANGLE from `google/angle`
2. Focus on Metal backend (`src/libANGLE/renderer/metal/`)
3. Start with `TextureMtl.mm` (CVE-2025-14174 pattern — buffer sizing)
4. Then `ContextMtl.mm` dirty-bit state handling
5. Then buffer lifecycle (`BufferMtl.mm`, `mtl_buffer_pool.mm`)
6. Shader compiler MSL output as secondary target
