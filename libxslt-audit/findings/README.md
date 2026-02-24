# libxslt Security Audit Findings

**Audit Date**: 2026-02-24
**Target**: libxslt (latest main branch, commit at time of audit)
**Focus**: WebKit-reachable code paths via XSLT processing
**Methodology**: Manual code audit + ASan/UBSan testing

## Executive Summary

Four code defects were identified. **None are directly exploitable from WebKit**
because (a) the type confusion variant requires OOM to trigger, and (b) WebKit
does not register EXSLT extension functions. However, all are real code defects
that should be fixed for non-WebKit consumers.

The core XSLT transformation engine has been significantly hardened by the
recent CVE fixes (CVE-2025-24855, CVE-2024-55549, CVE-2025-7424). The XPath
context node save/restore pattern and psvi type confusion are now correctly
handled in all main code paths.

## Finding 1: Type Confusion Variant of CVE-2025-7424

**File**: `libxslt/functions.c:339-344`
**Severity**: Medium-Low (requires OOM to trigger)
**WebKit Impact**: Not exploitable (requires xmlBuildURI to fail)

### Description

CVE-2025-7424 fixed `xsltDocumentFunctionLoadDocument()` to copy the
stylesheet doc and clean `psvi` fields when `document()` returns the
stylesheet itself. However, there is a **separate code path** in
`xsltDocumentFunction()` that was not patched:

```c
// functions.c:339-344
URI = xmlBuildURI(url, base);
if (URI == NULL) {
    if ((tctxt != NULL) && (tctxt->style != NULL) &&
        (tctxt->style->doc != NULL) &&
        (xmlStrEqual(URI, tctxt->style->doc->URL))) {
        /* This selects the stylesheet's doc itself. */
        valuePush(ctxt, xmlXPathNewNodeSet((xmlNodePtr) tctxt->style->doc));
        //        ^^^ RAW stylesheet doc, psvi NOT cleaned!
```

When `xmlBuildURI` returns NULL (OOM or edge case) AND `style->doc->URL`
is also NULL (stylesheet parsed from memory), `xmlStrEqual(NULL, NULL)`
returns 1, and the raw stylesheet doc is pushed with `psvi` fields intact.

### Triggering Conditions

1. `xmlBuildURI(url, base)` returns NULL — typically requires OOM
2. `tctxt->style->doc->URL == NULL` — stylesheet parsed from memory
3. `xmlStrEqual(NULL, NULL)` returns 1

### Recommended Fix

Either remove this dead code path (the same case is properly handled in
`xsltDocumentFunctionLoadDocument` at line 121-142), or apply the same
`xmlCopyDoc` + `xsltCleanupSourceDoc` treatment:

```c
if (URI == NULL) {
    if (...xmlStrEqual(URI, tctxt->style->doc->URL)...) {
        xmlDocPtr copy = xmlCopyDoc(tctxt->style->doc, 1);
        if (copy != NULL) {
            xsltCleanupSourceDoc(copy);
            xsltDocumentPtr idoc = xsltNewDocument(tctxt, copy);
            if (idoc != NULL)
                valuePush(ctxt, xmlXPathNewNodeSet((xmlNodePtr) copy));
            else
                xmlFreeDoc(copy);
        }
    }
}
```

## Finding 2: Latent Infinite Loop in exsltFormatLong

**File**: `libexslt/date.c:1122-1125`
**Severity**: Low (latent — not triggerable with current 100-byte buffer)
**WebKit Impact**: None (WebKit does not register EXSLT date functions)

### Description

When the output buffer is full (`*cur >= end`), the reverse-copy loop
spins forever because the decrement `--i` is inside the conditional:

```c
while (i > 0) {
    if (*cur < end)
        *(*cur)++ = buf[--i];  // --i ONLY executes when buffer has space
    // When buffer is full: i is never decremented -> infinite loop
}
```

### Why It's Latent

The buffer is 100 bytes (99 usable). The maximum formatted duration
is ~94 characters (with LONG_MAX-sized components), leaving a 5-byte
margin. The bug cannot be triggered with current constants.

### Recommended Fix

```c
while (i > 0) {
    i--;
    if (*cur < end)
        *(*cur)++ = buf[i];
}
```

## Finding 3: Undefined Behavior — Negating LONG_MIN

**File**: `libexslt/date.c:1173-1183`
**Severity**: Low (UB, produces incorrect output for extreme values)
**WebKit Impact**: None (WebKit does not register EXSLT date functions)

### Description

```c
if (days < 0) {
    ...
    days = -days;   // UB if days == LONG_MIN
}
if (months < 0) {
    months = -months;  // UB if months == LONG_MIN
    *cur = '-';
}
```

When `days` or `months` equals `LONG_MIN`, negation overflows (signed
integer overflow is undefined behavior). On typical platforms, the value
stays at LONG_MIN, leading to negative digits being passed to
`exsltFormatLong`, which produces garbage characters in the output.

### Recommended Fix

Add a guard: `if (days == LONG_MIN) days = LONG_MAX; else days = -days;`
(or clamp to safe range).

## Finding 4: Integer Overflow in _exsltDateCastYMToDays

**File**: `libexslt/date.c` (in `_exsltDateCastYMToDays`)
**Severity**: Low (incorrect results for extreme year values)
**WebKit Impact**: None

### Description

`(dt->year - 1) * 365` can overflow `long` for extreme year values
(e.g., years close to LONG_MAX/365). While callers sometimes validate
inputs, the function itself has no overflow protection.

---

## WebKit Attack Surface Summary

Based on WebKit source analysis (XSLTProcessorLibxslt.cpp, XSLStyleSheetLibxslt.cpp,
XSLTExtensions.cpp):

### What WebKit Uses
- **29 libxslt functions** + 25 libxml2 functions
- Parser options: `XML_PARSE_NOENT | XML_PARSE_DTDATTR | XML_PARSE_NOWARNING | XML_PARSE_NOCDATA`
- Security: `xsltSecurityForbid` for write-file, create-dir, write-network
- Custom `docLoaderFunc` enforcing same-origin policy
- `xsltMaxDepth = 1000`
- Dictionary sharing between parent/child stylesheets

### What WebKit Does NOT Use
- **EXSLT modules** (date, math, crypto, strings, sets, dynamic, saxon)
- Only `node-set()` extension function is registered (WebKit's own implementation)
- No external extension loading

### Implication
Findings 2-4 (EXSLT date module) are NOT reachable from WebKit.
Finding 1 requires OOM to trigger, making it impractical from a browser.

## Testing Summary

- Built libxslt with GCC ASan + UBSan (`-fsanitize=address,undefined`)
- Ran 2 test suites (runtest + testThreads) — all passed clean
- Ran 2 custom PoCs (type confusion variant, infinite loop) — both clean
- Manual code audit of ~12,000 lines across 15 source files

## Positive Findings (Hardening)

1. **CVE-2025-24855 fix is thorough**: XPath context node (`xpathCtxt->node`)
   is now properly saved/restored in all 4 identified locations
   (templates.c:73-102, templates.c:143-177, xsltutils.c:1079-1141, numbers.c)
2. **CVE-2025-7424 fix is thorough** (in the main code path): `xsltDocumentFunctionLoadDocument`
   now copies the doc and cleans psvi when returning the stylesheet doc
3. **CVE-2024-55549 fix**: Excluded namespace URIs are now copied into the
   dictionary to prevent dangling pointers
4. **Depth limits**: Template recursion bounded by `xsltMaxDepth` (default 3000,
   WebKit sets 1000), variable count bounded by `xsltMaxVars` (15000)
5. **Operation limit**: `ctxt->opLimit` prevents runaway transformations
