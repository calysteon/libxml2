# Out of Scope Issues

Issues found during audit that are not reachable from WebKit's usage of libxml2.

## 1. libxml2 XPath Engine (xpath.c)

**Why out of scope:** WebKit implements its own XPath engine in `WebCore/xml/XPath*`. libxml2's `xpath.c` is never called from WebKit.

**Note:** xpath.c historically has many bugs (type confusion, stack overflow in compilation, integer overflow in node set operations). These are irrelevant for WebKit since the code is unreachable.

## 2. RelaxNG Validation (relaxng.c)

**Why out of scope:** WebKit never uses RelaxNG validation. No `XML_PARSE_*` flags for RelaxNG are set.

**Recent fix:** Commit `5dfd906` fixed a UAF in RelaxNG, confirming this code still has issues but is not WebKit-reachable.

## 3. XML Schema Validation (xmlschemas.c)

**Why out of scope:** WebKit never uses XML Schema validation.

## 4. DTD Validation (valid.c)

**Why out of scope:** `XML_PARSE_DTDVALID` is never set by WebKit. DTD validation code paths are not reachable.

**Note:** DTD attribute defaulting IS enabled in XSLT context (`XML_PARSE_DTDATTR`), but this only adds default attribute values — it does not enable full DTD validation.

## 5. XPointer (xpointer.c)

**Why out of scope:** Not used by WebKit.

## 6. xmlReader API

**Why out of scope:** WebKit uses push/memory parser, not the reader API.

## 7. SAX1 Mode

**Why out of scope:** WebKit exclusively uses SAX2 (`sax.initialized = XML_SAX2_MAGIC`).

## 8. Old xmlBuffer API Issues

The old `xmlBuffer` API (struct `_xmlBuffer`) uses `unsigned int` for `size` and `use` fields. The bridge functions `xmlBufFromBuffer` and `xmlBufBackToBuffer` handle size truncation by:
- Failing entirely if `buf->use >= INT_MAX`
- Truncating capacity to `INT_MAX` if `buf->size >= INT_MAX`

This is a safe truncation pattern — the new `xmlBuf` API (using `size_t`) is what WebKit's code path uses internally.

## 9. Entity Expansion in Non-WebKit Contexts

When `XML_PARSE_NOENT` is NOT set (which is not how WebKit uses it), entity references are preserved as entity reference nodes. The entity re-expansion happens in `xmlStringGetNodeList` / `xmlNodeParseAttValue`. These code paths have different characteristics but are relevant only when applications re-serialize without entity substitution.
