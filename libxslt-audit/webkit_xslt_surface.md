# WebKit's libxslt Integration Surface Analysis

Analysis of WebKit's XSLT integration with libxslt, based on the following source files
from the WebKit repository (`Source/WebCore/xml/`):

- `XSLTProcessorLibxslt.cpp` (Copyright 2004-2025 Apple Inc., Alexey Proskuryakov)
- `XSLStyleSheetLibxslt.cpp` (Copyright 2004-2025 Apple Inc.)
- `XSLTExtensions.cpp` (Copyright Thomas Broyer, Charlie Bozeman, Daniel Veillard, Alexey Proskuryakov)
- `XSLTUnicodeSort.cpp` (Copyright 2007-2022 Apple Inc.)
- `XSLTExtensions.h`
- `XSLTUnicodeSort.h`
- `XMLDocumentParserScope.h` / `.cpp`

All code is guarded by `#if ENABLE(XSLT)`.

---

## 1. libxslt Functions Called by WebKit

### XSLTProcessorLibxslt.cpp (Transformation Engine)

| Function | Purpose |
|----------|---------|
| `xsltSetLoaderFunc(func)` | Installs custom document loader callback (`docLoaderFunc`) |
| `xsltNewTransformContext(sheet, sourceDoc)` | Creates a new XSLT transform context |
| `xsltNewSecurityPrefs()` | Allocates a new security preferences object |
| `xsltSetSecurityPrefs(prefs, pref, callback)` | Sets individual security preference callbacks |
| `xsltSetCtxtSecurityPrefs(prefs, context)` | Applies security preferences to a transform context |
| `xsltSecurityForbid` | Built-in callback that forbids an operation |
| `xsltSetCtxtSortFunc(context, func)` | Replaces the default sort function with a Unicode-aware one |
| `xsltQuoteUserParams(context, params)` | Passes user-specified XSLT parameters to the transform context |
| `xsltApplyStylesheetUser(sheet, doc, NULL, NULL, NULL, context)` | Executes the XSLT transformation |
| `xsltFreeTransformContext(context)` | Frees the transform context |
| `xsltFreeSecurityPrefs(prefs)` | Frees the security preferences |
| `xsltSaveResultTo(outputBuf, resultDoc, sheet)` | Serializes the transformation result to an output buffer |
| `xsltFreeStylesheet(sheet)` | Frees the compiled stylesheet |
| `XSLT_GET_IMPORT_PTR(resultType, sheet, method)` | Macro to get the output method from the stylesheet import chain |
| `xsltMaxDepth` (global variable) | Read and written: set to 1000 during transformation, then restored |

### XSLStyleSheetLibxslt.cpp (Stylesheet Parsing and Compilation)

| Function | Purpose |
|----------|---------|
| `xsltParseStylesheetDoc(doc)` | Compiles an xmlDoc into an xsltStylesheet (takes ownership of the doc) |
| `xsltLoadStylesheetPI(doc)` | Loads a stylesheet from processing instructions in an embedded document |
| `xsltGetNsProp(node, name, namespace)` | Retrieves an attribute value from an XSLT-namespaced node |
| `XSLT_NAMESPACE` | Constant for the XSLT namespace URI |
| `IS_XSLT_ELEM(node)` | Macro to test if a node is an XSLT element |
| `IS_XSLT_NAME(node, name)` | Macro to test if a node has a specific XSLT local name |

### XSLTExtensions.cpp (Extension Functions)

| Function | Purpose |
|----------|---------|
| `xsltXPathGetTransformContext(ctxt)` | Gets the transform context from an XPath parser context |
| `xsltFunctionNodeSet(ctxt, nargs)` | Default libxslt node-set function (for RTF-to-nodeset conversion) |
| `xsltCreateRVT(tctxt)` | Creates a Result Value Tree (document fragment) |
| `xsltRegisterLocalRVT(tctxt, fragment)` | Registers an RVT for automatic cleanup |
| `xsltTransformError(tctxt, NULL, inst, msg)` | Reports a transformation error |
| `xsltRegisterExtFunction(ctxt, name, ns, func)` | Registers an extension function on a transform context |

### XSLTUnicodeSort.cpp (Unicode-Aware Sorting)

| Function | Purpose |
|----------|---------|
| `xsltEvalAttrValueTemplate(ctxt, node, attr, ns)` | Evaluates an attribute value template |
| `xsltTransformError(ctxt, NULL, node, msg, ...)` | Reports a transformation error |
| `xsltComputeSortResult(ctxt, sort)` | Computes sort keys for an xsl:sort |
| `xmlXPathIsNaN(val)` | Tests if an XPath float is NaN |
| `xmlXPathFreeObject(obj)` | Frees an XPath object |
| `XSLT_MAX_SORT` | Constant for maximum number of sort keys |

---

## 2. XML Parser Options Used When Parsing Stylesheets

In `XSLStyleSheet::parseString()`, stylesheets are parsed with `xmlCtxtReadMemory()` using these options:

```c
XML_PARSE_NOENT | XML_PARSE_DTDATTR | XML_PARSE_NOWARNING | XML_PARSE_NOCDATA
```

| Flag | Value | Effect |
|------|-------|--------|
| `XML_PARSE_NOENT` | Substitute entities | Entity references are expanded during parsing |
| `XML_PARSE_DTDATTR` | Default DTD attributes | Default attribute values from the DTD are applied |
| `XML_PARSE_NOWARNING` | Suppress warnings | Warning messages are suppressed |
| `XML_PARSE_NOCDATA` | Merge CDATA as text | CDATA sections are merged into adjacent text nodes |

**Note:** In `docLoaderFunc()`, when loading documents via `xmlReadMemory()`, the `options` parameter
is passed through from the libxslt caller (the `int options` parameter of the `xsltDocLoaderFunc`
signature). WebKit does NOT set explicit parse options for document loading -- it uses whatever
libxslt passes.

### Stylesheet Parsing Details

- Input is **upconverted to UTF-16** before parsing (using `StringView::upconvertedCharacters()`)
- Encoding is specified as `"UTF-16LE"` or `"UTF-16BE"` based on BOM byte order detection
- A custom `xmlParserCtxt` is created first with `xmlCreateMemoryParserCtxt()`
- For child stylesheets, the parser context's dictionary (`ctxt->dict`) is shared with the parent stylesheet's document dictionary to prevent symbol dictionary corruption

---

## 3. Security Preferences (xsltSecurityPrefs)

WebKit configures a strict security sandbox in `XSLTProcessor::transformToString()`:

```cpp
xsltSecurityPrefsPtr securityPrefs = xsltNewSecurityPrefs();

// Read permissions are checked by docLoaderFunc.
xsltSetSecurityPrefs(securityPrefs, XSLT_SECPREF_WRITE_FILE, xsltSecurityForbid);
xsltSetSecurityPrefs(securityPrefs, XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
xsltSetSecurityPrefs(securityPrefs, XSLT_SECPREF_WRITE_NETWORK, xsltSecurityForbid);
xsltSetCtxtSecurityPrefs(securityPrefs, transformContext);
```

| Security Preference | Setting | Notes |
|---------------------|---------|-------|
| `XSLT_SECPREF_WRITE_FILE` | **Forbidden** (`xsltSecurityForbid`) | No file writes allowed |
| `XSLT_SECPREF_CREATE_DIRECTORY` | **Forbidden** (`xsltSecurityForbid`) | No directory creation allowed |
| `XSLT_SECPREF_WRITE_NETWORK` | **Forbidden** (`xsltSecurityForbid`) | No network writes allowed |
| `XSLT_SECPREF_READ_FILE` | **Not set** (default) | Read access is controlled by `docLoaderFunc` instead |
| `XSLT_SECPREF_READ_NETWORK` | **Not set** (default) | Read access is controlled by `docLoaderFunc` instead |

Each `xsltSetSecurityPrefs()` call is checked for failure -- if any returns non-zero, WebKit calls `CRASH()`.

Read permissions are enforced at a higher level through WebKit's same-origin policy in `docLoaderFunc()`,
which checks `securityOrigin->canRequest(url, OriginAccessPatternsForWebProcess::singleton())`.

---

## 4. Extension Functions Registered

### registerXSLTExtensions() -- called from transformToString()

WebKit registers **one** custom extension function:

```cpp
void registerXSLTExtensions(xsltTransformContextPtr ctxt)
{
    xsltRegisterExtFunction(ctxt,
        (const xmlChar*)"node-set",
        (const xmlChar*)"http://exslt.org/common",
        exsltNodeSetFunction);
}
```

| Function Name | Namespace URI | Implementation |
|---------------|---------------|----------------|
| `node-set` | `http://exslt.org/common` | `WebCore::exsltNodeSetFunction` |

The `exsltNodeSetFunction` implementation:
- Is based on libexslt v1.1.35 code (per the FIXME comment: "should sync with newer versions")
- If the argument is already a node-set, delegates to `xsltFunctionNodeSet()`
- If the argument is a string, creates a Result Value Tree (RVT) with a text node containing the string
- Uses `xsltCreateRVT()` and `xsltRegisterLocalRVT()` for memory management
- On failure, sets `tctxt->state = XSLT_STATE_STOPPED`

### xsltUnicodeSortFunction -- custom sort function

Not an extension function per se, but a custom sort function registered via:

```cpp
xsltSetCtxtSortFunc(transformContext, xsltUnicodeSortFunction);
```

This replaces libxslt's default code-point-only sort with a Unicode collation-aware sort using
WebKit's `WTF::Collator` (which wraps ICU). It supports:
- Multi-level sorting (up to `XSLT_MAX_SORT` levels)
- Both text and number data types
- Ascending and descending order
- Language-aware collation via `comp->lang` (defaults to `"en"`)
- The `lower-first` collation option

---

## 5. EXSLT Usage

WebKit does **NOT** call `exsltRegisterAll()` or use the EXSLT library directly.

Instead, WebKit provides its **own reimplementation** of the EXSLT `node-set` function
(`exsltNodeSetFunction` in `XSLTExtensions.cpp`). This is the only EXSLT function that
WebKit supports.

The includes in `XSLTExtensions.cpp` are:
```cpp
#include <libxslt/extensions.h>
#include <libxslt/extra.h>
#include <libxslt/xsltutils.h>
```

Note: `<libxslt/extra.h>` is included for `xsltFunctionNodeSet()`, not for EXSLT.

**No other EXSLT functions** (e.g., `exslt:math`, `exslt:sets`, `exslt:strings`, `exslt:dates-and-times`,
`exslt:dynamic`, `exslt:regexp`) are registered.

---

## 6. Stylesheet Loading Mechanism

### Custom Document Loader

WebKit installs a custom document loader via `xsltSetLoaderFunc()`:

```cpp
static void setXSLTLoadCallBack(xsltDocLoaderFunc func, XSLTProcessor* processor,
                                 CachedResourceLoader* cachedResourceLoader)
{
    xsltSetLoaderFunc(func);
    globalProcessor = processor;
    globalCachedResourceLoader() = cachedResourceLoader;
}
```

This is a global callback -- the comment says: "There seems to be no way to control the ctxt
pointer for loading here, thus we have globals."

### docLoaderFunc Behavior

The `docLoaderFunc` callback handles two load types:

#### XSLT_LOAD_DOCUMENT (xsl:document / document() function)
1. Resolves the URI relative to the current node's base URI using `xmlNodeGetBase()` and `xmlBuildURI()`
2. Checks same-origin policy: `securityOrigin->canRequest(url, OriginAccessPatternsForWebProcess::singleton())`
3. If allowed, performs a **synchronous** resource load via `frame->loader().loadResourceSynchronously()`
   - Uses `FetchOptions::Mode::SameOrigin`
   - Uses `FetchOptions::Credentials::Include`
   - Uses `ClientCredentialPolicy::MayAskClientForCredentials`
4. After load, re-checks the origin against the response URL (to handle redirects)
5. If denied, calls `cachedResourceLoader->printAccessDeniedMessage(url)`
6. Parses the loaded data with `xmlReadMemory()` -- does NOT specify encoding (comment: "Neither Gecko nor WinIE respects the encoding specified in the HTTP headers")
7. Checks that data size does not exceed `std::numeric_limits<int>::max()`

#### XSLT_LOAD_STYLESHEET (xsl:import / xsl:include)
1. Delegates to `XSLStyleSheet::locateStylesheetSubResource()` which walks the child stylesheet tree
2. Matches URIs by canonicalizing the import href using `xmlBuildURI()` and comparing with `xmlStrEqual()`
3. Marks matched child stylesheets as "processed" so they are not returned again

### Child Stylesheet Loading (XSLStyleSheetLibxslt.cpp)

`loadChildSheets()` walks the stylesheet DOM tree:
1. Finds the root element (skipping non-element nodes like DTD nodes)
2. For embedded stylesheets, locates the element by ID using `xmlGetID()`
3. Processes `xsl:import` elements first (they must come before other children)
4. Then processes `xsl:include` elements
5. Each import/include creates an `XSLImportRule` that triggers async sheet loading
6. The `href` attribute is retrieved using `xsltGetNsProp()` with `XSLT_NAMESPACE`

---

## 7. Error Handlers Installed

### XMLDocumentParserScope (RAII Error Handler Management)

WebKit uses a scoped RAII class to temporarily install error handlers for libxml/libxslt:

```cpp
XMLDocumentParserScope scope(cachedResourceLoader,
    XSLTProcessor::genericErrorFunc,
    XSLTProcessor::parseErrorFunc,
    console);
```

The constructor calls:
- `xmlSetGenericErrorFunc(context, genericErrorFunc)` -- installs the generic error handler
- `xmlSetStructuredErrorFunc(context, structuredErrorFunc)` -- installs the structured error handler

The destructor restores the previous handlers.

### genericErrorFunc

```cpp
void XSLTProcessor::genericErrorFunc(void*, const char*, ...)
{
    // It would be nice to do something with this error message.
}
```

This is a **silent no-op** -- all generic errors are swallowed. The comment indicates this was
intentionally left empty but could be improved.

### parseErrorFunc (Structured Error Handler)

```cpp
void XSLTProcessor::parseErrorFunc(void* userData, const xmlError* error)
```

- `userData` is cast to `FrameConsoleClient*`
- Maps `xmlError->level` to WebKit `MessageLevel`:
  - `XML_ERR_NONE` -> `MessageLevel::Debug`
  - `XML_ERR_WARNING` -> `MessageLevel::Warning`
  - `XML_ERR_ERROR` / `XML_ERR_FATAL` -> `MessageLevel::Error`
- Reports to the browser console via `console->addMessage()` with:
  - Source: `MessageSource::XML`
  - Message: `error->message` (Latin-1 encoded)
  - File: `error->file` (Latin-1 encoded)
  - Line: `error->line`
  - Column: `error->int2`

**Note:** The `parseErrorFunc` signature varies by libxml version:
```cpp
#if LIBXML_VERSION >= 21200
void XSLTProcessor::parseErrorFunc(void* userData, const xmlError* error)
#else
void XSLTProcessor::parseErrorFunc(void* userData, xmlError* error)
#endif
```

### Error Handler Installation Points

Error handlers are installed in two places:
1. **`XSLStyleSheet::parseString()`** -- when parsing the stylesheet XML
2. **`docLoaderFunc()`** (XSLT_LOAD_DOCUMENT case) -- when parsing documents loaded via `document()` function

---

## 8. Additional Notable Behaviors

### xsltMaxDepth Override
```cpp
int origXsltMaxDepth = xsltMaxDepth;
xsltMaxDepth = 1000;
// ... transformation ...
xsltMaxDepth = origXsltMaxDepth;
```
WebKit sets the maximum XSLT recursion depth to 1000 during transformation.

### XML Declaration Suppression
```cpp
sheet->omitXmlDeclaration = true;
```
The XML declaration is always omitted from the result, as WebKit immediately re-parses
the result as a fragment.

### Output Method Detection
```cpp
const xmlChar* resultType = nullptr;
XSLT_GET_IMPORT_PTR(resultType, sheet, method);
if (!resultType && resultDoc->type == XML_HTML_DOCUMENT_NODE)
    resultType = (const xmlChar*)"html";
```
If no output method is specified in the stylesheet and the result document is HTML,
WebKit defaults to HTML output. The MIME type is set accordingly:
- `"html"` -> `text/html`
- `"text"` -> `text/plain`
- Otherwise -> `application/xml`

### HTML Method Injection
```cpp
xmlChar* origMethod = sheet->method;
if (!origMethod && mimeType == textHTMLContentTypeAtom())
    sheet->method = byteCast<xmlChar>(const_cast<char*>("html"));
```
If the caller expects HTML output but the stylesheet doesn't specify a method,
WebKit temporarily sets the method to `"html"`.

### Result String Post-Processing
```cpp
// Workaround for <http://bugzilla.gnome.org/show_bug.cgi?id=495668>:
// libxslt appends an extra line feed to the result.
if (resultBuilder.length() > 0 && resultBuilder[resultBuilder.length() - 1] == '\n')
    resultBuilder.shrink(resultBuilder.length() - 1);
```

### Dictionary Sharing for Child Stylesheets
In `parseString()`, child stylesheets share their parent's XML dictionary to prevent
symbol dictionary corruption:
```cpp
if (m_parentStyleSheet && m_parentStyleSheet->m_stylesheetDoc) {
    xmlDictFree(ctxt->dict);
    ctxt->dict = m_parentStyleSheet->m_stylesheetDoc->dict;
    xmlDictReference(ctxt->dict);
}
```

### Stylesheet Compilation Safety
```cpp
// Certain libxslt versions are corrupting the xmlDoc on compilation
// failures - hence attempting to recompile after a failure is unsafe.
if (m_compilationFailed)
    return nullptr;
```
WebKit tracks compilation failures and refuses to recompile a previously failed stylesheet.

### Global State Warning
The document loader uses global variables due to libxslt API limitations:
```cpp
// FIXME: There seems to be no way to control the ctxt pointer for loading here,
// thus we have globals.
static XSLTProcessor* globalProcessor = nullptr;
```

---

## 9. Summary of libxml2/libxslt API Surface

### libxslt headers included
```
<libxslt/imports.h>
<libxslt/security.h>
<libxslt/variables.h>
<libxslt/xslt.h>
<libxslt/xsltutils.h>
<libxslt/extensions.h>
<libxslt/extra.h>
<libxslt/xsltInternals.h>
<libxslt/templates.h>
```

### libxml2 headers included
```
<libxml/uri.h>
<libxml/xpathInternals.h>
```

### Complete list of libxslt functions called
1. `xsltSetLoaderFunc()`
2. `xsltNewTransformContext()`
3. `xsltNewSecurityPrefs()`
4. `xsltSetSecurityPrefs()`
5. `xsltSetCtxtSecurityPrefs()`
6. `xsltSecurityForbid` (callback)
7. `xsltSetCtxtSortFunc()`
8. `xsltQuoteUserParams()`
9. `xsltApplyStylesheetUser()`
10. `xsltFreeTransformContext()`
11. `xsltFreeSecurityPrefs()`
12. `xsltSaveResultTo()`
13. `xsltFreeStylesheet()`
14. `xsltParseStylesheetDoc()`
15. `xsltLoadStylesheetPI()`
16. `xsltGetNsProp()`
17. `xsltXPathGetTransformContext()`
18. `xsltFunctionNodeSet()`
19. `xsltCreateRVT()`
20. `xsltRegisterLocalRVT()`
21. `xsltTransformError()`
22. `xsltRegisterExtFunction()`
23. `xsltEvalAttrValueTemplate()`
24. `xsltComputeSortResult()`
25. `XSLT_GET_IMPORT_PTR()` (macro)
26. `IS_XSLT_ELEM()` (macro)
27. `IS_XSLT_NAME()` (macro)
28. `XSLT_NAMESPACE` (constant)
29. `XSLT_MAX_SORT` (constant)

### Complete list of libxml2 functions called (from XSLT-related files)
1. `xmlSetGenericErrorFunc()`
2. `xmlSetStructuredErrorFunc()`
3. `xmlReadMemory()`
4. `xmlCtxtReadMemory()`
5. `xmlCreateMemoryParserCtxt()`
6. `xmlFreeParserCtxt()`
7. `xmlNodeGetBase()`
8. `xmlBuildURI()`
9. `xmlStrEqual()`
10. `xmlFree()`
11. `xmlFreeDoc()`
12. `xmlGetID()`
13. `xmlAllocOutputBuffer()`
14. `xmlOutputBufferClose()`
15. `xmlNewDocText()`
16. `xmlAddChild()`
17. `xmlXPathNewNodeSet()`
18. `xmlXPathPopString()`
19. `xmlXPathSetArityError()`
20. `xmlXPathStackIsNodeSet()`
21. `xmlXPathIsNaN()`
22. `xmlXPathFreeObject()`
23. `xmlDictFree()`
24. `xmlDictReference()`
25. `valuePush()` (XPath stack operation)

### Global variables accessed
1. `xsltMaxDepth` -- read and written (set to 1000 during transformation)

### Struct fields directly accessed
1. `xsltStylesheet::method` -- read and written
2. `xsltStylesheet::omitXmlDeclaration` -- written (set to true)
3. `xsltTransformContext::document` -- read
4. `xsltTransformContext::node` -- read
5. `xsltTransformContext::inst` -- read
6. `xsltTransformContext::state` -- written (set to `XSLT_STATE_STOPPED` on error)
7. `xsltTransformContext::nodeList` -- read
8. `xsltStylePreComp::stype` -- read
9. `xsltStylePreComp::has_stype` -- read
10. `xsltStylePreComp::number` -- read
11. `xsltStylePreComp::order` -- read
12. `xsltStylePreComp::has_order` -- read
13. `xsltStylePreComp::descending` -- read
14. `xsltStylePreComp::has_lang` -- read
15. `xsltStylePreComp::lang` -- read
16. `xsltStylePreComp::lower_first` -- read
17. `xmlDoc::type` -- read
18. `xmlDoc::encoding` -- read
19. `xmlDoc::dict` -- read and written
20. `xmlDoc::children` -- read
21. `xmlNode::psvi` -- read (cast to `xsltStylePreComp*`)
22. `xmlNode::next` -- read
23. `xmlNode::type` -- read
24. `xmlNode::parent` -- read
25. `xmlNodeSet::nodeNr` -- read
26. `xmlNodeSet::nodeTab` -- read
27. `xmlError::level` -- read
28. `xmlError::message` -- read
29. `xmlError::file` -- read
30. `xmlError::line` -- read
31. `xmlError::int2` -- read
32. `xmlXPathObject::floatval` -- read
33. `xmlXPathObject::stringval` -- read
34. `xmlXPathObject::index` -- read
35. `xmlOutputBuffer::context` -- written
36. `xmlOutputBuffer::writecallback` -- written
37. `xmlAttr::parent` -- read
38. `xmlParserCtxt::dict` -- read and written
