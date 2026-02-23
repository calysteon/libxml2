# WebKit libxml2 Attack Surface Map

## 1. Parser Configurations

### 1.1 XML Document Parsing (Push Mode)
- **Entry:** `XMLDocumentParserLibxml2.cpp` — `XMLDocumentParser::doWrite()`
- **Parser creation:** `xmlCreatePushParserCtxt()` with SAX2 callbacks
- **Options:** `XML_PARSE_NOENT | XML_PARSE_HUGE`
- **Input encoding:** UTF-16 (converted from WebKit's internal string format)
- **Data feed:** `xmlParseChunk()` with incremental data from network
- **Termination:** `xmlParseChunk(ctx, NULL, 0, 1)` on end-of-document

### 1.2 Fragment Parsing (Memory Mode)
- **Entry:** `XMLDocumentParser::parseDocumentFragment()`
- **Parser creation:** `xmlCreateMemoryParserCtxt()` + `xmlParseContent()`
- **Options:** `XML_PARSE_NODICT | XML_PARSE_NOENT | XML_PARSE_HUGE`
- **Input encoding:** UTF-8
- **Data feed:** Entire content loaded at creation time
- **Size guard:** Fragment content > INT_MAX bytes is rejected

### 1.3 XSLT Document Parsing
- **Entry:** `XSLTProcessorLibxslt.cpp` — `transformToString()`
- **Parser:** `xmlReadMemory()` / `xmlCtxtReadMemory()`
- **Options:** `XML_PARSE_NOENT | XML_PARSE_DTDLOAD | XML_PARSE_DTDATTR | XML_PARSE_NOCDATA`
- **Note:** `XML_PARSE_DTDLOAD` is ONLY enabled in XSLT context, not normal parsing
- **Attacker control:** Full — XSLT stylesheets and source documents are JS-controllable

### 1.4 Attribute Parsing (Synthetic Push)
- **Entry:** `XMLDocumentParser::parseAttributes()`
- **Parser creation:** Push parser wrapping attribute string in `<?xml version="1.0"?><attrs ... />`
- **Options:** `XML_PARSE_NOENT | XML_PARSE_HUGE`

## 2. SAX2 Callback Registration

WebKit registers 16 SAX callbacks in the primary handler:

| SAX Field | WebKit Handler | Notes |
|---|---|---|
| `startElementNs` | `startElementNsHandler` | Creates DOM elements, resolves namespaces |
| `endElementNs` | `endElementNsHandler` | Flushes text, triggers script execution |
| `characters` | `charactersHandler` | Appends to buffered text |
| `cdataBlock` | `cdataBlockHandler` | Creates CDATASection node |
| `comment` | `commentHandler` | Creates Comment node |
| `processingInstruction` | `processingInstructionHandler` | Detects XSLT/CSS |
| `startDocument` | `startDocumentHandler` | Switches encoding to UTF-16 |
| `endDocument` | `endDocumentHandler` | Final cleanup |
| `internalSubset` | `internalSubsetHandler` | Creates DocumentType |
| `externalSubset` | `externalSubsetHandler` | Detects XHTML DTDs |
| `getEntity` | `getEntityHandler` | 3-tier: predefined, document, XHTML |
| `entityDecl` | `xmlSAX2EntityDecl` | Direct libxml2 default |
| `ignorableWhitespace` | No-op | Crash workaround |
| `warning/error/fatalError` | Error handlers | Route to XMLDocumentParser::error() |

## 3. Trust Boundaries and Data Flow

### 3.1 Network Content (Primary Attack Vector)
```
Network → TextResourceDecoder → XMLDocumentParser::append()
  → doWrite() → UTF-16 conversion → xmlParseChunk()
  → SAX callbacks → DOM construction
```
- **Attacker control:** Full control of XML content
- **Pre-parsing validation:** None (raw XML fed to libxml2)
- **Encoding conversion:** WebKit converts to UTF-16 before feeding libxml2

### 3.2 Fragment Content (innerHTML)
```
JavaScript innerHTML → parseDocumentFragment()
  → UTF-8 conversion → xmlCreateMemoryParserCtxt()
  → xmlParseContent() → SAX callbacks → DOM fragment
```
- **Attacker control:** Full (any JS code can set innerHTML on XML element)
- **Pre-parsing validation:** Size check (INT_MAX), script/style bypass

### 3.3 XSLT (Attacker-Controlled Stylesheets)
```
JavaScript XSLTProcessor API:
  new DOMParser().parseFromString(attackerXSLT)
  → proc.importStylesheet(xslDoc)
  → proc.transformToDocument(attackerXML)
  → xsltApplyStylesheetUser()
```
- **Attacker control:** Stylesheet, parameters, and source document all controllable
- **Security:** File write/directory creation/network write forbidden
- **Read-side:** Same-origin only (custom document loader)

### 3.4 External Entity Loading
- **Gated by:** `shouldAllowExternalLoad()` — same-origin check
- **Blocked:** file:///etc/xml/catalog, w3.org DTDs, cross-origin resources
- **MIME validation:** External resources must have XML MIME type

## 4. Security Defenses

| Defense | Limit | Location |
|---|---|---|
| DOM tree depth | 5000 | `maxXMLTreeDepth` in WebKit |
| Entity nesting depth | 40 (HUGE) / 20 (normal) | `xmlCtxtPushInput` in libxml2 |
| Entity amplification | Default (~100x) | `xmlParserEntityCheck` in libxml2 |
| Text node size | 1 billion (HUGE) / 10 million (normal) | `XML_MAX_HUGE_LENGTH` |
| Fragment size | INT_MAX bytes | WebKit pre-check |
| External entity loading | Same-origin | `shouldAllowExternalLoad` |
| XSLT recursion depth | 1000 | `xsltMaxDepth` |
| URI length | 1 MB | `MAX_URI_LENGTH` in uri.c |

## 5. NOT Reachable from WebKit

| Feature | Why Not Reachable |
|---|---|
| libxml2 XPath (`xpath.c`) | WebKit has its own XPath implementation |
| XPointer (`xpointer.c`) | Not used by WebKit |
| DTD validation (`valid.c`) | `XML_PARSE_DTDVALID` never set |
| RelaxNG (`relaxng.c`) | Not used by WebKit |
| XML Schema (`xmlschemas.c`) | Not used by WebKit |
| `XML_PARSE_SAX1` mode | WebKit uses SAX2 exclusively |
| `xmlReader` API | WebKit uses push/memory parser |

## 6. Key Parser Options Impact

### XML_PARSE_NOENT (Entity Substitution)
- **Effect:** Internal entities are expanded by libxml2
- **Impact:** Entity expansion code paths are reachable
- **Risk:** Billion laughs variants (mitigated by amplification check)

### XML_PARSE_HUGE
- **Effect:** Removes or relaxes libxml2's built-in size limits
- **Impact:** Text nodes can be up to 1 billion bytes
- **Impact:** Entity nesting depth increased to 40
- **Impact:** Various name/value length limits relaxed
- **Risk:** Integer overflow in size calculations using `int` types

### XML_PARSE_DTDLOAD (XSLT only)
- **Effect:** External DTDs and parameter entities are loaded
- **Impact:** DTD processing code paths become reachable in XSLT context
- **Risk:** Additional attack surface in DTD parsing
