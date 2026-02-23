/*
 * webkit_harness.c - Mimics WebKit's exact libxml2 calling pattern
 *
 * WebKit uses:
 * - Push-mode parser with SAX2 callbacks
 * - XML_PARSE_NOENT | XML_PARSE_HUGE (document parsing)
 * - XML_PARSE_NODICT | XML_PARSE_NOENT | XML_PARSE_HUGE (fragment parsing)
 * - UTF-16 input for push parsing, UTF-8 for fragment parsing
 * - No explicit entity amplification limit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>
#include <libxml/SAX2.h>

/* Mode 1: Push parser (mirrors WebKit's XMLDocumentParser) */
static int test_push_mode(const char *filename) {
    FILE *f;
    char buf[4096];
    int size;
    xmlParserCtxtPtr ctxt;
    xmlSAXHandler sax;
    int ret = 0;

    f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", filename);
        return -1;
    }

    /* Mimic WebKit: create push parser with SAX2 */
    memset(&sax, 0, sizeof(sax));
    sax.initialized = XML_SAX2_MAGIC;
    sax.startElementNs = xmlSAX2StartElementNs;
    sax.endElementNs = xmlSAX2EndElementNs;
    sax.characters = xmlSAX2Characters;
    sax.cdataBlock = xmlSAX2CDataBlock;
    sax.comment = xmlSAX2Comment;
    sax.processingInstruction = xmlSAX2ProcessingInstruction;
    sax.startDocument = xmlSAX2StartDocument;
    sax.endDocument = xmlSAX2EndDocument;
    sax.internalSubset = xmlSAX2InternalSubset;
    sax.externalSubset = xmlSAX2ExternalSubset;
    sax.getEntity = xmlSAX2GetEntity;
    sax.entityDecl = xmlSAX2EntityDecl;
    sax.ignorableWhitespace = xmlSAX2IgnorableWhitespace;
    sax.warning = xmlParserWarning;
    sax.error = xmlParserError;
    sax.fatalError = xmlParserError;

    ctxt = xmlCreatePushParserCtxt(&sax, NULL, NULL, 0, filename);
    if (!ctxt) {
        fclose(f);
        return -1;
    }

    /* WebKit's document parsing options */
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_HUGE);

    while ((size = fread(buf, 1, sizeof(buf), f)) > 0) {
        xmlParseChunk(ctxt, buf, size, 0);
    }
    xmlParseChunk(ctxt, NULL, 0, 1); /* terminate */

    if (ctxt->myDoc)
        xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
    fclose(f);
    return ret;
}

/* Mode 2: Memory/fragment parser (mirrors WebKit's innerHTML parsing) */
static int test_fragment_mode(const char *filename) {
    FILE *f;
    long fsize;
    char *content;
    xmlParserCtxtPtr ctxt;
    xmlSAXHandler sax;

    f = fopen(filename, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    content = malloc(fsize + 1);
    if (!content) { fclose(f); return -1; }
    fread(content, 1, fsize, f);
    content[fsize] = 0;
    fclose(f);

    /* Mimic WebKit's fragment parsing: xmlCreateMemoryParserCtxt + xmlParseContent */
    memset(&sax, 0, sizeof(sax));
    sax.initialized = XML_SAX2_MAGIC;
    sax.startElementNs = xmlSAX2StartElementNs;
    sax.endElementNs = xmlSAX2EndElementNs;
    sax.characters = xmlSAX2Characters;
    sax.cdataBlock = xmlSAX2CDataBlock;
    sax.startDocument = xmlSAX2StartDocument;
    sax.endDocument = xmlSAX2EndDocument;
    sax.internalSubset = xmlSAX2InternalSubset;
    sax.getEntity = xmlSAX2GetEntity;
    sax.entityDecl = xmlSAX2EntityDecl;

    ctxt = xmlCreateMemoryParserCtxt(content, fsize);
    if (ctxt) {
        /* WebKit's fragment options */
        xmlCtxtUseOptions(ctxt, XML_PARSE_NODICT | XML_PARSE_NOENT | XML_PARSE_HUGE);

        /* Mimic WebKit: parse as content (not a full document) */
        xmlParseDocument(ctxt);

        if (ctxt->myDoc)
            xmlFreeDoc(ctxt->myDoc);
        xmlFreeParserCtxt(ctxt);
    }

    free(content);
    return 0;
}

/* Mode 3: XSLT-like document parsing (XML_PARSE_NOENT | XML_PARSE_DTDLOAD | XML_PARSE_DTDATTR | XML_PARSE_NOCDATA) */
static int test_xslt_mode(const char *filename) {
    xmlDocPtr doc;

    doc = xmlReadFile(filename, NULL,
                      XML_PARSE_NOENT | XML_PARSE_DTDATTR |
                      XML_PARSE_NOWARNING | XML_PARSE_NOCDATA);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *mode;
    const char *filename;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <push|fragment|xslt> <file>\n", argv[0]);
        return 1;
    }

    mode = argv[1];
    filename = argv[2];

    xmlInitParser();

    if (strcmp(mode, "push") == 0)
        test_push_mode(filename);
    else if (strcmp(mode, "fragment") == 0)
        test_fragment_mode(filename);
    else if (strcmp(mode, "xslt") == 0)
        test_xslt_mode(filename);
    else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        return 1;
    }

    xmlCleanupParser();
    return 0;
}
