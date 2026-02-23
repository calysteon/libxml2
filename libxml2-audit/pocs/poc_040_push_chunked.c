/*
 * Test push parsing with small chunk sizes to exercise boundary conditions
 * in the push parser state machine. WebKit feeds data incrementally.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/SAX2.h>

static void test_push_small_chunks(const char *filename) {
    FILE *f;
    char buf[1]; /* Single byte chunks to maximize state transitions */
    int size;
    xmlParserCtxtPtr ctxt;

    f = fopen(filename, "rb");
    if (!f) return;

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, filename);
    if (!ctxt) { fclose(f); return; }
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_HUGE);

    while ((size = fread(buf, 1, 1, f)) > 0) {
        xmlParseChunk(ctxt, buf, size, 0);
    }
    xmlParseChunk(ctxt, NULL, 0, 1);

    if (ctxt->myDoc) xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
    fclose(f);
}

static void test_push_varying_chunks(const char *filename) {
    FILE *f;
    char buf[8192];
    int sizes[] = {1, 2, 3, 5, 7, 11, 13, 17, 100, 1000, 4096};
    int idx = 0;
    int size;
    xmlParserCtxtPtr ctxt;

    f = fopen(filename, "rb");
    if (!f) return;

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, filename);
    if (!ctxt) { fclose(f); return; }
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_HUGE);

    while (1) {
        int chunk = sizes[idx % (sizeof(sizes)/sizeof(sizes[0]))];
        idx++;
        size = fread(buf, 1, chunk, f);
        if (size <= 0) break;
        xmlParseChunk(ctxt, buf, size, 0);
    }
    xmlParseChunk(ctxt, NULL, 0, 1);

    if (ctxt->myDoc) xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
    fclose(f);
}

/* Test: push parser with entity boundaries split across chunks */
static void test_split_entity_refs(void) {
    const char *xml =
        "<?xml version=\"1.0\"?>"
        "<!DOCTYPE doc ["
        "  <!ENTITY ent \"hello world\">"
        "]>"
        "<doc>";

    const char *entity_ref = "&ent;";
    const char *end = "</doc>";
    xmlParserCtxtPtr ctxt;

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
    if (!ctxt) return;
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_HUGE);

    /* Feed DTD and opening tag */
    xmlParseChunk(ctxt, xml, strlen(xml), 0);

    /* Feed entity reference split across multiple chunks */
    xmlParseChunk(ctxt, "&", 1, 0);
    xmlParseChunk(ctxt, "e", 1, 0);
    xmlParseChunk(ctxt, "n", 1, 0);
    xmlParseChunk(ctxt, "t", 1, 0);
    xmlParseChunk(ctxt, ";", 1, 0);

    /* Feed more entity refs in quick succession */
    for (int i = 0; i < 100; i++) {
        xmlParseChunk(ctxt, entity_ref, strlen(entity_ref), 0);
    }

    xmlParseChunk(ctxt, end, strlen(end), 0);
    xmlParseChunk(ctxt, NULL, 0, 1);

    if (ctxt->myDoc) xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
}

/* Test: push parser with CDATA split across chunks */
static void test_split_cdata(void) {
    xmlParserCtxtPtr ctxt;

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
    if (!ctxt) return;
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_HUGE);

    xmlParseChunk(ctxt, "<?xml version=\"1.0\"?>", 21, 0);
    xmlParseChunk(ctxt, "<doc>", 5, 0);
    xmlParseChunk(ctxt, "<![CDA", 6, 0);
    xmlParseChunk(ctxt, "TA[content", 10, 0);
    xmlParseChunk(ctxt, "]]", 2, 0);
    xmlParseChunk(ctxt, ">", 1, 0);
    xmlParseChunk(ctxt, "</doc>", 6, 0);
    xmlParseChunk(ctxt, NULL, 0, 1);

    if (ctxt->myDoc) xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
}

/* Test: push parser with comment split at -- boundary */
static void test_split_comment(void) {
    xmlParserCtxtPtr ctxt;

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
    if (!ctxt) return;
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_HUGE);

    xmlParseChunk(ctxt, "<?xml version=\"1.0\"?>", 21, 0);
    xmlParseChunk(ctxt, "<doc>", 5, 0);
    xmlParseChunk(ctxt, "<!-", 3, 0);
    xmlParseChunk(ctxt, "- comment -", 11, 0);
    xmlParseChunk(ctxt, "->", 2, 0);
    xmlParseChunk(ctxt, "</doc>", 6, 0);
    xmlParseChunk(ctxt, NULL, 0, 1);

    if (ctxt->myDoc) xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
}

/* Test: push parser with tag split */
static void test_split_tags(void) {
    xmlParserCtxtPtr ctxt;

    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
    if (!ctxt) return;
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_HUGE);

    xmlParseChunk(ctxt, "<?xml version=\"1.0\"?>", 21, 0);
    xmlParseChunk(ctxt, "<do", 3, 0);
    xmlParseChunk(ctxt, "c at", 4, 0);
    xmlParseChunk(ctxt, "tr=\"va", 6, 0);
    xmlParseChunk(ctxt, "lue\" ", 5, 0);
    xmlParseChunk(ctxt, "attr2=", 6, 0);
    xmlParseChunk(ctxt, "\"val2\"", 6, 0);
    xmlParseChunk(ctxt, ">", 1, 0);
    xmlParseChunk(ctxt, "text", 4, 0);
    xmlParseChunk(ctxt, "</do", 4, 0);
    xmlParseChunk(ctxt, "c>", 2, 0);
    xmlParseChunk(ctxt, NULL, 0, 1);

    if (ctxt->myDoc) xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
}

int main(int argc, char **argv) {
    xmlInitParser();

    printf("Test: split entity refs\n");
    test_split_entity_refs();

    printf("Test: split CDATA\n");
    test_split_cdata();

    printf("Test: split comment\n");
    test_split_comment();

    printf("Test: split tags\n");
    test_split_tags();

    if (argc > 1) {
        printf("Test: push small chunks on %s\n", argv[1]);
        test_push_small_chunks(argv[1]);

        printf("Test: push varying chunks on %s\n", argv[1]);
        test_push_varying_chunks(argv[1]);
    }

    xmlCleanupParser();
    printf("All push chunk tests completed.\n");
    return 0;
}
