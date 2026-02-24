/*
 * PoC for infinite loop in exsltFormatLong (date.c:1122-1125)
 *
 * When the output buffer fills up (*cur >= end), the inner loop
 * `while (i > 0)` spins forever because `--i` is inside the
 * `if (*cur < end)` branch and never executes.
 *
 * To trigger: call a date function that returns a formatted duration
 * with enough components to fill the 99-byte buffer.
 *
 * NOTE: With the current 100-byte buffer, the maximum formatted
 * duration is ~94 chars (with LONG_MAX values), so this is a LATENT
 * bug that cannot be triggered with current constants. We demonstrate
 * the code defect by examining the function directly.
 */

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>
#include <libexslt/exslt.h>

/* Use EXSLT date:add to create durations that format to long strings */
static const char *xsl_sheet =
"<?xml version=\"1.0\"?>\n"
"<xsl:stylesheet version=\"1.0\"\n"
"  xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"\n"
"  xmlns:date=\"http://exslt.org/dates-and-times\">\n"
"\n"
"  <xsl:template match=\"/\">\n"
"    <result>\n"
"      <!-- Create a duration with maximum-length components -->\n"
"      <!-- P999999999999999999Y11M... would be the longest -->\n"
"      <xsl:value-of select=\"date:duration(99999999999999999)\"/>\n"
"      <xsl:text> | </xsl:text>\n"
"      <xsl:value-of select=\"date:add('2000-01-01', 'P999999999Y11M30DT23H59M59.999999999S')\"/>\n"
"    </result>\n"
"  </xsl:template>\n"
"\n"
"</xsl:stylesheet>\n";

static const char *xml_input =
"<?xml version=\"1.0\"?>\n"
"<root/>\n";

static volatile sig_atomic_t timed_out = 0;
static jmp_buf jmp_env;

static void alarm_handler(int sig) {
    (void)sig;
    timed_out = 1;
    longjmp(jmp_env, 1);
}

int main(void) {
    xmlDocPtr doc, style_doc, res;
    xsltStylesheetPtr style;

    xmlInitParser();
    exsltRegisterAll();

    printf("=== Infinite Loop Test (exsltFormatLong) ===\n\n");
    printf("Buffer size: 100 bytes (99 usable)\n");
    printf("Max format length: ~94 chars (LONG_MAX values)\n");
    printf("Result: Latent bug, not triggerable with current buffer\n\n");

    style_doc = xmlParseMemory(xsl_sheet, strlen(xsl_sheet));
    if (style_doc == NULL) {
        fprintf(stderr, "Failed to parse stylesheet\n");
        return 1;
    }

    style = xsltParseStylesheetDoc(style_doc);
    if (style == NULL) {
        fprintf(stderr, "Failed to parse XSLT stylesheet\n");
        xmlFreeDoc(style_doc);
        return 1;
    }

    doc = xmlParseMemory(xml_input, strlen(xml_input));
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse input\n");
        xsltFreeStylesheet(style);
        return 1;
    }

    /* Set a 5-second timeout to detect infinite loops */
    signal(SIGALRM, alarm_handler);
    alarm(5);

    printf("Running transformation with 5-second timeout...\n");

    if (setjmp(jmp_env) == 0) {
        res = xsltApplyStylesheet(style, doc, NULL);
        alarm(0); /* cancel alarm */

        if (res != NULL) {
            printf("Transformation completed (no infinite loop).\n");
            printf("Result: ");
            xsltSaveResultToFile(stdout, res, style);
            printf("\n");
            xmlFreeDoc(res);
        } else {
            printf("Transformation returned NULL.\n");
        }
    } else {
        printf("\n*** TIMEOUT: Infinite loop detected! ***\n");
    }

    xmlFreeDoc(doc);
    xsltFreeStylesheet(style);
    xsltCleanupGlobals();
    xmlCleanupParser();

    printf("\n=== Test complete ===\n");
    return timed_out ? 1 : 0;
}
