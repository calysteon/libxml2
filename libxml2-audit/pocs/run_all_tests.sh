#!/bin/bash
# Run all PoC files through xmllint with WebKit-equivalent flags
# and through the custom harness

XMLLINT="/home/user/libxml2/build-asan/xmllint"
HARNESS="/home/user/libxml2-audit/pocs/webkit_harness"
POCDIR="/home/user/libxml2-audit/pocs"
RESULTS="/home/user/libxml2-audit/pocs/test_results.txt"

export ASAN_OPTIONS="halt_on_error=0:detect_leaks=0:print_stacktrace=1:symbolize=1"

echo "=== libxml2 ASan Test Results ===" > "$RESULTS"
echo "Date: $(date)" >> "$RESULTS"
echo "" >> "$RESULTS"

# Test each XML file
for poc in "$POCDIR"/poc_*.xml; do
    name=$(basename "$poc")
    echo "--- Testing: $name ---" >> "$RESULTS"

    # Test 1: xmllint with --noent --huge (WebKit document mode)
    echo "  [xmllint --noent --huge]" >> "$RESULTS"
    timeout 30 "$XMLLINT" --noent --huge --noout "$poc" >> "$RESULTS" 2>&1
    echo "  exit: $?" >> "$RESULTS"

    # Test 2: Custom harness - push mode
    echo "  [harness push]" >> "$RESULTS"
    timeout 30 "$HARNESS" push "$poc" >> "$RESULTS" 2>&1
    echo "  exit: $?" >> "$RESULTS"

    # Test 3: Custom harness - fragment mode
    echo "  [harness fragment]" >> "$RESULTS"
    timeout 30 "$HARNESS" fragment "$poc" >> "$RESULTS" 2>&1
    echo "  exit: $?" >> "$RESULTS"

    # Test 4: Custom harness - xslt mode (dtdload enabled)
    echo "  [harness xslt]" >> "$RESULTS"
    timeout 30 "$HARNESS" xslt "$poc" >> "$RESULTS" 2>&1
    echo "  exit: $?" >> "$RESULTS"

    echo "" >> "$RESULTS"
done

echo "=== Testing Complete ===" >> "$RESULTS"
echo "Results written to: $RESULTS"

# Show summary of any ASan errors
if grep -l "ERROR: AddressSanitizer\|ERROR: UndefinedBehaviorSanitizer\|runtime error:" "$RESULTS" 2>/dev/null; then
    echo "*** SANITIZER ERRORS FOUND ***"
    grep -A5 "ERROR: AddressSanitizer\|ERROR: UndefinedBehaviorSanitizer\|runtime error:" "$RESULTS"
else
    echo "No sanitizer errors found."
fi
