# Candidate: WebKit Does Not Configure Entity Amplification Limit

## Status: UNCONFIRMED — mitigated by libxml2 defaults, but worth noting

## CWE Classification: CWE-776 (Improper Restriction of Recursive Entity References)

## Description

WebKit does not call `xmlCtxtSetMaxAmplification()` to configure an entity expansion amplification limit. The default amplification factor in libxml2 is hardcoded:

```c
// parser.c, xmlParserEntityCheck():
unsigned long maxAmpl = (ctxt->maxAmpl > 0) ? ctxt->maxAmpl : 100;
```

The default is 100x — meaning the expanded entity content can be at most 100 times the size of the unexpanded document. With `XML_PARSE_HUGE`, the expanded size is only limited by `XML_MAX_HUGE_LENGTH` (1 billion bytes) and available memory.

## Concrete Impact

An attacker can craft a document where:
- Document size: ~10 KB
- Expanded entity content: ~1 MB (100x amplification)

This is relatively modest. However, with a larger document:
- Document size: ~10 MB
- Expanded entity content: ~1 GB (100x amplification)

With `XML_PARSE_HUGE` enabled, this 1 GB expansion is permitted by libxml2.

## WebKit Reachability

YES — WebKit uses `XML_PARSE_NOENT | XML_PARSE_HUGE` and does not configure amplification limits.

### Entity Expansion Test (poc_001):
```xml
<!DOCTYPE doc [
  <!ENTITY a "AAA...100 chars...AAA">
  <!ENTITY b "&a;&a;...50x...&a;">
  <!ENTITY c "&b;&b;...50x...&b;">
  <!ENTITY d "&c;&c;...50x...&c;">
  <!ENTITY e "&d;&d;...50x...&d;">
]>
<doc>&e;</doc>
```

**Tested with ASan:** The parser correctly detects the amplification limit and reports:
```
Maximum entity amplification factor exceeded
```

This confirms the default 100x limit IS enforced, even without explicit configuration.

## Why Not Confirmed as Vulnerability

1. The default 100x amplification limit IS enforced
2. libxml2 catches the billion-laughs pattern and stops parsing
3. While WebKit doesn't explicitly configure the limit, the default is sufficient
4. No memory corruption — just resource consumption (DoS without memory safety impact)

## Recommendation

WebKit could call `xmlCtxtSetMaxAmplification()` with a more conservative value (e.g., 10x) to reduce the maximum memory consumption from entity expansion. This is a defense-in-depth improvement, not a vulnerability fix.
