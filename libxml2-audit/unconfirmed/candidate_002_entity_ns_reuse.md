# Candidate: Entity Namespace Resolution Reuse Across Contexts

## Status: UNCONFIRMED — correctness issue, not memory corruption

## CWE Classification: CWE-436 (Interpretation Conflict)

## Vulnerable Code
- **File:** `parser.c`
- **Function:** `xmlParseReference()`
- **Lines:** 7180-7208 (documented in a FIXME comment by the developers)

## Description

When an entity contains elements with namespace prefixes, the entity is parsed once and cached. Subsequent references to the same entity reuse the cached parse tree (via `xmlDocCopyNode`). However, the namespace resolution from the first expansion is baked into the cached tree.

This means if the same entity is expanded in different namespace contexts (where the same prefix maps to different URIs), all expansions will use the namespace bindings from the first expansion.

From the source comment at line 7180:
```c
/*
 * FIXME: This doesn't work correctly since entities can be
 * expanded with different namespace declarations in scope.
 * For example:
 *
 * <!DOCTYPE doc [
 *   <!ENTITY ent "<ns:elem/>">
 * ]>
 * <doc>
 *   <decl1 xmlns:ns="urn:ns1">
 *     &ent;
 *   </decl1>
 *   <decl2 xmlns:ns="urn:ns2">
 *     &ent;
 *   </decl2>
 * </doc>
 */
```

## Security Impact

This is primarily a **correctness/logic issue**, not a memory corruption vulnerability. The DOM tree would have incorrect namespace bindings, but:
- No buffer overflow
- No use-after-free
- No double-free
- The nodes are properly allocated and linked

### Potential Security Angle
In theory, incorrect namespace resolution could cause WebKit to misinterpret element semantics (e.g., treating a non-SVG element as SVG, or misidentifying security-relevant elements). However, this would require:
1. WebKit to make security decisions based on namespace URIs
2. The attacker to control entity content with namespace prefixes
3. The entity to be expanded in contexts with conflicting namespace mappings

This is speculative and was not confirmed as exploitable.

## WebKit Reachability

YES — this is reachable via normal XML document parsing with `XML_PARSE_NOENT` enabled.

## Why Not Confirmed

- No memory corruption
- Exploitation would require a secondary vulnerability in WebKit's namespace handling
- The developers are aware (documented FIXME) and have a proposed fix
