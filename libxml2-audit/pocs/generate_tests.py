#!/usr/bin/env python3
"""Generate edge-case XML test files for libxml2 security testing."""

import os

OUTDIR = os.path.dirname(os.path.abspath(__file__))

def write_test(name, content):
    path = os.path.join(OUTDIR, name)
    with open(path, 'wb') as f:
        f.write(content.encode('utf-8') if isinstance(content, str) else content)
    print(f"Generated: {name}")

# Test: Very long attribute value (near XML_MAX_TEXT_LENGTH)
def gen_long_attr():
    val = "A" * 9999990
    content = f'<?xml version="1.0"?>\n<doc attr="{val}"/>\n'
    write_test("poc_020_long_attr.xml", content)

# Test: Many attributes on single element
def gen_many_attrs():
    attrs = " ".join(f'a{i}="v{i}"' for i in range(10000))
    content = f'<?xml version="1.0"?>\n<doc {attrs}/>\n'
    write_test("poc_021_many_attrs.xml", content)

# Test: Entity that contains element markup with deep nesting
def gen_entity_with_markup():
    content = '''<?xml version="1.0"?>
<!DOCTYPE doc [
  <!ENTITY e1 "<a><b><c>text</c></b></a>">
  <!ENTITY e2 "&e1;&e1;&e1;">
  <!ENTITY e3 "<wrapper>&e2;</wrapper>">
]>
<doc>&e3;&e3;</doc>
'''
    write_test("poc_022_entity_markup_nesting.xml", content)

# Test: Entity used in different namespace contexts
def gen_entity_ns_context():
    content = '''<?xml version="1.0"?>
<!DOCTYPE doc [
  <!ENTITY ent "<ns:elem/>">
]>
<doc>
  <decl1 xmlns:ns="urn:ns1">&ent;</decl1>
  <decl2 xmlns:ns="urn:ns2">&ent;</decl2>
</doc>
'''
    write_test("poc_023_entity_ns_context.xml", content)

# Test: Empty entity expansions
def gen_empty_entities():
    content = '''<?xml version="1.0"?>
<!DOCTYPE doc [
  <!ENTITY empty "">
  <!ENTITY empty2 "&empty;&empty;&empty;">
  <!ENTITY empty3 "&empty2;&empty2;&empty2;">
]>
<doc attr="&empty;">&empty;&empty2;&empty3;</doc>
'''
    write_test("poc_024_empty_entities.xml", content)

# Test: Recursive-looking (but valid) entity chain in attributes
def gen_entity_attr_chain():
    entities = []
    for i in range(39):  # Just under the HUGE limit of 40
        if i == 0:
            entities.append(f'  <!ENTITY e0 "A">')
        else:
            entities.append(f'  <!ENTITY e{i} "&e{i-1};&e{i-1};">')

    entity_decls = "\n".join(entities)
    content = f'''<?xml version="1.0"?>
<!DOCTYPE doc [
{entity_decls}
]>
<doc attr="&e38;"/>
'''
    write_test("poc_025_entity_attr_chain_deep.xml", content)

# Test: Large CDATA section adjacent to text
def gen_large_cdata():
    cdata_content = "X" * 100000
    content = f'<?xml version="1.0"?>\n<doc>text<![CDATA[{cdata_content}]]>moretext</doc>\n'
    write_test("poc_026_large_cdata.xml", content)

# Test: Mixed content with entities and char refs in attributes
def gen_mixed_attr_entities():
    content = '''<?xml version="1.0"?>
<!DOCTYPE doc [
  <!ENTITY x "&#38;#65;">
  <!ENTITY y "&#38;amp;">
]>
<doc attr="&x;&y;&#38;&#60;&#62;"/>
'''
    write_test("poc_027_mixed_attr_entities.xml", content)

# Test: UTF-16 LE BOM file
def gen_utf16le():
    xml_str = '<?xml version="1.0" encoding="UTF-16"?>\n<doc>Hello UTF-16</doc>\n'
    bom = b'\xFF\xFE'
    content = bom + xml_str.encode('utf-16-le')
    write_test("poc_028_utf16le.xml", content)

# Test: UTF-16 BE BOM file
def gen_utf16be():
    xml_str = '<?xml version="1.0" encoding="UTF-16"?>\n<doc>Hello UTF-16 BE</doc>\n'
    bom = b'\xFE\xFF'
    content = bom + xml_str.encode('utf-16-be')
    write_test("poc_029_utf16be.xml", content)

# Test: Truncated UTF-16 (odd number of bytes)
def gen_truncated_utf16():
    xml_str = '<?xml version="1.0" encoding="UTF-16"?>\n<doc>Hello</doc>\n'
    bom = b'\xFF\xFE'
    encoded = bom + xml_str.encode('utf-16-le')
    # Truncate to odd length
    content = encoded[:-1]
    write_test("poc_030_truncated_utf16.xml", content)

# Test: Invalid UTF-8 sequences
def gen_invalid_utf8():
    content = b'<?xml version="1.0"?>\n<doc>'
    content += b'\xC0\xAF'  # overlong encoding of '/'
    content += b'\xE0\x80\xAF'  # overlong 3-byte
    content += b'\xF0\x80\x80\xAF'  # overlong 4-byte
    content += b'\xFE\xFF'  # invalid start bytes
    content += b'\x80\x81\x82'  # continuation bytes without start
    content += b'\xED\xA0\x80'  # surrogate half (U+D800)
    content += b'</doc>\n'
    write_test("poc_031_invalid_utf8.xml", content)

# Test: Surrogate pairs in UTF-16
def gen_utf16_surrogates():
    bom = b'\xFF\xFE'
    # Build a document with surrogate pairs (emoji)
    xml_str = '<?xml version="1.0" encoding="UTF-16"?>\n<doc>\U0001F600\U0001F4A9\U00010000</doc>\n'
    content = bom + xml_str.encode('utf-16-le')
    write_test("poc_032_utf16_surrogates.xml", content)

# Test: Invalid surrogate pair in UTF-16
def gen_utf16_bad_surrogate():
    bom = b'\xFF\xFE'
    # High surrogate without low surrogate
    content = bom
    content += '<?xml version="1.0" encoding="UTF-16"?>\n<doc>'.encode('utf-16-le')
    content += b'\x00\xD8'  # lone high surrogate
    content += 'X'.encode('utf-16-le')
    content += '</doc>\n'.encode('utf-16-le')
    write_test("poc_033_utf16_bad_surrogate.xml", content)

if __name__ == "__main__":
    gen_long_attr()
    gen_many_attrs()
    gen_entity_with_markup()
    gen_entity_ns_context()
    gen_empty_entities()
    gen_entity_attr_chain()
    gen_large_cdata()
    gen_mixed_attr_entities()
    gen_utf16le()
    gen_utf16be()
    gen_truncated_utf16()
    gen_invalid_utf8()
    gen_utf16_surrogates()
    gen_utf16_bad_surrogate()
    print("\nAll test files generated.")
