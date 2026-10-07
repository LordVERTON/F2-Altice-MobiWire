#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import struct
from collections import defaultdict
import s13_5a51_launcher_dispatch_init_trace as m

TITLE = "S13.5A.54 - F03BB8F8 CONSUMER AND ROW-SCHEMA TRACE"
TABLE_LO = 0xF03BB800
TABLE_HI = 0xF03BB940
TARGET_PTR = 0xF03BB8F8
TARGET_LITERAL = 0x1034B95C
SECOND_LO = 0xF02F3F60
SECOND_HI = 0xF02F3FF0

FOCUS_IDS = {
    0x87ED, 0x8569, 0x8928, 0x8927,
    0xB6FD, 0xB707, 0xB705, 0xB703,
}
FOCUS_PTRS = {
    0xF0301C8D: "ROW_87ED_FN",
    0xF02FD275: "ROW_8569_FN",
    0x10348D05: "REGPTR_8569",
    0xF02FCF95: "ROW_B705_B703_FN",
    0x103471C9: "ROW_NEXT_FN",
    0x10344D89: "ROW_892X_FN",
}


def hline(s):
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def u16s(v):
    return v & 0xFFFF, (v >> 16) & 0xFFFF


def code_tag(aud, v):
    root = v & ~1
    img = aud.image_for(root)
    if img is None:
        return ""
    ins = aud.decode_one(root)
    if ins is None:
        return ""
    return f"CODE:{img.name}"


def find_u32(img, value):
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    p = 0
    out = []
    while True:
        p = img.data.find(needle, p)
        if p < 0:
            break
        out.append(img.base + p)
        p += 1
    return out


def find_literal_loads(aud, literal_addr=None, literal_value=None):
    rows = []
    for img in aud.images:
        pc = img.base & ~1
        end = img.end - 2
        while pc < end:
            x = aud.decode_one(pc)
            if x is not None and x.literal_addr is not None:
                ok = True
                if literal_addr is not None:
                    ok = ok and x.literal_addr == literal_addr
                if literal_value is not None:
                    ok = ok and x.literal_value == literal_value
                if ok:
                    rows.append((img.name, x))
            pc += 2
    return rows


def candidate_entries(aud, site, back=0x240):
    out = []
    start = max(site - back, 0) & ~1
    pc = start
    while pc <= site:
        x = aud.decode_one(pc)
        if x is not None:
            t = x.text.lower()
            if t.startswith("push") and "lr" in t:
                fa = aud.audit_func(pc, max_span=0x700, max_insns=1000)
                if site in fa.insns:
                    out.append((pc, fa))
        pc += 2
    return out


def dump_window(aud, center, before=0x60, after=0xA0):
    pc = (center - before) & ~1
    end = center + after
    while pc < end:
        x = aud.decode_one(pc)
        if x is not None:
            extra = []
            if x.target is not None:
                norm, via = aud.normalized_target(x.target)
                extra.append(f"target=0x{norm:08X}" + (f"[{via}]" if via else ""))
            if x.literal_value is not None:
                extra.append(f"literal@0x{x.literal_addr:08X}=0x{x.literal_value:08X}")
                s = aud.string_at(x.literal_value)
                if s:
                    extra.append(f'STR="{s}"')
            mark = " <XREF>" if pc == center else ""
            suffix = (" ; " + " ".join(extra)) if extra else ""
            print(f"0x{pc:08X}: {x.text}{suffix}{mark}")
            pc += max(x.size, 2)
        else:
            pc += 2


def dump_function(aud, entry, fa):
    print(f"candidate_entry=0x{entry:08X} image={fa.image} insns={len(fa.insns)} calls={len(fa.calls)} literals={len(fa.literals)} truncated={fa.truncated}")
    for addr in sorted(fa.insns):
        x = fa.insns[addr]
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            extra.append(f"target=0x{norm:08X}" + (f"[{via}]" if via else ""))
        if x.literal_value is not None:
            extra.append(f"literal@0x{x.literal_addr:08X}=0x{x.literal_value:08X}")
            s = aud.string_at(x.literal_value)
            if s:
                extra.append(f'STR="{s}"')
        suffix = (" ; " + " ".join(extra)) if extra else ""
        print(f"  0x{addr:08X}: {x.text}{suffix}")


def row(aud, zimage, start):
    w0 = zimage.read_u32(start)
    w1 = zimage.read_u32(start + 4)
    w2 = zimage.read_u32(start + 8)
    a, b = u16s(w1)
    c, d = u16s(w2)
    tags = []
    if w0 in FOCUS_PTRS:
        tags.append(FOCUS_PTRS[w0])
    if a in FOCUS_IDS or b in FOCUS_IDS or c in FOCUS_IDS or d in FOCUS_IDS:
        tags.append("FOCUS_ID")
    ct = code_tag(aud, w0)
    if ct:
        tags.append(ct)
    return w0, w1, w2, a, b, c, d, tags


def print_rows(aud, zimage, lo, hi):
    a = lo
    while a + 12 <= hi:
        w0, w1, w2, x0, x1, x2, x3, tags = row(aud, zimage, a)
        suffix = " <" + ", ".join(tags) + ">" if tags else ""
        print(
            f"0x{a:08X}: fn=0x{w0:08X} "
            f"k01=[{x0:04X},{x1:04X}] k23=[{x2:04X},{x3:04X}]{suffix}"
        )
        a += 12


def scan_pointer_refs(aud, lo, hi):
    refs = []
    for img in aud.images:
        a = img.base
        end = img.end - 4
        while a <= end:
            v = img.read_u32(a)
            if lo <= v < hi:
                refs.append((img.name, a, v))
            a += 4
    return refs


def main():
    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    if os.environ.get("F2_AUTOMATION_OFFLINE") != "1":
        raise SystemExit("offline automation marker missing")

    hline("A. CANONICAL IMAGE GUARDS")
    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    hline("B. CONFIRM 12-BYTE ROWS AROUND THE FOCUS RANGE")
    print_rows(aud, zimage, TABLE_LO, TABLE_HI)

    hline("C. UNIQUE POINTER INTO THE TABLE REGION")
    refs = scan_pointer_refs(aud, TABLE_LO, TABLE_HI)
    print(f"raw_refs={len(refs)}")
    for image_name, addr, value in refs:
        print(f"{image_name} 0x{addr:08X} -> 0x{value:08X}")

    hline("D. CODE LITERAL LOADS OF F03BB8F8")
    loads = find_literal_loads(aud, literal_value=TARGET_PTR)
    print(f"literal_loads_of_0x{TARGET_PTR:08X}={len(loads)}")
    for image_name, x in loads:
        print(f"{image_name} site=0x{x.addr:08X} {x.text} literal_addr=0x{x.literal_addr:08X}")
        dump_window(aud, x.addr)

    hline("E. CODE LITERAL LOADS USING THE EXACT ALICE POOL WORD")
    loads2 = find_literal_loads(aud, literal_addr=TARGET_LITERAL)
    print(f"literal_loads_using_pool_0x{TARGET_LITERAL:08X}={len(loads2)}")
    for image_name, x in loads2:
        print(f"{image_name} site=0x{x.addr:08X} {x.text} value=0x{x.literal_value:08X}")

    hline("F. ENCLOSING CONSUMER FUNCTION CANDIDATES")
    sites = sorted({x.addr for _, x in loads + loads2})
    if not sites:
        print("No Thumb literal-load site recovered.")
    for site in sites:
        print(f"consumer_site=0x{site:08X}")
        entries = candidate_entries(aud, site)
        print(f"  enclosing_candidates={len(entries)}")
        for entry, fa in entries[-4:]:
            dump_function(aud, entry, fa)

    hline("G. TARGET ROW AND NEIGHBOR FIELD RELATION")
    target_row = 0xF03BB8F4
    w0, w1, w2, a, b, c, d, tags = row(aud, zimage, target_row)
    print(f"row@0x{target_row:08X}: fn=0x{w0:08X} ids=[0x{a:04X},0x{b:04X},0x{c:04X},0x{d:04X}]")
    print(f"consumer pointer 0x{TARGET_PTR:08X} = row+4, i.e. it points to packed-ID field rather than fn field")
    print(f"contains_8928={0x8928 in (a,b,c,d)} contains_8927={0x8927 in (a,b,c,d)}")

    hline("H. SECONDARY F02F3FXX NEIGHBORHOOD")
    a = SECOND_LO
    while a + 4 <= SECOND_HI:
        v = zimage.read_u32(a)
        tags = []
        if v in FOCUS_PTRS:
            tags.append(FOCUS_PTRS[v])
        ct = code_tag(aud, v)
        if ct:
            tags.append(ct)
        if tags:
            print(f"0x{a:08X}: 0x{v:08X} <{', '.join(tags)}>")
        a += 4

    hline("I. EXACT FUNCTION-POINTER OCCURRENCES")
    for ptr, label in FOCUS_PTRS.items():
        hits = []
        for img in aud.images:
            for addr in find_u32(img, ptr):
                hits.append((img.name, addr))
        print(f"{label} 0x{ptr:08X}: {len(hits)} occurrences")
        for image_name, addr in hits:
            print(f"  {image_name} 0x{addr:08X}")

    hline("J. DECISION GATE")
    phase_rows = []
    a = TABLE_LO
    while a + 12 <= TABLE_HI:
        phase_rows.append(row(aud, zimage, a))
        a += 12
    code_rows = sum(1 for r in phase_rows if code_tag(aud, r[0]))
    focus_row_8569 = row(aud, zimage, 0xF03BB870)
    focus_row_reg = row(aud, zimage, 0xF03BB87C)
    print(f"phase0_rows={len(phase_rows)} code_first_field_rows={code_rows}")
    print(f"8569 row fn=0x{focus_row_8569[0]:08X} ids=[0x{focus_row_8569[3]:04X},0x{focus_row_8569[4]:04X},0x{focus_row_8569[5]:04X},0x{focus_row_8569[6]:04X}]")
    print(f"next row fn=0x{focus_row_reg[0]:08X} ids=[0x{focus_row_reg[3]:04X},0x{focus_row_reg[4]:04X},0x{focus_row_reg[5]:04X},0x{focus_row_reg[6]:04X}]")
    if focus_row_8569[1] == 0x85698569 and focus_row_reg[0] == m.INITPTR_8569:
        print("FACT: 85698569 belongs to the row whose function field is F02FD275; 10348D05 is the following row's function field.")
        print("Therefore 10348D05 must not be equated with the 8569 table-row function.")
    else:
        print("Row relationship differs from the A.53 observation.")
    if loads or loads2:
        print("NEXT: interpret the recovered consumer's indexing/stride and determine the semantic role of the packed-ID fields, especially the row containing 8927/8928.")
    else:
        print("NEXT: search non-literal references and parent-table pointers for the same packed-ID field.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
