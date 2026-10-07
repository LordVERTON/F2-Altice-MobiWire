#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import struct
from collections import defaultdict
import s13_5a51_launcher_dispatch_init_trace as m

TITLE = "S13.5A.53 - F03BB8XX ROLE TABLE OWNER AUDIT"
REGION_START = 0xF03BB820
REGION_END = 0xF03BB980
ANCHOR = 0xF03BB864
FOCUS_WORDS = {
    0x87ED87ED: "PAIR_87ED",
    0x85698569: "PAIR_8569",
    0xB707B6FD: "B6FD_B707",
    0x0000B6FD: "B6FD_ZERO",
    0xB703B705: "B705_B703",
}
FOCUS_PTRS = {
    0xF0301C8D: "ROW_FN_NEAR_87ED",
    0xF02FD275: "ROW_FN_NEAR_8569",
    0x10348D05: "INITPTR_8569",
    0xF02FCF95: "ROW_FN_B705_B703",
    0x103471C9: "NEXT_ROW_FN",
}


def hline(s):
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def u16s(v):
    return v & 0xFFFF, (v >> 16) & 0xFFFF


def code_tag(aud, v):
    addr = v & ~1
    img = aud.image_for(addr)
    if img is None:
        return ""
    ins = aud.decode_one(addr)
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


def profile(aud, root, depth=4):
    funcs, edges, focus, strings = m.callgraph(aud, root & ~1, depth=depth, max_funcs=220)
    calls = set()
    for fa in funcs.values():
        for _, raw in fa.calls:
            calls.add(aud.normalized_target(raw)[0])
    return funcs, edges, focus, strings, calls


def unique_strings(rows):
    seen = set()
    out = []
    for entry, site, ptr, s in rows:
        key = (ptr, s)
        if key not in seen:
            seen.add(key)
            out.append((entry, site, ptr, s))
    return out


def dump_profile(aud, label, ptr):
    root = ptr & ~1
    funcs, edges, focus, strings, calls = profile(aud, root)
    print(f"{label}: ptr=0x{ptr:08X} root=0x{root:08X} funcs={len(funcs)} calls={len(calls)} strings={len(strings)}")
    for entry, site, sptr, s in unique_strings(strings)[:60]:
        print(f'  STR func=0x{entry:08X} site=0x{site:08X} ptr=0x{sptr:08X} "{s}"')
    return funcs, edges, focus, strings, calls


def row_dump(aud, zimage, start, count):
    for i in range(count):
        a = start + i * 12
        if not zimage.contains(a, 12):
            break
        w0 = zimage.read_u32(a)
        w1 = zimage.read_u32(a + 4)
        w2 = zimage.read_u32(a + 8)
        a1, b1 = u16s(w1)
        a2, b2 = u16s(w2)
        tags = []
        if w0 in FOCUS_PTRS:
            tags.append(FOCUS_PTRS[w0])
        if w1 in FOCUS_WORDS:
            tags.append(FOCUS_WORDS[w1])
        if w2 in FOCUS_WORDS:
            tags.append(FOCUS_WORDS[w2])
        ct = code_tag(aud, w0)
        if ct:
            tags.append(ct)
        suffix = " <" + ", ".join(tags) + ">" if tags else ""
        print(
            f"0x{a:08X}: w0=0x{w0:08X} "
            f"w1=0x{w1:08X}[{a1:04X},{b1:04X}] "
            f"w2=0x{w2:08X}[{a2:04X},{b2:04X}]{suffix}"
        )


def score_phase(aud, zimage, phase, lo, hi):
    rows = 0
    code = 0
    focus = 0
    zeroish = 0
    a = lo + ((phase - lo) % 12)
    while a + 12 <= hi:
        rows += 1
        w0 = zimage.read_u32(a)
        w1 = zimage.read_u32(a + 4)
        w2 = zimage.read_u32(a + 8)
        if code_tag(aud, w0):
            code += 1
        if w0 in FOCUS_PTRS or w1 in FOCUS_WORDS or w2 in FOCUS_WORDS:
            focus += 1
        if w2 == 0 or (w2 >> 16) == 0:
            zeroish += 1
        a += 12
    return rows, code, focus, zeroish


def scan_region_refs(aud):
    refs = []
    for img in aud.images:
        a = img.base
        end = img.end - 4
        while a <= end:
            v = img.read_u32(a)
            if REGION_START <= v < REGION_END:
                refs.append((img.name, a, v))
            a += 4
    return refs


def inspect_ref_code(aud, ref_addr):
    out = []
    start = (ref_addr - 0x30) & ~1
    end = ref_addr + 0x34
    pc = start
    while pc < end:
        x = aud.decode_one(pc)
        if x is not None:
            if x.literal_value is not None and REGION_START <= x.literal_value < REGION_END:
                out.append((pc, x.text, x.literal_value))
        pc += 2
    return out


def main():
    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    if os.environ.get("F2_AUTOMATION_OFFLINE") != "1":
        raise SystemExit("offline automation marker missing")

    hline("A. CANONICAL IMAGE GUARDS")
    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    hline("B. RAW REGION AROUND F03BB87C")
    a = REGION_START
    while a + 4 <= REGION_END:
        v = zimage.read_u32(a)
        lo, hi = u16s(v)
        tags = []
        if v in FOCUS_WORDS:
            tags.append(FOCUS_WORDS[v])
        if v in FOCUS_PTRS:
            tags.append(FOCUS_PTRS[v])
        ct = code_tag(aud, v)
        if ct:
            tags.append(ct)
        if tags or (0xF03BB840 <= a <= 0xF03BB920):
            suffix = " <" + ", ".join(tags) + ">" if tags else ""
            print(f"0x{a:08X}: 0x{v:08X} u16=[{lo:04X},{hi:04X}]{suffix}")
        a += 4

    hline("C. 12-BYTE ROW HYPOTHESIS")
    base_mod = ANCHOR % 12
    for delta in (0, 4, 8):
        phase = (base_mod + delta) % 12
        rows, code, focus, zeroish = score_phase(aud, zimage, phase, REGION_START, REGION_END)
        print(f"phase_mod12={phase}: rows={rows} code_w0={code} focus_rows={focus} zeroish_w2={zeroish}")
    start = ANCHOR - 12 * 8
    print(f"\nCandidate rows anchored at 0x{ANCHOR:08X}:")
    row_dump(aud, zimage, start, 26)

    hline("D. EXACT FOCUS WORD OCCURRENCES")
    for value, label in {**FOCUS_WORDS, **FOCUS_PTRS}.items():
        hits = []
        for img in aud.images:
            hits.extend((img.name, x) for x in find_u32(img, value))
        print(f"{label} 0x{value:08X}: occurrences={len(hits)}")
        for image_name, addr in hits[:40]:
            print(f"  {image_name} 0x{addr:08X}")

    hline("E. RAW POINTERS INTO THE F03BB8XX REGION")
    refs = scan_region_refs(aud)
    print(f"raw_u32_refs_into_region={len(refs)}")
    for image_name, addr, value in refs[:200]:
        print(f"  {image_name} 0x{addr:08X} -> 0x{value:08X}")
        for site, text, lit in inspect_ref_code(aud, addr):
            print(f"    CODE_LITERAL site=0x{site:08X} {text} -> 0x{lit:08X}")
    if len(refs) > 200:
        print("  ... truncated")

    hline("F. FOCUS FUNCTION SEMANTIC PROFILES")
    profiles = {}
    for ptr, label in FOCUS_PTRS.items():
        profiles[label] = dump_profile(aud, label, ptr)

    hline("G. FUNCTION FAMILY SIMILARITY")
    labels = list(profiles)
    for i, a_name in enumerate(labels):
        for b_name in labels[i + 1:]:
            sa = profiles[a_name][4]
            sb = profiles[b_name][4]
            inter = sa & sb
            union = sa | sb
            jac = len(inter) / len(union) if union else 1.0
            print(f"{a_name} vs {b_name}: shared={len(inter)} union={len(union)} jaccard={jac:.4f}")
            if inter and (a_name == "INITPTR_8569" or b_name == "INITPTR_8569"):
                print("  shared:", ", ".join(f"0x{x:08X}" for x in sorted(inter)[:80]))

    hline("H. DECISION GATE")
    pair_8569_hits = []
    init_hits = []
    for img in aud.images:
        pair_8569_hits.extend((img.name, x) for x in find_u32(img, 0x85698569))
        init_hits.extend((img.name, x) for x in find_u32(img, m.INITPTR_8569))
    print(f"0x85698569 occurrences={len(pair_8569_hits)}")
    print(f"0x10348D05 occurrences={len(init_hits)}")
    print(f"candidate_anchor=0x{ANCHOR:08X} row_fn=0x{zimage.read_u32(ANCHOR):08X} row_word1=0x{zimage.read_u32(ANCHOR+4):08X} row_word2=0x{zimage.read_u32(ANCHOR+8):08X}")
    row_8569 = 0xF03BB870
    print(f"8569-pair row candidate @0x{row_8569:08X}: fn=0x{zimage.read_u32(row_8569):08X} keys=0x{zimage.read_u32(row_8569+4):08X} tail=0x{zimage.read_u32(row_8569+8):08X}")
    print()
    if zimage.read_u32(row_8569 + 4) == 0x85698569 and zimage.read_u32(ANCHOR) == m.INITPTR_8569:
        print("FACT: the structured ZIMAGE neighborhood contains consecutive 12-byte candidates with 85698569 and 10348D05 in adjacent rows, not the same row.")
        print("This is stronger evidence that the F03BB8xx structure must be decoded before equating 10348D05 with the 8569 visible role.")
    else:
        print("The 12-byte adjacency hypothesis did not match the expected anchors.")
    if refs:
        print("NEXT: use the recovered pointer/literal owner(s) above to identify the exact consumer and field semantics of the F03BB8xx structure.")
    else:
        print("NEXT: recover the structure owner through neighboring function/data references and stride-consistent scans.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
