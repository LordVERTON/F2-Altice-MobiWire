#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import struct
import s13_5a51_launcher_dispatch_init_trace as m

TITLE = "S13.5A.55 - 1034B644 CONSUMER CALLERS / 0xA0 RECORD SEMANTICS"
CONSUMER = 0x1034B644
BASE = 0xF03BB8F8
STRIDE = 0xA0
HELPER_RESOLVE = 0xF02E67A8
HELPER_RGB2 = 0xF02E1A04
HELPER_PAIR = 0xF022A298
MAX_RECORDS = 16
READ_U8 = (0x00, 0x01, 0x02, 0x08, 0x09, 0x0A)
READ_U16 = (0x04, 0x06, 0x1A, 0x1C, 0x1E, 0x20, 0x22, 0x24, 0x26, 0x30, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x46)
FOCUS_IDS = {0x8569,0x87ED,0x86C0,0x8927,0x8928,0x8923,0x8924,0x8925,0x8929,0x892B}

def hline(s):
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)

def find_u32(img, value):
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    out = []
    p = 0
    while True:
        p = img.data.find(needle, p)
        if p < 0:
            break
        out.append(img.base + p)
        p += 1
    return out

def reverse_direct_calls(aud, target):
    target &= ~1
    out = []
    for img in aud.images:
        pc = img.base & ~1
        end = img.end - 2
        while pc < end:
            x = aud.decode_one(pc)
            if x is not None and x.is_call and x.target is not None:
                norm, via = aud.normalized_target(x.target)
                if norm == target:
                    out.append((img.name, pc, x.target, via))
            pc += 2
    return out

def context(aud, center, before=0x30, after=0x18):
    rows = []
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
                extra.append(f"literal=0x{x.literal_value:08X}")
                s = aud.string_at(x.literal_value)
                if s:
                    extra.append(f'STR="{s}"')
            mark = " <CALL>" if pc == center else ""
            rows.append((pc, x.text, " ".join(extra), mark))
            pc += max(2, x.size)
        else:
            pc += 2
    return rows

def infer_r0_immediate(aud, site, lookback=0x28):
    pc = (site - lookback) & ~1
    last = None
    while pc < site:
        x = aud.decode_one(pc)
        if x is None:
            pc += 2
            continue
        low = x.text.lower()
        if x.is_call:
            last = None
        parts = low.replace(",", " ").split()
        if low.startswith(("movs","mov")) and len(parts) >= 3 and parts[1] == "r0" and parts[2].startswith("#"):
            try:
                last = (pc, int(parts[2][1:], 0))
            except ValueError:
                last = None
        elif len(parts) >= 2 and parts[1] == "r0" and low.startswith(("ldr","ldrb","ldrh","adds","subs","add","sub","muls")):
            last = None
        pc += max(2, x.size)
    return last

def dump_linear_function(aud, start, max_bytes=0x500):
    pc = start & ~1
    end = pc + max_bytes
    count = 0
    while pc < end:
        x = aud.decode_one(pc)
        if x is None:
            print(f"0x{pc:08X}: <decode stop>")
            break
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
        print(f"0x{pc:08X}: {x.text}{suffix}")
        count += 1
        if m.StaticAudit.is_return(x.text):
            print(f"LINEAR_RETURN=0x{pc:08X} insns={count}")
            break
        pc += max(2, x.size)

def helper_profile(aud, root, label):
    funcs, edges, focus, strings = m.callgraph(aud, root, depth=4, max_funcs=180)
    calls = set()
    for fa in funcs.values():
        for _, raw in fa.calls:
            calls.add(aud.normalized_target(raw)[0])
    print(f"{label}: root=0x{root:08X} funcs={len(funcs)} calls={len(calls)} strings={len(strings)} focus={len(focus)}")
    seen = set()
    for entry, site, ptr, s in strings:
        k = (ptr, s)
        if k in seen:
            continue
        seen.add(k)
        print(f'  STR func=0x{entry:08X} site=0x{site:08X} ptr=0x{ptr:08X} "{s}"')
        if len(seen) >= 60:
            break
    return calls

def u16(img, addr):
    b = img.read(addr, 2)
    return b[0] | (b[1] << 8)

def record_summary(zimage, idx):
    base = BASE + idx * STRIDE
    if not zimage.contains(base, STRIDE):
        return None
    u8s = {o: zimage.read(base + o, 1)[0] for o in READ_U8}
    u16s = {o: u16(zimage, base + o) for o in READ_U16}
    return base, u8s, u16s

def print_record(zimage, idx):
    rec = record_summary(zimage, idx)
    if rec is None:
        return
    base, b, h = rec
    rgb0 = tuple(b[o] for o in (0,1,2))
    rgb1 = tuple(b[o] for o in (8,9,10))
    focus = [(o,v) for o,v in h.items() if v in FOCUS_IDS]
    print(f"record[{idx:02d}] base=0x{base:08X} rgb0={rgb0} rgb1={rgb1}")
    print("  u16:", " ".join(f"+0x{o:02X}=0x{h[o]:04X}" for o in READ_U16))
    if focus:
        print("  FOCUS:", " ".join(f"+0x{o:02X}=0x{v:04X}" for o,v in focus))

def occurrences_in_records(zimage, wanted):
    out = []
    for idx in range(MAX_RECORDS):
        base = BASE + idx * STRIDE
        if not zimage.contains(base, STRIDE):
            break
        for off in range(0, STRIDE - 1, 2):
            v = u16(zimage, base + off)
            if v in wanted:
                out.append((idx, off, v))
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

    hline("B. FULL LINEAR CONSUMER 0x1034B644")
    dump_linear_function(aud, CONSUMER)

    hline("C. REVERSE DIRECT CALLERS OF 0x1034B644")
    callers = reverse_direct_calls(aud, CONSUMER)
    print(f"direct_callers={len(callers)}")
    inferred = []
    for image_name, site, raw, via in callers:
        imm = infer_r0_immediate(aud, site)
        print(f"{image_name} callsite=0x{site:08X} raw=0x{raw:08X} via={via or 'DIRECT'} r0_immediate={imm[1] if imm else 'UNKNOWN'}")
        if imm:
            inferred.append((site, imm[1]))
        for addr, text, extra, mark in context(aud, site):
            suffix = (" ; " + extra) if extra else ""
            print(f"  0x{addr:08X}: {text}{suffix}{mark}")

    hline("D. POINTER OCCURRENCES OF CONSUMER")
    for value in (CONSUMER | 1, CONSUMER):
        hits = []
        for img in aud.images:
            hits.extend((img.name, a) for a in find_u32(img, value))
        print(f"ptr=0x{value:08X} occurrences={len(hits)}")
        for image_name, addr in hits:
            print(f"  {image_name} 0x{addr:08X}")

    hline("E. 0xA0 RECORD SUMMARIES")
    for idx in range(MAX_RECORDS):
        if not zimage.contains(BASE + idx * STRIDE, STRIDE):
            break
        print_record(zimage, idx)

    hline("F. FOCUS ID OCCURRENCES WITHIN 0xA0 RECORDS")
    occ = occurrences_in_records(zimage, FOCUS_IDS)
    print(f"focus_occurrences={len(occ)}")
    for idx, off, value in occ:
        print(f"record[{idx:02d}] +0x{off:02X} = 0x{value:04X}")

    hline("G. HELPER SEMANTIC PROFILES")
    helper_profile(aud, HELPER_RESOLVE, "HELPER_F02E67A8")
    helper_profile(aud, HELPER_RGB2, "HELPER_F02E1A04")
    helper_profile(aud, HELPER_PAIR, "HELPER_F022A298")

    hline("H. HELPER REVERSE CALL COUNTS")
    for root, label in ((HELPER_RESOLVE,"F02E67A8"),(HELPER_RGB2,"F02E1A04"),(HELPER_PAIR,"F022A298")):
        rows = reverse_direct_calls(aud, root)
        print(f"{label} direct_callers={len(rows)}")
        for image_name, site, raw, via in rows[:50]:
            print(f"  {image_name} 0x{site:08X}")
        if len(rows) > 50:
            print("  ... truncated")

    hline("I. LOCAL 0x89xx DIFFERENTIAL")
    for idx in range(min(MAX_RECORDS,12)):
        rec = record_summary(zimage, idx)
        if rec is None:
            continue
        _, _, h = rec
        fields = [(o,v) for o,v in h.items() if 0x8900 <= v <= 0x89FF]
        print(f"record[{idx:02d}] 89xx_fields=" + (", ".join(f"+0x{o:02X}=0x{v:04X}" for o,v in fields) if fields else "NONE"))

    hline("J. DECISION GATE")
    uniq_imm = sorted({v for _,v in inferred})
    print(f"caller_immediate_indexes={uniq_imm if uniq_imm else 'NONE'}")
    print(f"base=0x{BASE:08X} stride=0x{STRIDE:X}")
    print("consumer computes r4 = base + r0*0xA0, then reads byte triplets and many 16-bit fields.")
    print("record0 contains 0x8927 at +0x04 and 0x8928 at +0x06.")
    if callers:
        print("FACT: 0x1034B644 is a real indexed consumer of a 0xA0-byte record array rooted at F03BB8F8.")
        print("This supersedes interpreting F03BB8F8 itself as a 12-byte launcher-row pointer.")
    if any(v in range(0,9) for v in uniq_imm):
        print("SUPPORTED: callers provide small record indexes, consistent with profile/style/theme selection rather than app-ID dispatch.")
    if occ:
        print("The 0x89xx values must be classified through helper F02E67A8 and caller context before treating them as launcher IDs.")
    print("NEXT: trace the strongest caller(s) of 1034B644 and classify helper F02E67A8 return semantics; if this is UI/theme data, pivot away from F03BB8xx and back to the 86C0/8928 registry/owner path.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
