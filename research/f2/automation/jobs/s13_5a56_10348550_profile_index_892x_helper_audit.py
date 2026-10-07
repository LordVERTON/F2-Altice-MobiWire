#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import struct
from collections import defaultdict
import s13_5a51_launcher_dispatch_init_trace as m

TITLE = "S13.5A.56 - 10348550 CALLER / PROFILE-INDEX AND 892X HELPER AUDIT"

APPLY_PROFILE = 0x10348550
A0_CONSUMER = 0x1034B644
RESOLVE_892X = 0xF02E67A8
CACHE_GLOBAL = 0xF00E29E8
FOCUS_892X = tuple(range(0x8920, 0x8930))


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


def find_u16(img, value):
    needle = struct.pack("<H", value & 0xFFFF)
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


def dump_context(aud, center, before=0x50, after=0x28):
    pc = (center - before) & ~1
    end = center + after
    while pc < end:
        x = aud.decode_one(pc)
        if x is None:
            pc += 2
            continue
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            extra.append(f"target=0x{norm:08X}" + (f"[{via}]" if via else ""))
        if x.literal_value is not None:
            extra.append(f"literal@0x{x.literal_addr:08X}=0x{x.literal_value:08X}")
            s = aud.string_at(x.literal_value)
            if s:
                extra.append(f'STR="{s}"')
        mark = " <FOCUS>" if pc == center else ""
        suffix = (" ; " + " ".join(extra)) if extra else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{mark}")
        pc += max(2, x.size)


def dump_linear(aud, start, max_bytes=0x300):
    pc = start & ~1
    end = pc + max_bytes
    n = 0
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
        n += 1
        if m.StaticAudit.is_return(x.text):
            print(f"LINEAR_RETURN=0x{pc:08X} insns={n}")
            break
        pc += max(2, x.size)


def backslice_arg(aud, site, reg, lookback=0x50):
    """
    Very small mechanical backward scan. It does not claim full dataflow.
    It reports the nearest obvious write to the requested argument register
    without crossing another direct call.
    """
    insns = []
    pc = (site - lookback) & ~1
    while pc < site:
        x = aud.decode_one(pc)
        if x is not None:
            insns.append(x)
            pc += max(2, x.size)
        else:
            pc += 2

    for x in reversed(insns):
        low = x.text.lower()
        if x.is_call:
            return ("CALL_BARRIER", x.addr, x.text)
        parts = low.replace(",", " ").replace("[", " ").split()
        if len(parts) < 2:
            continue
        if parts[1] != reg:
            continue
        if low.startswith(("movs", "mov", "ldrb", "ldrh", "ldr", "adds", "add", "subs", "sub")):
            return ("WRITE", x.addr, x.text)
    return ("UNKNOWN", None, "")


def helper_signature(aud, root):
    fa = aud.audit_func(root, max_span=0x500, max_insns=700)
    print(f"root=0x{root:08X} image={fa.image} insns={len(fa.insns)} calls={len(fa.calls)} literals={len(fa.literals)} truncated={fa.truncated}")
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


def u16_context(img, addr, radius=0x10):
    lo = max(img.base, addr - radius)
    hi = min(img.end, addr + radius + 2)
    a = lo & ~1
    while a + 2 <= hi:
        v = int.from_bytes(img.read(a, 2), "little")
        mark = " <HIT>" if a == addr else ""
        print(f"    0x{a:08X}: 0x{v:04X}{mark}")
        a += 2


def main():
    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    if os.environ.get("F2_AUTOMATION_OFFLINE") != "1":
        raise SystemExit("offline automation marker missing")

    hline("A. CANONICAL IMAGE GUARDS")
    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    hline("B. APPLY-PROFILE FUNCTION 0x10348550")
    dump_linear(aud, APPLY_PROFILE, max_bytes=0x180)

    hline("C. DIRECT CALLERS OF 0x10348550")
    callers = reverse_direct_calls(aud, APPLY_PROFILE)
    print(f"direct_callers={len(callers)}")
    for image_name, site, raw, via in callers:
        print(f"{image_name} callsite=0x{site:08X} raw=0x{raw:08X} via={via or 'DIRECT'}")
        for reg in ("r0", "r1", "r2", "r3"):
            print(f"  {reg}: {backslice_arg(aud, site, reg)}")
        dump_context(aud, site)

    hline("D. POINTER OCCURRENCES OF APPLY-PROFILE")
    for value in (APPLY_PROFILE, APPLY_PROFILE | 1):
        hits = []
        for img in aud.images:
            hits.extend((img.name, a) for a in find_u32(img, value))
        print(f"ptr=0x{value:08X} occurrences={len(hits)}")
        for image_name, addr in hits:
            print(f"  {image_name} 0x{addr:08X}")

    hline("E. A0-CONSUMER CALL CHAIN CONFIRMATION")
    rows = reverse_direct_calls(aud, A0_CONSUMER)
    print(f"direct_callers_of_1034B644={len(rows)}")
    for image_name, site, raw, via in rows:
        print(f"  {image_name} 0x{site:08X}")
        dump_context(aud, site, before=0x20, after=0x20)

    hline("F. HELPER F02E67A8 FULL STATIC SIGNATURE")
    helper_signature(aud, RESOLVE_892X)

    hline("G. DIRECT CALLERS OF HELPER NEAR AUDIO REGISTRY CODE")
    helper_calls = reverse_direct_calls(aud, RESOLVE_892X)
    print(f"helper_direct_callers={len(helper_calls)}")
    for image_name, site, raw, via in helper_calls:
        if image_name == "ALICE" and (0x1033D000 <= site < 0x10341000):
            print(f"ALICE 0x{site:08X}")
            dump_context(aud, site, before=0x18, after=0x10)

    hline("H. 0x8920..0x892F EXACT U16 OCCURRENCES")
    total = 0
    for value in FOCUS_892X:
        hits = []
        for img in aud.images:
            for addr in find_u16(img, value):
                hits.append((img.name, addr))
        print(f"0x{value:04X}: occurrences={len(hits)}")
        total += len(hits)
        for image_name, addr in hits[:24]:
            print(f"  {image_name} 0x{addr:08X}")
        if len(hits) > 24:
            print("  ... truncated")
    print(f"total_892x_occurrences={total}")

    hline("I. LOCAL CONTEXT FOR 8927 / 8928 / 8923 / 8925 / 892B")
    for value in (0x8923, 0x8925, 0x8927, 0x8928, 0x892B):
        print(f"\nVALUE 0x{value:04X}")
        shown = 0
        for img in aud.images:
            for addr in find_u16(img, value):
                if shown >= 12:
                    break
                print(f"  {img.name} hit=0x{addr:08X}")
                u16_context(img, addr, radius=0x0C)
                shown += 1
            if shown >= 12:
                break

    hline("J. DECISION GATE")
    print(f"apply_profile_callers={len(callers)}")
    print(f"a0_consumer_callers={len(rows)}")
    print("Known internal flow: 10348550 copies incoming r3 to r5, then passes r5 as r0 to 1034B644 when cached profile differs.")
    if len(rows) == 1 and rows[0][1] == 0x10348570:
        print("FACT: 10348550 is the unique direct parent of the 0xA0-record consumer.")
    if callers:
        print("NEXT: use the caller contexts above to classify incoming r3 (profile/theme/style index vs application identifier).")
    else:
        print("NEXT: recover indirect/pointer callers of 10348550.")
    print("If r3 is proven to be a UI/profile index and F02E67A8 resolves resource identifiers, close the F03BB8xx branch as non-launcher evidence and pivot back to 86C0/8928 owner/registry semantics.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
