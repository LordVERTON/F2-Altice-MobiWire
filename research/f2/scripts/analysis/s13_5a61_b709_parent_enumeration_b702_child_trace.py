#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.61 - B709 visible-parent enumeration -> B702 child trace

STRICTLY OFFLINE.
Reads only canonical extracted firmware images from the local repository.
No USB/COM/BROM/DA/device access. No flash write/erase/repack/patch.

A.60 ruled out the simple MOVS #0xB7 / shift / add construction of B702.
The stronger model is now that B702 is obtained dynamically as one of the
nine children of B709.

This gate:
  - revalidates the B709 record and derives the exact B702 child-slot address;
  - finds every code owner that materializes B709;
  - classifies those owners for record lookup / child-count / child-pointer use;
  - traces B709 through the common registry/menu helpers;
  - looks for a loop that consumes B709.children and therefore obtains B702
    without ever materializing 0xB702 as a code constant.

Output:
research/f2/work/reports/s13_5a61_b709_parent_enumeration_b702_child_trace.txt
"""

from __future__ import annotations

import re
import struct
import sys
import traceback
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path

TITLE = "S13.5A.61 - B709 PARENT ENUMERATION -> B702 CHILD TRACE"

# Canonical registry facts.
REG_RECORD_BASE = 0xF0378760
REG_RECORD_STRIDE = 0x10
DENSE_B709 = 891
B709_RECORD = REG_RECORD_BASE + DENSE_B709 * REG_RECORD_STRIDE

B709 = 0xB709
B702 = 0xB702
EXPECTED_B709_CHILDREN = [0xB702, 0xAF2A, 0xB707, 0x8321, 0xB6FE, 0xB6FD, 0x9639, 0xB700, 0xB705]

# Helpers repeatedly seen in the B70x / menu-registration family.
FOCUS_CALLS = {
    0xF02D53DC: "F02D53DC",
    0xF02AE4E4: "F02AE4E4",
    0xF03002A0: "F03002A0",
    0x10318848: "10318848",
    0x10319094: "ROOT_MAPPER",
    0xF02AE864: "F02AE864",
    0xF02E5C9C: "F02E5C9C",
    0x10317C58: "10317C58",
    0x1031F81C: "1031F81C",
}

MEM_RE = re.compile(
    r"\[(?P<base>r(?:1[0-2]|[0-9])|sp|lr)"
    r"(?:,\s*#(?P<off>-?(?:0x[0-9a-f]+|\d+)))?\]",
    re.I,
)


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)
            s.flush()
        return len(data)

    def flush(self):
        for s in self.streams:
            s.flush()


def hline(s):
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def u16(img, addr):
    b = img.read(addr, 2)
    return b[0] | (b[1] << 8)


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


def parse_mem(text):
    m = MEM_RE.search(text.lower())
    if not m:
        return None
    raw = m.group("off")
    return m.group("base").lower(), (int(raw, 0) if raw is not None else 0)


def candidate_entries(aud, site, back=0x360):
    img = aud.image_for(site)
    if img is None:
        return []
    start = max(img.base, site - back) & ~1
    rows = []
    seen = set()
    pc = start
    while pc <= site:
        x = aud.decode_one(pc)
        if x is not None:
            low = x.text.lower()
            if low.startswith("push") and "lr" in low:
                fa = aud.audit_func(pc, max_span=0x1800, max_insns=2000)
                if site in fa.insns and pc not in seen:
                    seen.add(pc)
                    rows.append((pc, fa))
        pc += 2
    rows.sort(key=lambda row: (site - row[0], row[0]))
    return rows


def normalized_calls(aud, fa):
    out = []
    for site, raw in fa.calls:
        norm, via = aud.normalized_target(raw)
        out.append((site, norm, raw, via))
    return out


def function_strings(aud, fa):
    out = []
    seen = set()
    for _, _, value in fa.literals:
        s = aud.string_at(value)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def context(aud, center, before=0x40, after=0x80, mark="FOCUS"):
    img = aud.image_for(center)
    if img is None:
        return
    pc = max(img.base, center - before) & ~1
    end = min(img.end, center + after)
    while pc < end:
        x = aud.decode_one(pc)
        if x is None:
            pc += 2
            continue
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            label = FOCUS_CALLS.get(norm)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{label}>" if label else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            extra.append(f"literal=0x{x.literal_value:08X}")
            s = aud.string_at(x.literal_value)
            if s:
                extra.append(f'STR="{s}"')
        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = f" <{mark}>" if pc == center else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{flag}")
        pc += max(2, x.size)


def reverse_direct_calls(aud, targets):
    targets = {t & ~1 for t in targets}
    out = {t: [] for t in targets}
    for img in aud.images:
        pc = img.base & ~1
        end = img.end - 2
        while pc < end:
            x = aud.decode_one(pc)
            if x is not None and x.is_call and x.target is not None:
                norm, via = aud.normalized_target(x.target)
                if norm in targets:
                    out[norm].append((img.name, pc, x.target, via))
            pc += 2
    return out


def b709_literal_sites(aud):
    out = []
    for img in aud.images:
        pc = img.base & ~1
        end = img.end - 2
        while pc < end:
            x = aud.decode_one(pc)
            if x is not None and x.literal_value == B709:
                out.append((img.name, pc, x.literal_addr, x.text))
            pc += 2
    return out


def memory_profile(fa):
    rows = []
    for addr, x in fa.insns.items():
        mem = parse_mem(x.text)
        if not mem:
            continue
        base, off = mem
        low = x.text.lower()
        if off in (0, 2, 0xC):
            rows.append((addr, low.split()[0], base, off, x.text))
    return sorted(rows)


def loop_profile(fa):
    loops = []
    for addr, x in fa.insns.items():
        if x.is_jump and x.target is not None and (x.target & ~1) < addr:
            loops.append((addr, x.target & ~1, x.text))
    return sorted(loops)


def local_flow_after_b709(aud, fa, site, span=0x180):
    """
    Print a bounded straight/CFG-agnostic window after the B709 materialization.
    Also summarize calls and record-style memory accesses appearing nearby.
    """
    end = site + span
    calls = []
    mems = []
    for addr in sorted(a for a in fa.insns if site <= a <= end):
        x = fa.insns[addr]
        if x.is_call and x.target is not None:
            norm, via = aud.normalized_target(x.target)
            calls.append((addr, norm, via))
        mem = parse_mem(x.text)
        if mem and mem[1] in (0, 2, 0xC):
            mems.append((addr, x.text))
    return calls, mems


def main_body():
    repo = Path.cwd().resolve()
    helper = repo / "research/f2/automation/jobs/s13_5a51_launcher_dispatch_init_trace.py"
    if not helper.is_file():
        raise SystemExit(
            "Run from C:\\Users\\verto\\F2-Altice-MobiWire so the canonical A.51 helper is available."
        )

    sys.path.insert(0, str(helper.parent))
    import s13_5a51_launcher_dispatch_init_trace as m

    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE: local firmware reads only.")

    hline("A. CANONICAL IMAGE GUARDS")
    print(f"ALICE size=0x{len(alice.data):X} sha256={m.sha256(alice.data)}")
    print(f"ZIMAGE size=0x{len(zimage.data):X} sha256={m.sha256(zimage.data)}")
    print("Canonical A.51 loader = PASS")

    hline("B. B709 RECORD / CHILD ARRAY GROUND TRUTH")
    print(f"B709 record = 0x{B709_RECORD:08X}")
    parent = u16(zimage, B709_RECORD + 0)
    count = u16(zimage, B709_RECORD + 2)
    child_ptr = zimage.read_u32(B709_RECORD + 0xC)
    children = [u16(zimage, child_ptr + i * 2) for i in range(count)]

    print(f"B709.parent      = 0x{parent:04X}")
    print(f"B709.child_count = {count}")
    print(f"B709.child_ptr   = 0x{child_ptr:08X}")
    print("B709.children:")
    for i, value in enumerate(children):
        print(f"  [{i}] addr=0x{child_ptr + i*2:08X} id=0x{value:04X}")

    if children != EXPECTED_B709_CHILDREN:
        raise RuntimeError(
            "B709 child list no longer matches canonical S13 state: "
            + repr([hex(x) for x in children])
        )

    b702_slot = child_ptr
    print(f"B702 slot inside B709.children = 0x{b702_slot:08X}")
    print("B709 registry regression = PASS")

    hline("C. RAW 0xB702 OCCURRENCES AND B709 CHILD SLOT")
    for img in aud.images:
        hits = find_u16(img, B702)
        print(f"{img.name}: raw_u16_B702_occurrences={len(hits)}")
        for addr in hits[:80]:
            mark = " <B709_CHILD_SLOT>" if addr == b702_slot else ""
            print(f"  0x{addr:08X}{mark}")
        if len(hits) > 80:
            print("  ... truncated")

    hline("D. DIRECT POINTER/XREF CHECKS FOR B709 CHILD ARRAY")
    for value, label in ((child_ptr, "B709_CHILD_PTR"), (B709_RECORD, "B709_RECORD")):
        hits = []
        for img in aud.images:
            hits.extend((img.name, a) for a in find_u32(img, value))
        print(f"{label} 0x{value:08X}: raw_u32_occurrences={len(hits)}")
        for image_name, addr in hits[:80]:
            print(f"  {image_name} 0x{addr:08X}")
        if len(hits) > 80:
            print("  ... truncated")

    hline("E. ALL B709 LITERAL OWNERS")
    sites = b709_literal_sites(aud)
    print(f"B709_literal_loads={len(sites)}")

    owners = {}
    provenance = defaultdict(list)
    for image_name, site, litaddr, text in sites:
        print(f"\n{image_name} B709 load site=0x{site:08X} pool=0x{litaddr:08X} {text}")
        context(aud, site, before=0x48, after=0xA0, mark="B709_LOAD")
        entries = candidate_entries(aud, site)
        print(f"  enclosing_candidates={len(entries)}")
        for entry, fa in entries[:3]:
            owners.setdefault(entry, fa)
            provenance[entry].append(site)
            print(
                f"    entry=0x{entry:08X} image={fa.image} "
                f"insns={len(fa.insns)} calls={len(fa.calls)}"
            )

    hline("F. B709 OWNER FUNCTION CLASSIFICATION")
    ranked = []
    for entry, fa in owners.items():
        calls = normalized_calls(aud, fa)
        targets = {norm for _, norm, _, _ in calls}
        mem = memory_profile(fa)
        loops = loop_profile(fa)
        strings = function_strings(aud, fa)

        focus = sorted(targets & set(FOCUS_CALLS))
        has_count = any(op.startswith("ldrh") and off == 2 for _, op, base, off, text in mem)
        has_child = any(op == "ldr" and off == 0xC for _, op, base, off, text in mem)
        score = len(focus) * 5 + (8 if has_count else 0) + (10 if has_child else 0) + (5 if loops else 0)

        ranked.append(
            {
                "score": score,
                "entry": entry,
                "fa": fa,
                "targets": targets,
                "focus": focus,
                "mem": mem,
                "loops": loops,
                "strings": strings,
                "has_count": has_count,
                "has_child": has_child,
            }
        )

    ranked.sort(key=lambda r: (-r["score"], r["entry"]))

    for r in ranked:
        print(
            f"entry=0x{r['entry']:08X} image={r['fa'].image} score={r['score']} "
            f"insns={len(r['fa'].insns)} calls={len(r['fa'].calls)} "
            f"count(+2)={r['has_count']} childptr(+0xC)={r['has_child']} loops={len(r['loops'])}"
        )
        if r["focus"]:
            print(
                "  FOCUS_CALLS:",
                ", ".join(f"0x{x:08X}<{FOCUS_CALLS[x]}>" for x in r["focus"])
            )
        if r["mem"]:
            for addr, op, base, off, text in r["mem"][:40]:
                print(f"  MEM 0x{addr:08X}: {text}")
        if r["loops"]:
            for addr, target, text in r["loops"][:20]:
                print(f"  LOOP 0x{addr:08X} -> 0x{target:08X}: {text}")
        for s in r["strings"][:20]:
            print(f'  STR "{s}"')
        print("  B709_LOADS:", ", ".join(f"0x{x:08X}" for x in provenance[r["entry"]]))

    hline("G. B709 LOAD -> LOCAL CALL/MEMORY FLOW")
    for r in ranked:
        fa = r["fa"]
        for site in provenance[r["entry"]]:
            calls, mems = local_flow_after_b709(aud, fa, site)
            print(f"\nowner=0x{r['entry']:08X} B709_site=0x{site:08X}")
            for addr, norm, via in calls:
                label = FOCUS_CALLS.get(norm)
                print(
                    f"  CALL 0x{addr:08X} -> 0x{norm:08X}"
                    + (f"<{label}>" if label else "")
                    + (f"[{via}]" if via else "")
                )
            for addr, text in mems:
                print(f"  MEM  0x{addr:08X}: {text}")

    hline("H. REVERSE CALLERS OF TOP B709 OWNERS")
    top = [r["entry"] for r in ranked[:12]]
    reverse = reverse_direct_calls(aud, top) if top else {}
    for target in top:
        rows = reverse.get(target & ~1, [])
        print(f"\nTARGET 0x{target:08X}: direct_callers={len(rows)}")
        for image_name, site, raw, via in rows[:50]:
            print(f"  {image_name} callsite=0x{site:08X} via={via or 'DIRECT'}")
            context(aud, site, before=0x30, after=0x28, mark="OWNER_CALL")
        if len(rows) > 50:
            print("  ... truncated")

    hline("I. B709 OWNERS THAT LOOK LIKE CHILD ENUMERATORS")
    strong = [
        r for r in ranked
        if r["has_count"] and r["has_child"] and r["loops"]
    ]
    print(f"strong_B709_child_enumerators={len(strong)}")
    for r in strong:
        print(
            f"  0x{r['entry']:08X} score={r['score']} "
            f"focus={','.join(FOCUS_CALLS[x] for x in r['focus']) if r['focus'] else 'NONE'}"
        )

    hline("J. DECISION GATE")
    print(f"B709_literal_loads={len(sites)}")
    print(f"B709_owner_functions={len(ranked)}")
    print(f"B709_child_ptr=0x{child_ptr:08X}")
    print(f"B702_runtime_slot=0x{b702_slot:08X}")
    print(f"strong_B709_child_enumerators={len(strong)}")

    if strong:
        best = strong[0]
        print(
            f"RESULT: leading B709 child-enumerator owner = 0x{best['entry']:08X}."
        )
        print(
            "This path can obtain B702 dynamically from B709.children without "
            "any B702 code literal."
        )
        print(
            "NEXT: trace the selected child ID from B709.children through this "
            "owner into the visible node/action builder and compare slot 0 "
            "(B702) with the sibling slots."
        )
    elif ranked:
        best = ranked[0]
        print(
            f"RESULT: no single B709 literal owner simultaneously proves count/"
            f"child-pointer/loop access. Best owner = 0x{best['entry']:08X}."
        )
        print(
            "NEXT: follow its focus helper calls one function boundary; the "
            "actual enumeration is probably delegated to a generic helper."
        )
    else:
        print("RESULT: no B709 literal owner function was recovered.")
        print(
            "NEXT: trace the B709 record through the generic parent mapper and "
            "the static child array pointer instead of literal owners."
        )

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a61_b709_parent_enumeration_b702_child_trace.txt"
    report.parent.mkdir(parents=True, exist_ok=True)

    with report.open("w", encoding="utf-8", newline="\n") as fp:
        tee = Tee(sys.stdout, fp)
        with redirect_stdout(tee):
            try:
                main_body()
                print()
                print("=" * 120)
                print("EXIT CODE = 0")
                print("=" * 120)
                return 0
            except Exception:
                print()
                print("=" * 120)
                print("EXCEPTION")
                print("=" * 120)
                traceback.print_exc(file=tee)
                print()
                print("EXIT CODE = 1")
                return 1


if __name__ == "__main__":
    raise SystemExit(main())
