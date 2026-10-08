#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.58 - B702 visible/menu builder consumer trace

STRICTLY OFFLINE.
Reads only canonical extracted firmware images from the local repository.
No USB/COM/BROM/DA/device access. No flash write/erase/repack/patch.

Purpose:
  After A.57 established the role split
      86C0 = Audio-domain owner/browser/helper (strongly supported)
      8928 = confirmed native Audio Player application
  trace the static consumers of the B702 registry/enumeration structure and
  isolate the code that turns B702.children into a visible/menu representation.

The script writes:
  research/f2/work/reports/s13_5a58_b702_visible_builder_consumer_trace.txt
"""

from __future__ import annotations

import re
import struct
import sys
import traceback
from pathlib import Path
from contextlib import redirect_stdout


TITLE = "S13.5A.58 - B702 VISIBLE / MENU BUILDER CONSUMER TRACE"

# Canonical registry model recovered in S13.
REG_DESCRIPTOR = 0xF037C08C
REG_RECORD_BASE = 0xF0378760
REG_RANGE_BASE = 0xF037BF54
REG_RANGE_COUNT = 52
REG_RECORD_COUNT = 895
REG_RECORD_STRIDE = 0x10

B702 = 0xB702
B709 = 0xB709
ID_8569 = 0x8569
ID_87ED = 0x87ED
ID_86C0 = 0x86C0
ID_8928 = 0x8928

DENSE_B702 = 884
DENSE_B709 = 891
DENSE_8928 = 490

B702_RECORD = REG_RECORD_BASE + DENSE_B702 * REG_RECORD_STRIDE
B709_RECORD = REG_RECORD_BASE + DENSE_B709 * REG_RECORD_STRIDE
R8928_RECORD = REG_RECORD_BASE + DENSE_8928 * REG_RECORD_STRIDE
B702_CHILDREN = 0xF0378720

ROOT_MAPPER = 0x10319094

FOCUS_VALUES = {
    REG_DESCRIPTOR: "REG_DESCRIPTOR",
    REG_RECORD_BASE: "REG_RECORD_BASE",
    REG_RANGE_BASE: "REG_RANGE_BASE",
    B702_RECORD: "B702_RECORD",
    B709_RECORD: "B709_RECORD",
    R8928_RECORD: "8928_RECORD",
    B702_CHILDREN: "B702_CHILDREN",
    B702: "ID_B702",
    B709: "ID_B709",
    ID_8569: "ID_8569",
    ID_87ED: "ID_87ED",
    ID_86C0: "ID_86C0",
    ID_8928: "ID_8928",
}


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


def scan_literal_loads(aud, values):
    """Mechanical Thumb literal-load scan for exact 32-bit values."""
    wanted = set(values)
    out = []
    for img in aud.images:
        pc = img.base & ~1
        end = img.end - 2
        while pc < end:
            x = aud.decode_one(pc)
            if x is not None and x.literal_value in wanted:
                out.append((img.name, x.addr, x.literal_addr, x.literal_value, x.text))
            pc += 2
    return out


def candidate_entries(aud, site, back=0x300):
    """
    Find nearby Thumb PUSH {...,lr} candidates whose audited CFG contains site.
    This is deliberately conservative; multiple candidates are retained.
    """
    img = aud.image_for(site)
    if img is None:
        return []
    start = max(img.base, site - back) & ~1
    pc = start
    candidates = []
    seen = set()
    while pc <= site:
        x = aud.decode_one(pc)
        if x is not None:
            low = x.text.lower()
            if low.startswith("push") and "lr" in low:
                fa = aud.audit_func(pc, max_span=0x1200, max_insns=1400)
                if site in fa.insns and pc not in seen:
                    seen.add(pc)
                    candidates.append((pc, fa))
        pc += 2
    candidates.sort(key=lambda row: (site - row[0], row[0]))
    return candidates


def normalize_calls(aud, fa):
    out = set()
    for _, raw in fa.calls:
        out.add(aud.normalized_target(raw)[0])
    return out


def literal_map(fa):
    out = {}
    for site, litaddr, value in fa.literals:
        out.setdefault(value, []).append((site, litaddr))
    return out


def has_mem_offset(fa, off):
    # Match an exact immediate memory offset, e.g. [r4,#2] or [r4,#0xc].
    dec = str(off)
    hx = f"0x{off:x}"
    rx = re.compile(r"\[[^\]]+,\s*#(?:" + re.escape(dec) + "|" + re.escape(hx) + r")\]")
    for x in fa.insns.values():
        if rx.search(x.text.lower()):
            return True
    return False


def func_features(aud, entry, fa):
    calls = normalize_calls(aud, fa)
    lits = literal_map(fa)
    texts = [x.text.lower() for x in fa.insns.values()]
    strings = []
    for _, _, value in fa.literals:
        s = aud.string_at(value)
        if s and s not in strings:
            strings.append(s)

    features = {
        "entry": entry,
        "image": fa.image,
        "insns": len(fa.insns),
        "calls": calls,
        "lits": lits,
        "strings": strings,
        "count_off_2": has_mem_offset(fa, 2),
        "childptr_off_c": has_mem_offset(fa, 0xC),
        "parent_off_0": any(
            ("ldrh" in t or t.startswith("ldr")) and re.search(r"\[[^\]]+\]", t)
            for t in texts
        ),
        "root_mapper": ROOT_MAPPER in calls,
        "adds_2": any(
            re.search(r"\b(?:adds|add)\b.*#(?:2|0x2)\b", t) for t in texts
        ),
        "loopish": any(
            t.startswith(("bne", "beq", "bcc", "bcs", "blo", "bhi", "bls", "bgt", "blt", "ble", "bge"))
            for t in texts
        ),
    }

    score = 0
    weights = {
        B702_CHILDREN: 8,
        B702_RECORD: 7,
        REG_DESCRIPTOR: 5,
        REG_RECORD_BASE: 5,
        REG_RANGE_BASE: 3,
        B702: 5,
        ID_86C0: 2,
        ID_8928: 2,
        ID_8569: 2,
        ID_87ED: 2,
    }
    for value, weight in weights.items():
        if value in lits:
            score += weight
    if features["count_off_2"]:
        score += 5
    if features["childptr_off_c"]:
        score += 7
    if features["count_off_2"] and features["childptr_off_c"]:
        score += 8
    if features["root_mapper"]:
        score += 2
    if features["adds_2"]:
        score += 2
    if features["loopish"]:
        score += 1

    features["score"] = score
    return features


def dump_function_summary(aud, feat):
    print(
        f"entry=0x{feat['entry']:08X} image={feat['image']} "
        f"score={feat['score']} insns={feat['insns']} calls={len(feat['calls'])} "
        f"count+2={feat['count_off_2']} childptr+0xC={feat['childptr_off_c']} "
        f"root_mapper={feat['root_mapper']} loopish={feat['loopish']}"
    )
    focus = []
    for value, rows in feat["lits"].items():
        if value in FOCUS_VALUES:
            focus.append((value, FOCUS_VALUES[value], rows))
    for value, label, rows in sorted(focus):
        sites = ", ".join(f"0x{x[0]:08X}" for x in rows[:12])
        print(f"  LIT {label} 0x{value:08X}: {sites}")
    if feat["strings"]:
        for s in feat["strings"][:20]:
            print(f'  STR "{s}"')
    if feat["calls"]:
        print("  CALLS:", ", ".join(f"0x{x:08X}" for x in sorted(feat["calls"])[:60]))


def dump_context(aud, center, before=0x30, after=0x28, mark="FOCUS"):
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
            label = FOCUS_VALUES.get(x.literal_value)
            extra.append(f"literal=0x{x.literal_value:08X}" + (f"<{label}>" if label else ""))
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


def main_body():
    repo = Path.cwd().resolve()
    helper = repo / "research/f2/automation/jobs/s13_5a51_launcher_dispatch_init_trace.py"
    if not helper.is_file():
        raise SystemExit(
            "Run this script from C:\\Users\\verto\\F2-Altice-MobiWire "
            "(canonical repository root)."
        )

    sys.path.insert(0, str(helper.parent))
    import s13_5a51_launcher_dispatch_init_trace as m

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE: local firmware reads only; no phone/device access.")

    hline("A. CANONICAL IMAGE GUARDS")
    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    hline("B. REGISTRY GROUND TRUTH")
    print(f"descriptor       = 0x{REG_DESCRIPTOR:08X}")
    print(f"record_base      = 0x{REG_RECORD_BASE:08X}")
    print(f"range_base       = 0x{REG_RANGE_BASE:08X}")
    print(f"range_count      = {REG_RANGE_COUNT}")
    print(f"record_count     = {REG_RECORD_COUNT}")
    print(f"record_stride    = 0x{REG_RECORD_STRIDE:X}")
    print(f"B702 dense       = {DENSE_B702}")
    print(f"B702 record      = 0x{B702_RECORD:08X}")
    print(f"B702 children    = 0x{B702_CHILDREN:08X}")

    parent = u16(zimage, B702_RECORD + 0x00)
    count = u16(zimage, B702_RECORD + 0x02)
    child_ptr = zimage.read_u32(B702_RECORD + 0x0C)
    print(f"B702.record.parent     = 0x{parent:04X}")
    print(f"B702.record.child_count= {count}")
    print(f"B702.record.child_ptr  = 0x{child_ptr:08X}")
    children = [u16(zimage, child_ptr + i * 2) for i in range(count)]
    print("B702.children          = [" + ", ".join(f"0x{x:04X}" for x in children) + "]")

    if parent != B709 or count != 2 or child_ptr != B702_CHILDREN or children != [ID_8569, ID_87ED]:
        raise RuntimeError("Canonical B702 registry facts do not match expected S13 state.")
    print("B702 registry regression = PASS")

    hline("C. EXACT RAW U32 OCCURRENCES OF REGISTRY ANCHORS")
    for value, label in FOCUS_VALUES.items():
        if value <= 0xFFFF:
            continue
        hits = []
        for img in aud.images:
            hits.extend((img.name, addr) for addr in find_u32(img, value))
        print(f"{label} 0x{value:08X}: raw_u32_occurrences={len(hits)}")
        for image_name, addr in hits[:40]:
            print(f"  {image_name} 0x{addr:08X}")
        if len(hits) > 40:
            print("  ... truncated")

    hline("D. THUMB LITERAL-LOAD XREFS TO B702 / REGISTRY FOCUS VALUES")
    loads = scan_literal_loads(aud, FOCUS_VALUES)
    print(f"literal_load_hits={len(loads)}")
    by_value = {}
    for row in loads:
        by_value.setdefault(row[3], []).append(row)

    for value, label in FOCUS_VALUES.items():
        rows = by_value.get(value, [])
        print(f"\n{label} 0x{value:08X}: literal_loads={len(rows)}")
        for image_name, site, litaddr, _, text in rows[:60]:
            print(f"  {image_name} site=0x{site:08X} pool=0x{litaddr:08X} {text}")
        if len(rows) > 60:
            print("  ... truncated")

    hline("E. ENCLOSING FUNCTIONS FOR FOCUS XREFS")
    candidates = {}
    provenance = {}
    for image_name, site, litaddr, value, text in loads:
        rows = candidate_entries(aud, site)
        # Keep the two nearest valid enclosing candidates for each xref.
        for entry, fa in rows[:2]:
            key = entry & ~1
            candidates.setdefault(key, fa)
            provenance.setdefault(key, []).append((site, value, FOCUS_VALUES.get(value, "?")))

    features = []
    for entry, fa in candidates.items():
        feat = func_features(aud, entry, fa)
        feat["provenance"] = provenance.get(entry, [])
        features.append(feat)
    features.sort(key=lambda f: (-f["score"], f["entry"]))

    print(f"candidate_functions={len(features)}")
    for feat in features[:80]:
        dump_function_summary(aud, feat)
        if feat["provenance"]:
            p = ", ".join(
                f"0x{site:08X}:{label}"
                for site, value, label in feat["provenance"][:16]
            )
            print("  XREFS:", p)
    if len(features) > 80:
        print("... truncated")

    hline("F. CANDIDATES THAT ACTUALLY LOOK LIKE CHILD-ARRAY ENUMERATORS")
    enum_like = [
        f for f in features
        if f["count_off_2"] or f["childptr_off_c"] or B702_CHILDREN in f["lits"] or B702_RECORD in f["lits"]
    ]
    enum_like.sort(key=lambda f: (-f["score"], f["entry"]))
    print(f"enum_like_candidates={len(enum_like)}")
    for feat in enum_like[:30]:
        dump_function_summary(aud, feat)

    hline("G. REVERSE DIRECT CALLERS OF TOP ENUMERATOR CANDIDATES")
    top_targets = [f["entry"] for f in enum_like[:12]]
    if not top_targets:
        top_targets = [f["entry"] for f in features[:8]]
    reverse = reverse_direct_calls(aud, top_targets) if top_targets else {}
    for target in top_targets:
        rows = reverse.get(target & ~1, [])
        print(f"\nTARGET 0x{target:08X}: direct_callers={len(rows)}")
        for image_name, site, raw, via in rows[:40]:
            print(f"  {image_name} callsite=0x{site:08X} via={via or 'DIRECT'}")
            dump_context(aud, site, before=0x24, after=0x18, mark="CALL")
        if len(rows) > 40:
            print("  ... truncated")

    hline("H. B702-LITERAL OWNER CONTEXTS")
    b702_rows = by_value.get(B702, [])
    print(f"B702 literal loads={len(b702_rows)}")
    for image_name, site, litaddr, value, text in b702_rows[:80]:
        print(f"\n{image_name} B702 site=0x{site:08X} pool=0x{litaddr:08X}")
        dump_context(aud, site, before=0x38, after=0x50, mark="B702_LOAD")

    hline("I. DIRECT ROOT_MAPPER CALLS NEAR B702 / 86C0 / 8928 LITERALS")
    mapper_calls = reverse_direct_calls(aud, [ROOT_MAPPER]).get(ROOT_MAPPER, [])
    print(f"ROOT_MAPPER direct_callers={len(mapper_calls)}")
    focus_sites = []
    focus_load_sites = [row[1] for row in loads if row[3] in (B702, ID_86C0, ID_8928, ID_8569, ID_87ED)]
    for image_name, site, raw, via in mapper_calls:
        nearest = min((abs(site - x) for x in focus_load_sites), default=0x7FFFFFFF)
        if nearest <= 0x60:
            focus_sites.append((image_name, site, nearest))
    print(f"ROOT_MAPPER calls within 0x60 of focus-ID literal loads={len(focus_sites)}")
    for image_name, site, distance in focus_sites[:80]:
        print(f"\n{image_name} call=0x{site:08X} nearest_focus_literal_distance=0x{distance:X}")
        dump_context(aud, site, before=0x48, after=0x28, mark="ROOT_MAPPER")
    if len(focus_sites) > 80:
        print("... truncated")

    hline("J. DECISION GATE")
    exact_b702_enum = [
        f for f in enum_like
        if (
            B702 in f["lits"]
            or B702_RECORD in f["lits"]
            or B702_CHILDREN in f["lits"]
        )
        and (f["count_off_2"] or f["childptr_off_c"])
    ]
    both_fields = [f for f in enum_like if f["count_off_2"] and f["childptr_off_c"]]

    print(f"candidates_tied_directly_to_B702_and_record_fields={len(exact_b702_enum)}")
    for f in exact_b702_enum[:20]:
        print(f"  0x{f['entry']:08X} score={f['score']}")

    print(f"candidates_reading_both_count(+2)_and_childptr(+0xC)={len(both_fields)}")
    for f in both_fields[:20]:
        print(f"  0x{f['entry']:08X} score={f['score']}")

    if exact_b702_enum:
        print("RESULT: at least one static function ties B702 directly to child-count/child-pointer style access.")
        print("NEXT: classify its caller chain and the object/menu node it constructs; this is the leading visible-builder path.")
    elif both_fields:
        print("RESULT: generic record enumerator candidate(s) were recovered, but B702 is supplied indirectly.")
        print("NEXT: trace callers of the highest-scoring enumerator with B702 as the runtime parent key.")
    elif enum_like:
        print("RESULT: partial registry/child-enumeration candidates recovered; no single function yet proves the complete B702 builder path.")
        print("NEXT: use the top reverse-caller contexts to isolate the function joining parent ID -> record -> child list.")
    else:
        print("RESULT: no credible child-enumerator recovered from literal xrefs.")
        print("NEXT: emulate/instrument the generic registry accessor using B702 and trace reads of F037BEA0/F0378720.")

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a58_b702_visible_builder_consumer_trace.txt"
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
