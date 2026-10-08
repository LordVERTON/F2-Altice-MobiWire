#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.62 - 0x10316834 item-writer caller differential / B702 submenu trace

STRICTLY OFFLINE.
No USB/COM/BROM/DA/device access. No flash write/erase/repack/patch.

Why this gate is new:
- B709/B702 topology, F02AE864 enumeration, F0316CE0 selectors,
  ROOT_MAPPER/F02F9D34 and the B709 root builder are already known.
- 0x10316834 is a low-level 0x20-byte visible-item record writer with only
  three direct callers. One known caller is inside the B709 UI builder
  0x103647C4.
- The other caller(s) have not been classified in the canonical docs.
  They are a narrow place to look for the deeper/submenu builder that may
  consume B702 and materialize 8569/87ED.

This gate:
1. recovers every direct caller of 0x10316834;
2. finds the exact enclosing owner of each callsite;
3. compares those owners against known registry/menu helpers;
4. reverse-calls each owner one layer to recover its inputs;
5. highlights any non-root owner that consumes child-count/enumeration/
   selector helpers or focus IDs 8569/87ED/86C0/8928/B702;
6. does NOT rediscover B709 topology and does NOT select a patch.

Output:
research/f2/work/reports/s13_5a62_item_writer_callers_b702_submenu_trace.txt
"""

from __future__ import annotations

import re
import sys
import traceback
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path

TITLE = "S13.5A.62 - ITEM WRITER CALLERS / B702 SUBMENU TRACE"

ITEM_WRITER = 0x10316834
KNOWN_B709_BUILDER = 0x103647C4

FOCUS_IDS = {
    0xB709: "B709",
    0xB702: "B702",
    0x8569: "8569",
    0x87ED: "87ED",
    0x86C0: "86C0",
    0x8928: "8928",
    0x8321: "8321",
    0x8313: "8313",
}

HELPERS = {
    0xF02D53DC: "COUNT_FILTERED_CHILDREN",
    0xF02AE864: "ENUM_FILTERED_CHILD_IDS",
    0xF02D8178: "CHILD_ID_AT_INDEX",
    0xF02D5458: "CHILD_FILTER_PREDICATE",
    0xF0316CE0: "LOOKUP_ID_SELECTOR",
    0x1031DA2C: "RESOURCE_CONVERT_A",
    0x10321B40: "RESOURCE_CONVERT_B",
    0x10319094: "ROOT_MAPPER",
    0xF02F9D34: "ROOT_MAPPER_CORE",
    ITEM_WRITER: "ITEM_WRITER",
    KNOWN_B709_BUILDER: "KNOWN_B709_BUILDER",
}

REG_RE = r"(?:r(?:1[0-2]|[0-9])|sp|lr|pc)"
MOV_IMM_RE = re.compile(r"^(?:movs?|mov)\s+(r(?:1[0-2]|[0-9])),\s*#(0x[0-9a-f]+|\d+)$", re.I)
MOV_REG_RE = re.compile(r"^(?:movs?|mov)\s+(r(?:1[0-2]|[0-9])),\s*(r(?:1[0-2]|[0-9]))$", re.I)
SHIFT_RE = re.compile(r"^(lsls?|lsrs?)\s+(r(?:1[0-2]|[0-9])),\s*(?:\2,\s*)?#(0x[0-9a-f]+|\d+)$", re.I)
ADD_IMM_RE = re.compile(r"^(adds?|subs?)\s+(r(?:1[0-2]|[0-9])),(?:\s*\2,)?\s*#(0x[0-9a-f]+|\d+)$", re.I)


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


def hline(label):
    print()
    print("=" * 120)
    print(label)
    print("=" * 120)


def normalized_calls(aud, fa):
    rows = []
    for site, raw in fa.calls:
        norm, via = aud.normalized_target(raw)
        rows.append((site, norm, raw, via))
    return rows


def function_strings(aud, fa):
    out = []
    seen = set()
    for row in fa.literals:
        # Historical helper versions exposed either (site, literal_addr, value)
        # or a longer tuple. The value is always the last element.
        if not row:
            continue
        value = row[-1]
        if not isinstance(value, int):
            continue
        s = aud.string_at(value)
        if s and s not in seen:
            seen.add(s)
            out.append((value, s))
    return out


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


def candidate_entries(aud, site, back=0x700):
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
                try:
                    fa = aud.audit_func(pc, max_span=0x2200, max_insns=3200)
                except TypeError:
                    fa = aud.audit_func(pc)
                if site in fa.insns and pc not in seen:
                    seen.add(pc)
                    rows.append((pc, fa))
        pc += 2
    rows.sort(key=lambda row: (site - row[0], row[0]))
    return rows


def best_owner(aud, site):
    rows = candidate_entries(aud, site)
    return rows[0] if rows else (None, None)


def context(aud, center, before=0x50, after=0x70, mark="SITE"):
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
            lab = HELPERS.get(norm)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{lab}>" if lab else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            v = x.literal_value
            lab = FOCUS_IDS.get(v)
            extra.append(f"literal=0x{v:08X}" + (f"<{lab}>" if lab else ""))
            s = aud.string_at(v)
            if s:
                extra.append(f'STR="{s}"')
        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = f" <{mark}>" if pc == center else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{flag}")
        pc += max(2, x.size)


def dump_function(aud, fa, highlight_sites=None):
    highlight_sites = set(highlight_sites or [])
    for addr in sorted(fa.insns):
        x = fa.insns[addr]
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            lab = HELPERS.get(norm)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{lab}>" if lab else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            v = x.literal_value
            lab = FOCUS_IDS.get(v)
            extra.append(f"literal=0x{v:08X}" + (f"<{lab}>" if lab else ""))
        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = " <ITEM_WRITER_CALL>" if addr in highlight_sites else ""
        print(f"0x{addr:08X}: {x.text}{suffix}{flag}")


def focus_literals(fa):
    rows = []
    for row in fa.literals:
        if not row:
            continue
        value = row[-1]
        if isinstance(value, int) and value in FOCUS_IDS:
            rows.append((row[0], value, FOCUS_IDS[value]))
    return rows


def helper_profile(aud, fa):
    rows = normalized_calls(aud, fa)
    by_target = defaultdict(list)
    for site, norm, raw, via in rows:
        if norm in HELPERS:
            by_target[norm].append(site)
    return by_target


def infer_simple_constants(aud, fa, callsite, max_back_insns=28):
    """
    Conservative straight-line constant reconstruction for r0-r3 immediately
    before a call. Any intervening call clobbers r0-r3. Memory loads become
    unknown unless they are PC literals already exposed by the decoder.
    This is evidence aid only, never a proof engine.
    """
    addrs = [a for a in sorted(fa.insns) if a < callsite]
    addrs = addrs[-max_back_insns:]
    vals = {f"r{i}": None for i in range(4)}

    for addr in addrs:
        x = fa.insns[addr]
        text = x.text.lower().replace("\t", " ")
        text = re.sub(r"\s+", " ", text).strip()

        if x.is_call:
            for r in vals:
                vals[r] = None
            continue

        if x.literal_value is not None:
            m = re.match(r"^ldr\s+(r[0-3]),\s*\[pc", text)
            if m:
                vals[m.group(1)] = x.literal_value
                continue

        m = MOV_IMM_RE.match(text)
        if m and m.group(1) in vals:
            vals[m.group(1)] = int(m.group(2), 0) & 0xFFFFFFFF
            continue

        m = MOV_REG_RE.match(text)
        if m and m.group(1) in vals:
            vals[m.group(1)] = vals.get(m.group(2))
            continue

        m = SHIFT_RE.match(text)
        if m and m.group(2) in vals:
            r = m.group(2)
            if vals[r] is not None:
                sh = int(m.group(3), 0)
                if text.startswith("lsl"):
                    vals[r] = (vals[r] << sh) & 0xFFFFFFFF
                else:
                    vals[r] = (vals[r] >> sh) & 0xFFFFFFFF
            continue

        m = ADD_IMM_RE.match(text)
        if m and m.group(2) in vals:
            r = m.group(2)
            if vals[r] is not None:
                imm = int(m.group(3), 0)
                vals[r] = ((vals[r] - imm) if text.startswith("sub") else (vals[r] + imm)) & 0xFFFFFFFF
            continue

        # Conservative invalidation when an instruction visibly writes r0-r3.
        head = text.split(" ", 1)
        if len(head) == 2:
            operands = head[1]
            first = operands.split(",", 1)[0].strip()
            if first in vals and not text.startswith(("cmp ", "tst ", "str", "push", "stm")):
                vals[first] = None

    return vals


def owner_score(aud, entry, fa):
    hp = helper_profile(aud, fa)
    score = 0
    reasons = []
    if entry == KNOWN_B709_BUILDER:
        reasons.append("KNOWN_B709_ROOT_BUILDER")
    for target, weight in (
        (0xF02D53DC, 8),
        (0xF02AE864, 10),
        (0xF02D8178, 8),
        (0xF0316CE0, 7),
        (0x10319094, 4),
        (0x1031DA2C, 3),
        (0x10321B40, 3),
    ):
        if hp.get(target):
            score += weight
            reasons.append(HELPERS[target])
    fl = focus_literals(fa)
    if fl:
        score += 6 * len(fl)
        reasons.extend(name for _, _, name in fl)
    return score, reasons, hp, fl


def main_body():
    repo = Path.cwd().resolve()
    helper = repo / "research/f2/automation/jobs/s13_5a51_launcher_dispatch_init_trace.py"
    if not helper.is_file():
        raise SystemExit(
            "Run from C:\\Users\\verto\\F2-Altice-MobiWire; canonical A.51 helper not found."
        )

    sys.path.insert(0, str(helper.parent))
    import s13_5a51_launcher_dispatch_init_trace as m

    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE: local firmware reads only.")
    print("Purpose: classify the two/three ITEM_WRITER owner families, not rediscover B709 topology.")

    hline("A. CANONICAL IMAGE GUARDS")
    print(f"ALICE size=0x{len(alice.data):X} sha256={m.sha256(alice.data)}")
    print(f"ZIMAGE size=0x{len(zimage.data):X} sha256={m.sha256(zimage.data)}")
    print("Canonical loader = PASS")

    hline("B. DIRECT CALLERS OF ITEM_WRITER 0x10316834")
    rev = reverse_direct_calls(aud, {ITEM_WRITER})
    rows = rev.get(ITEM_WRITER, [])
    print(f"direct_callers={len(rows)}")
    for image_name, site, raw, via in rows:
        print(f"\n{image_name} callsite=0x{site:08X} raw=0x{raw:08X} via={via or 'DIRECT'}")
        context(aud, site, before=0x60, after=0x60, mark="ITEM_WRITER_CALL")

    hline("C. EXACT ENCLOSING OWNERS")
    owner_map = {}
    owner_callsites = defaultdict(list)
    for image_name, site, raw, via in rows:
        entry, fa = best_owner(aud, site)
        if entry is None:
            print(f"callsite=0x{site:08X}: OWNER NOT RECOVERED")
            continue
        owner_map[entry] = fa
        owner_callsites[entry].append(site)
        print(
            f"callsite=0x{site:08X} -> owner=0x{entry:08X} image={fa.image} "
            f"insns={len(fa.insns)} calls={len(fa.calls)}"
        )

    hline("D. OWNER DIFFERENTIAL")
    ranked = []
    for entry, fa in owner_map.items():
        score, reasons, hp, fl = owner_score(aud, entry, fa)
        ranked.append((score, entry, fa, reasons, hp, fl))
    ranked.sort(key=lambda x: (-x[0], x[1]))

    for score, entry, fa, reasons, hp, fl in ranked:
        print(
            f"\nOWNER 0x{entry:08X} image={fa.image} score={score} "
            f"KNOWN_B709_BUILDER={entry == KNOWN_B709_BUILDER}"
        )
        print("  reasons=" + (", ".join(reasons) if reasons else "NONE"))
        for target in sorted(hp):
            sites = ", ".join(f"0x{x:08X}" for x in hp[target])
            print(f"  helper {HELPERS[target]} 0x{target:08X}: {sites}")
        for site, value, name in fl:
            print(f"  focus literal 0x{value:04X}<{name}> at 0x{site:08X}")
        for value, s in function_strings(aud, fa)[:30]:
            print(f'  STR 0x{value:08X}: "{s}"')

        print("  ITEM_WRITER call arguments (conservative straight-line constants):")
        for site in owner_callsites[entry]:
            vals = infer_simple_constants(aud, fa, site)
            def fmt(v):
                if v is None:
                    return "UNKNOWN"
                lab = FOCUS_IDS.get(v)
                return f"0x{v:08X}" + (f"<{lab}>" if lab else "")
            print(
                f"    @0x{site:08X}: "
                + " ".join(f"{r}={fmt(vals[r])}" for r in ("r0","r1","r2","r3"))
            )

    hline("E. COMPLETE OWNER BODIES")
    for score, entry, fa, reasons, hp, fl in ranked:
        print(f"\n----- OWNER 0x{entry:08X} -----")
        dump_function(aud, fa, owner_callsites[entry])

    hline("F. REVERSE CALLERS OF EACH ITEM-WRITER OWNER")
    owner_targets = set(owner_map)
    owner_rev = reverse_direct_calls(aud, owner_targets) if owner_targets else {}
    owner_parent_map = defaultdict(set)

    for score, entry, fa, reasons, hp, fl in ranked:
        callers = owner_rev.get(entry & ~1, [])
        print(f"\nOWNER 0x{entry:08X}: direct_callers={len(callers)}")
        for image_name, site, raw, via in callers[:60]:
            parent_entry, parent_fa = best_owner(aud, site)
            if parent_entry is not None:
                owner_parent_map[entry].add(parent_entry)
            parent_txt = f" parent_owner=0x{parent_entry:08X}" if parent_entry is not None else ""
            print(
                f"  {image_name} callsite=0x{site:08X} via={via or 'DIRECT'}{parent_txt}"
            )
            context(aud, site, before=0x58, after=0x58, mark="OWNER_CALL")
        if len(callers) > 60:
            print("  ... truncated")

    hline("G. ONE-LAYER PARENT OWNER CLASSIFICATION")
    seen = set()
    parent_ranked = []
    for child_entry, parents in owner_parent_map.items():
        for parent_entry in parents:
            if parent_entry in seen:
                continue
            seen.add(parent_entry)
            # Recover using any callsite from reverse map that belongs to this parent.
            parent_fa = None
            for target in owner_targets:
                for _, site, _, _ in owner_rev.get(target, []):
                    pe, pfa = best_owner(aud, site)
                    if pe == parent_entry:
                        parent_fa = pfa
                        break
                if parent_fa is not None:
                    break
            if parent_fa is None:
                continue
            score, reasons, hp, fl = owner_score(aud, parent_entry, parent_fa)
            parent_ranked.append((score, parent_entry, parent_fa, reasons, hp, fl))

    parent_ranked.sort(key=lambda x: (-x[0], x[1]))
    for score, entry, fa, reasons, hp, fl in parent_ranked:
        print(f"\nPARENT OWNER 0x{entry:08X} image={fa.image} score={score}")
        print("  reasons=" + (", ".join(reasons) if reasons else "NONE"))
        for target in sorted(hp):
            print(
                f"  helper {HELPERS[target]} 0x{target:08X}: "
                + ", ".join(f"0x{x:08X}" for x in hp[target])
            )
        for site, value, name in fl:
            print(f"  focus literal 0x{value:04X}<{name}> at 0x{site:08X}")
        for value, st in function_strings(aud, fa)[:25]:
            print(f'  STR 0x{value:08X}: "{st}"')

    hline("H. NON-ROOT ITEM-BUILDER CANDIDATES")
    candidates = []
    for score, entry, fa, reasons, hp, fl in ranked:
        if entry == KNOWN_B709_BUILDER:
            continue
        has_child_pipeline = any(
            hp.get(t) for t in (0xF02D53DC, 0xF02AE864, 0xF02D8178, 0xF0316CE0)
        )
        candidates.append((score, entry, has_child_pipeline, reasons))

    if not candidates:
        print("No non-root direct owner of ITEM_WRITER was recovered.")
    else:
        for score, entry, has_child_pipeline, reasons in candidates:
            print(
                f"candidate=0x{entry:08X} score={score} "
                f"child_pipeline={has_child_pipeline} "
                f"reasons={','.join(reasons) if reasons else 'NONE'}"
            )

    hline("I. DECISION GATE")
    print(f"ITEM_WRITER direct callers = {len(rows)}")
    print(f"distinct ITEM_WRITER owners = {len(owner_map)}")
    print(f"known B709 root owner present = {KNOWN_B709_BUILDER in owner_map}")
    print(f"non-root owner candidates = {len(candidates)}")

    strong = [c for c in candidates if c[2]]
    if strong:
        best = strong[0]
        print(
            f"RESULT: non-root owner 0x{best[1]:08X} uses the child/selector pipeline "
            f"and is the leading deeper/submenu-builder candidate."
        )
        print(
            "NEXT: trace its runtime parent argument and compare materialization of "
            "8569/87ED against non-enumerated 86C0/8928. This is patch-relevant."
        )
    elif candidates:
        best = candidates[0]
        print(
            f"RESULT: non-root ITEM_WRITER owner(s) exist, but no direct known "
            f"child-enumeration helper was recovered in the same owner. "
            f"Best candidate = 0x{best[1]:08X}."
        )
        print(
            "NEXT: follow the candidate's one-layer parent owner and any arrays "
            "feeding its ITEM_WRITER arguments; do not return to B709 topology."
        )
    else:
        print(
            "RESULT: 0x10316834 appears confined to the already-known root item path "
            "under the recovered ownership model."
        )
        print(
            "NEXT: pivot to the action/callback field consumers of the 0x20-byte "
            "item records and identify the generic submenu action builder."
        )

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a62_item_writer_callers_b702_submenu_trace.txt"
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
