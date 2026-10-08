#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.64 - F00960A0 per-item side-table consumer / action-dispatch audit

STRICTLY OFFLINE.
No USB/COM/BROM/DA/device access. No flash write/erase/repack/patch.

A.63 proved:
  0x102FFEC8(index, value):
      r2 = 0xF00960A0
      r0 = index * 8
      [r2 + r0] = value

So F00960A0 is an 8-byte-stride per-item side table. Its exact semantics are
still unknown. This gate searches for every code consumer of that table and
tests whether the stored dword becomes:
  - an indirect function/callback target,
  - a user-data/context pointer,
  - an ID/resource value,
  - or generic UI state.

This is deliberately new work. It does not revisit B709/B702 topology,
ROOT_MAPPER, or the old S13.2A Image Viewer redirect.

Output:
research/f2/work/reports/s13_5a64_f00960a0_consumer_action_dispatch_audit.txt
"""

from __future__ import annotations

import re
import sys
import traceback
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path

TITLE = "S13.5A.64 - F00960A0 CONSUMER / ACTION-DISPATCH AUDIT"

TABLE = 0xF00960A0
TABLE_PLUS4 = TABLE + 4
WRITER = 0x102FFEC8
ITEM_WRITER = 0x10316834
WRAPPER = 0x10306034

FOCUS = {
    0xB709: "B709",
    0xB702: "B702",
    0x8569: "8569",
    0x87ED: "87ED",
    0x86C0: "86C0",
    0x8928: "8928",
    0x1033D840: "CB_8928",
    0x1033D841: "CB_8928_THUMB",
    0x1033E814: "INIT_8928",
    0x1033E815: "INIT_8928_THUMB",
    0x1033F83C: "AUDIO_PLAYER",
    0x1033F83D: "AUDIO_PLAYER_THUMB",
    0x1033EF28: "INIT_86C0",
    0x1033EF29: "INIT_86C0_THUMB",
    0x10348D04: "INIT_8569",
    0x10348D05: "INIT_8569_THUMB",
}

KNOWN = {
    WRITER: "SIDE_TABLE_WRITER",
    ITEM_WRITER: "ITEM_WRITER",
    WRAPPER: "ITEM_WRITER_PLUS_SIDE_TABLE",
}

REG = r"r(?:1[0-2]|[0-9])"
LDR_LIT_RE = re.compile(rf"^ldr\s+({REG}),\s*\[pc", re.I)
MEM_RE = re.compile(
    rf"\[(?P<base>{REG}|sp|lr)(?:,\s*(?P<idx>{REG}))?"
    rf"(?:,\s*#(?P<imm>-?(?:0x[0-9a-f]+|\d+)))?\]",
    re.I,
)
LSL3_RE = re.compile(rf"^lsls?\s+({REG}),\s*({REG}),\s*#(?:3|0x3)$", re.I)
ADD_REG_RE = re.compile(rf"^adds?\s+({REG}),\s*({REG}),\s*({REG})$", re.I)
MOV_RE = re.compile(rf"^(?:movs?|mov)\s+({REG}),\s*({REG})$", re.I)
ADDI_RE = re.compile(
    rf"^adds?\s+({REG}),\s*(?:({REG}),\s*)?#(0x[0-9a-f]+|\d+)$", re.I
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


def hline(label):
    print()
    print("=" * 120)
    print(label)
    print("=" * 120)


def norm_text(s):
    return re.sub(r"\s+", " ", s.lower().replace("\t", " ")).strip()


def audit_func(aud, addr):
    try:
        return aud.audit_func(addr & ~1, max_span=0x3000, max_insns=5000)
    except TypeError:
        return aud.audit_func(addr & ~1)


def candidate_entries(aud, site, back=0x900):
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
                    fa = audit_func(aud, pc)
                except Exception:
                    fa = None
                if fa is not None and site in fa.insns and pc not in seen:
                    seen.add(pc)
                    rows.append((pc, fa))
        pc += 2
    rows.sort(key=lambda r: (site - r[0], r[0]))
    return rows


def best_owner(aud, site):
    rows = candidate_entries(aud, site)
    return rows[0] if rows else (None, None)


def reverse_calls(aud, targets):
    targets = {t & ~1 for t in targets}
    out = {t: [] for t in targets}
    for img in aud.images:
        pc = img.base & ~1
        while pc < img.end - 2:
            x = aud.decode_one(pc)
            if x is not None and x.is_call and x.target is not None:
                norm, via = aud.normalized_target(x.target)
                if norm in targets:
                    out[norm].append((img.name, pc, x.target, via))
            pc += 2
    return out


def direct_literal_sites(aud, values):
    values = set(values)
    rows = []
    for img in aud.images:
        pc = img.base & ~1
        while pc < img.end - 2:
            x = aud.decode_one(pc)
            if x is not None and x.literal_value in values:
                rows.append((img.name, pc, x.literal_addr, x.literal_value, x.text))
            pc += 2
    return rows


def dump_context(aud, center, before=0x70, after=0x90, mark="SITE"):
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
            lab = KNOWN.get(norm) or FOCUS.get(norm) or FOCUS.get(norm | 1)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{lab}>" if lab else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            v = x.literal_value
            lab = FOCUS.get(v)
            if v == TABLE:
                lab = "F00960A0"
            elif v == TABLE_PLUS4:
                lab = "F00960A4"
            extra.append(f"literal=0x{v:08X}" + (f"<{lab}>" if lab else ""))
        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = f" <{mark}>" if pc == center else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{flag}")
        pc += max(2, x.size)


def dump_function(aud, fa, marks=None):
    marks = marks or {}
    for addr in sorted(fa.insns):
        x = fa.insns[addr]
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            lab = KNOWN.get(norm) or FOCUS.get(norm) or FOCUS.get(norm | 1)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{lab}>" if lab else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            v = x.literal_value
            lab = FOCUS.get(v)
            if v == TABLE:
                lab = "F00960A0"
            elif v == TABLE_PLUS4:
                lab = "F00960A4"
            extra.append(f"literal=0x{v:08X}" + (f"<{lab}>" if lab else ""))
        suffix = (" ; " + " ".join(extra)) if extra else ""
        mark = f" <{marks[addr]}>" if addr in marks else ""
        print(f"0x{addr:08X}: {x.text}{suffix}{mark}")


def is_indirect_control(x):
    t = norm_text(x.text)
    if re.match(r"^blx\s+r(?:1[0-2]|[0-9])$", t):
        return True
    if re.match(r"^bx\s+r(?:1[0-2]|[0-9])$", t) and t != "bx lr":
        return True
    return False


def indirect_reg(x):
    t = norm_text(x.text)
    m = re.match(r"^(?:blx|bx)\s+(r(?:1[0-2]|[0-9]))$", t)
    return m.group(1) if m else None


def literal_base_reg_at(fa, site, value):
    x = fa.insns.get(site)
    if x is None or x.literal_value != value:
        return None
    m = LDR_LIT_RE.match(norm_text(x.text))
    return m.group(1) if m else None


def analyze_table_flow(aud, fa, literal_site, value):
    """
    Local conservative register tracking from a literal load of TABLE/TABLE+4.
    Tracks copies/additions enough to spot memory operations whose effective
    address is derived from the table base. It does not pretend to be full SSA.
    """
    base0 = literal_base_reg_at(fa, literal_site, value)
    if base0 is None:
        return []

    # reg -> constant offset relative to TABLE
    rel = {base0: value - TABLE}
    events = []
    addrs = [a for a in sorted(fa.insns) if a >= literal_site][:120]

    for addr in addrs:
        x = fa.insns[addr]
        t = norm_text(x.text)

        if addr == literal_site:
            continue

        if x.is_call:
            # Calls clobber r0-r3, preserve r4-r11 in ABI terms.
            for r in ("r0", "r1", "r2", "r3"):
                rel.pop(r, None)

        m = MOV_RE.match(t)
        if m:
            dst, src = m.groups()
            if src in rel:
                rel[dst] = rel[src]
            else:
                rel.pop(dst, None)
            continue

        m = ADDI_RE.match(t)
        if m:
            dst, src, imm = m.groups()
            src = src or dst
            if src in rel:
                rel[dst] = rel[src] + int(imm, 0)
            else:
                rel.pop(dst, None)
            continue

        # If an address register is built with ADD base + index, keep a symbolic marker.
        m = ADD_REG_RE.match(t)
        if m:
            dst, a, b = m.groups()
            if a in rel:
                rel[dst] = ("indexed", rel[a], b)
            elif b in rel:
                rel[dst] = ("indexed", rel[b], a)
            else:
                rel.pop(dst, None)
            continue

        mem = MEM_RE.search(t)
        if mem:
            b = mem.group("base")
            idx = mem.group("idx")
            imm = int(mem.group("imm"), 0) if mem.group("imm") else 0
            if b in rel:
                events.append((addr, "MEM", b, rel[b], idx, imm, x.text))

        # Identify indirect control regardless of base tracking.
        if is_indirect_control(x):
            events.append((addr, "INDIRECT", indirect_reg(x), None, None, 0, x.text))

        # Generic clobber of a tracked destination.
        head = t.split(" ", 1)
        if len(head) == 2:
            dst = head[1].split(",", 1)[0].strip()
            if dst in rel and not t.startswith(("cmp ", "tst ", "str", "push", "stm", "ldr")):
                if not (MOV_RE.match(t) or ADDI_RE.match(t) or ADD_REG_RE.match(t)):
                    rel.pop(dst, None)

    return events


def find_prev_def(fa, before, reg, limit=20):
    addrs = [a for a in sorted(fa.insns) if a < before][-limit:]
    for addr in reversed(addrs):
        x = fa.insns[addr]
        t = norm_text(x.text)
        # direct load/write into reg
        if re.match(rf"^(?:ldr|ldrh|ldrb|movs?|mov|adds?|subs?)\s+{re.escape(reg)}\b", t):
            return addr, x.text
        if x.is_call and reg in ("r0","r1","r2","r3"):
            return addr, f"CALL CLOBBER: {x.text}"
    return None


def raw_u32_hits(img, value):
    needle = int(value).to_bytes(4, "little")
    out = []
    start = 0
    while True:
        i = img.data.find(needle, start)
        if i < 0:
            break
        out.append(img.base + i)
        start = i + 1
    return out


def literal_values(fa):
    out = []
    for row in fa.literals:
        if row and isinstance(row[-1], int):
            out.append((row[0], row[-1]))
    return out


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
    print("STRICTLY OFFLINE: canonical firmware reads only.")

    hline("A. CANONICAL IMAGE GUARDS")
    print(f"ALICE size=0x{len(alice.data):X} sha256={m.sha256(alice.data)}")
    print(f"ZIMAGE size=0x{len(zimage.data):X} sha256={m.sha256(zimage.data)}")
    print("Canonical loader = PASS")

    hline("B. RAW POINTER OCCURRENCES")
    for value, label in ((TABLE, "F00960A0"), (TABLE_PLUS4, "F00960A4")):
        print(f"\n{label} 0x{value:08X}")
        total = 0
        for img in aud.images:
            hits = raw_u32_hits(img, value)
            total += len(hits)
            print(f"  {img.name}: {len(hits)} raw_u32 occurrence(s)")
            for a in hits[:80]:
                print(f"    0x{a:08X}")
        print(f"  total={total}")

    hline("C. DIRECT CODE LITERAL LOADS OF TABLE / TABLE+4")
    sites = direct_literal_sites(aud, {TABLE, TABLE_PLUS4})
    print(f"literal_loads={len(sites)}")
    owners = {}
    owner_sites = defaultdict(list)

    for image_name, site, litaddr, value, text in sites:
        owner, fa = best_owner(aud, site)
        print(
            f"\n{image_name} site=0x{site:08X} pool=0x{litaddr:08X} "
            f"value=0x{value:08X} owner="
            + (f"0x{owner:08X}" if owner is not None else "UNKNOWN")
        )
        if owner is not None:
            owners[owner] = fa
            owner_sites[owner].append((site, value))
        dump_context(aud, site, before=0x50, after=0x90, mark="TABLE_LITERAL")

    hline("D. TABLE-OWNER FUNCTION CLASSIFICATION")
    classifications = []

    for entry, fa in sorted(owners.items()):
        reads = []
        writes = []
        indirect = []
        all_events = []

        for site, value in owner_sites[entry]:
            events = analyze_table_flow(aud, fa, site, value)
            all_events.extend(events)
            for ev in events:
                addr, kind, base, rel, idx, imm, text = ev
                t = norm_text(text)
                if kind == "INDIRECT":
                    indirect.append(ev)
                elif kind == "MEM":
                    if t.startswith(("str ", "strh ", "strb ")):
                        writes.append(ev)
                    if t.startswith(("ldr ", "ldrh ", "ldrb ")):
                        reads.append(ev)

        focus = [(site, v, FOCUS.get(v) or FOCUS.get(v & ~1))
                 for site, v in literal_values(fa)
                 if v in FOCUS or (v & ~1) in FOCUS]

        score = len(reads) * 3 + len(indirect) * 8 - len(writes)
        if entry == WRITER:
            score -= 10

        classifications.append((score, entry, fa, reads, writes, indirect, focus, all_events))

    classifications.sort(key=lambda r: (-r[0], r[1]))

    for score, entry, fa, reads, writes, indirect, focus, all_events in classifications:
        print(
            f"\nOWNER 0x{entry:08X} image={fa.image} score={score} "
            f"reads={len(reads)} writes={len(writes)} indirect_ctrl={len(indirect)}"
        )
        for site, v, lab in focus:
            print(f"  FOCUS 0x{site:08X}: 0x{v:08X} <{lab}>")
        for ev in all_events:
            addr, kind, base, rel, idx, imm, text = ev
            if kind == "MEM":
                print(
                    f"  TABLE_MEM 0x{addr:08X}: {text} "
                    f"base={base} rel={rel} idx={idx or '-'} imm={imm}"
                )
            else:
                print(f"  INDIRECT 0x{addr:08X}: {text}")

    hline("E. FULL BODIES OF TABLE OWNERS")
    for score, entry, fa, reads, writes, indirect, focus, all_events in classifications:
        marks = {}
        for site, value in owner_sites[entry]:
            marks[site] = "TABLE_LITERAL"
        for ev in indirect:
            marks[ev[0]] = "INDIRECT_CONTROL"
        print(f"\n----- 0x{entry:08X} -----")
        dump_function(aud, fa, marks=marks)

    hline("F. INDIRECT-CONTROL BACKSLICE")
    indirect_candidates = []
    for score, entry, fa, reads, writes, indirect, focus, all_events in classifications:
        for ev in indirect:
            addr, _, reg, *_ = ev
            prev = find_prev_def(fa, addr, reg, limit=24)
            print(f"\nowner=0x{entry:08X} indirect@0x{addr:08X} reg={reg}")
            if prev:
                print(f"  previous definition: 0x{prev[0]:08X}: {prev[1]}")
            else:
                print("  previous definition: NOT FOUND")
            dump_context(aud, addr, before=0x60, after=0x30, mark="INDIRECT")
            indirect_candidates.append((entry, addr, reg, prev))

    hline("G. REVERSE CALLERS OF TABLE-READING OWNERS")
    read_owners = [entry for score, entry, fa, reads, writes, indirect, focus, all_events in classifications if reads]
    rev = reverse_calls(aud, read_owners) if read_owners else {}
    for entry in read_owners:
        rows = rev.get(entry & ~1, [])
        print(f"\nOWNER 0x{entry:08X}: direct_callers={len(rows)}")
        for image_name, site, raw, via in rows[:60]:
            parent, _ = best_owner(aud, site)
            print(
                f"  {image_name} callsite=0x{site:08X} via={via or 'DIRECT'} "
                + (f"parent=0x{parent:08X}" if parent is not None else "parent=UNKNOWN")
            )
            dump_context(aud, site, before=0x48, after=0x48, mark="OWNER_CALL")
        if len(rows) > 60:
            print("  ... truncated")

    hline("H. SECOND FIELD (+4) EVIDENCE")
    plus4_direct = [r for r in sites if r[3] == TABLE_PLUS4]
    print(f"direct_literal_loads_F00960A4={len(plus4_direct)}")

    # Also report memory events whose relative base is +4 or whose immediate
    # lands on +4 relative to TABLE.
    plus4_events = []
    for score, entry, fa, reads, writes, indirect, focus, all_events in classifications:
        for ev in all_events:
            if ev[1] != "MEM":
                continue
            _, _, _, rel, _, imm, text = ev
            if isinstance(rel, int) and rel + imm == 4:
                plus4_events.append((entry, ev))

    print(f"derived_plus4_memory_events={len(plus4_events)}")
    for entry, ev in plus4_events:
        print(f"  owner=0x{entry:08X} 0x{ev[0]:08X}: {ev[6]}")

    hline("I. FOCUS-ID / AUDIO POINTER CO-LOCATION")
    any_focus = 0
    for score, entry, fa, reads, writes, indirect, focus, all_events in classifications:
        if not focus:
            continue
        any_focus += len(focus)
        print(f"\nowner=0x{entry:08X}")
        for site, v, lab in focus:
            print(f"  0x{site:08X}: 0x{v:08X} <{lab}>")
    if any_focus == 0:
        print("No focus IDs/Audio pointers appear as literals in table-owner functions.")

    hline("J. DECISION GATE")
    readers = [r for r in classifications if r[3]]
    indirect_readers = [r for r in readers if r[5]]

    print(f"distinct table-owner functions = {len(classifications)}")
    print(f"table-reading owners           = {len(readers)}")
    print(f"reading owners with indirect control = {len(indirect_readers)}")
    print(f"direct/derived +4 evidence     = {len(plus4_direct) + len(plus4_events)}")

    if indirect_readers:
        best = indirect_readers[0]
        print(
            f"RESULT: leading callback-dispatch candidate = 0x{best[1]:08X}. "
            "It both reads F00960A0-derived state and contains indirect control flow."
        )
        print(
            "NEXT: prove whether the indirect branch target is the dword loaded from "
            "F00960A0[index*8]; if yes, compare per-item values with Audio callback/init."
        )
    elif readers:
        best = readers[0]
        print(
            f"RESULT: F00960A0 has executable consumers, but no same-function indirect "
            f"control was mechanically proven. Leading consumer = 0x{best[1]:08X}."
        )
        print(
            "NEXT: trace the loaded value one function boundary to its consumer; do not "
            "treat the table as a callback table until that use is proven."
        )
    else:
        print(
            "RESULT: only writers/direct literal owners were recovered; no executable "
            "read consumer was proven from exact base references."
        )
        print(
            "NEXT: search consumers that receive F00960A0 indirectly via a global pointer "
            "or use a neighboring base constant."
        )

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a64_f00960a0_consumer_action_dispatch_audit.txt"
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
