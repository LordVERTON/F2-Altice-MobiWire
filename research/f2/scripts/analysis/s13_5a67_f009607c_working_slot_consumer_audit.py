#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.67 - F009607C/F0096080 working-slot consumer audit

STRICTLY OFFLINE.
Reads only canonical extracted firmware images from the local repository.
No USB/COM/BROM/DA/device access. No flash write/erase/repack/patch.

A.66 proved:
  1033E770(r0, r1, r2):
      if 0 <= r1 < [r0+0x24]:
          [r0 + 0x1C + r1*4] = r2

At the unique caller:
  r0 = F0096060
  r2 = F00960A0[current_index*8 + sub_index*4]

Therefore the per-item side-table dword is copied into the WORKING SLOTS:
  F009607C + sub_index*4
with the working-slot count at F0096084.

This gate answers the NEW question:
  Who reads F009607C/F0096080, and how is the loaded value used?

It follows the F0096060 base both:
  - directly in functions that load it as a literal;
  - one direct call boundary when that base is passed as r0-r3;
and taint-tracks values loaded from the working slots into:
  - pointer dereferences,
  - stores/copies,
  - direct-call arguments,
  - indirect BLX/BX.

It does NOT redo the A.64/A.65 F00960A0 xref census, B709/B702 topology,
ROOT_MAPPER, F03BB8xx, or the S13.2A physical POC.

Output:
research/f2/work/reports/s13_5a67_f009607c_working_slot_consumer_audit.txt
"""

from __future__ import annotations

import re
import sys
import traceback
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path

TITLE = "S13.5A.67 - F009607C/F0096080 WORKING-SLOT CONSUMER AUDIT"

BASE = 0xF0096060
SLOT0 = BASE + 0x1C
SLOT1 = BASE + 0x20
COUNT = BASE + 0x24
SOURCE_SIDE = 0xF00960A0
COPIER = 0x1033E770

FOCUS = {
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
    0x8569: "8569",
    0x87ED: "87ED",
    0x86C0: "86C0",
    0x8928: "8928",
}

REG = r"r(?:1[0-2]|[0-9])"
LDR_LIT_RE = re.compile(rf"^ldr\s+({REG}),\s*\[pc", re.I)
MOV_RE = re.compile(rf"^(?:movs?|mov)\s+({REG}),\s*({REG})$", re.I)
ADD3_RE = re.compile(rf"^adds?\s+({REG}),\s*({REG}),\s*({REG})$", re.I)
ADDI_RE = re.compile(rf"^adds?\s+({REG}),\s*(?:({REG}),\s*)?#(0x[0-9a-f]+|\d+)$", re.I)
SUBI_RE = re.compile(rf"^subs?\s+({REG}),\s*(?:({REG}),\s*)?#(0x[0-9a-f]+|\d+)$", re.I)
LSL_RE = re.compile(rf"^lsls?\s+({REG}),\s*({REG}),\s*#(0x[0-9a-f]+|\d+)$", re.I)
MEM_RE = re.compile(
    rf"\[(?P<base>{REG}|sp|lr)"
    rf"(?:,\s*(?P<idx>{REG}))?"
    rf"(?:,\s*#(?P<imm>-?(?:0x[0-9a-f]+|\d+)))?\]",
    re.I,
)
LOAD_DEST_RE = re.compile(rf"^ldr(?:b|h|sb|sh)?\s+({REG}),", re.I)
STORE_SRC_RE = re.compile(rf"^str(?:b|h)?\s+({REG}),", re.I)
INDIRECT_RE = re.compile(rf"^(blx|bx)\s+({REG})$", re.I)
CMP_RE = re.compile(rf"^(?:cmp|tst)\s+({REG})\b", re.I)


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


def nt(s):
    return re.sub(r"\s+", " ", s.lower().replace("\t", " ")).strip()


def audit_func(aud, addr):
    try:
        return aud.audit_func(addr & ~1, max_span=0x2800, max_insns=4500)
    except TypeError:
        return aud.audit_func(addr & ~1)


def candidate_entries(aud, site, back=0x900):
    img = aud.image_for(site)
    if img is None:
        return []
    start = max(img.base, site - back) & ~1
    out, seen = [], set()
    pc = start
    while pc <= site:
        x = aud.decode_one(pc)
        if x is not None and x.text.lower().startswith("push") and "lr" in x.text.lower():
            try:
                fa = audit_func(aud, pc)
            except Exception:
                fa = None
            if fa is not None and site in fa.insns and pc not in seen:
                seen.add(pc)
                out.append((pc, fa))
        pc += 2
    out.sort(key=lambda row: (site - row[0], row[0]))
    return out


def best_owner(aud, site):
    rows = candidate_entries(aud, site)
    return rows[0] if rows else (None, None)


def literal_sites(aud, value):
    rows = []
    for img in aud.images:
        pc = img.base & ~1
        while pc < img.end - 2:
            x = aud.decode_one(pc)
            if x is not None and x.literal_value == value:
                rows.append((img.name, pc, x.literal_addr, x.text))
            pc += 2
    return rows


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


def dump_context(aud, center, before=0x44, after=0x58, mark="SITE"):
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
            lab = FOCUS.get(norm) or FOCUS.get(norm | 1)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{lab}>" if lab else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            v = x.literal_value
            tag = ""
            if v == BASE:
                tag = "F0096060"
            elif v == SLOT0:
                tag = "F009607C"
            elif v == SLOT1:
                tag = "F0096080"
            elif v == COUNT:
                tag = "F0096084"
            elif v in FOCUS or (v & ~1) in FOCUS:
                tag = FOCUS.get(v) or FOCUS.get(v & ~1)
            extra.append(f"literal=0x{v:08X}" + (f"<{tag}>" if tag else ""))
        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = f" <{mark}>" if pc == center else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{flag}")
        pc += max(2, x.size)


class AddrExpr:
    __slots__ = ("off", "dyn")
    def __init__(self, off=0, dyn=""):
        self.off = int(off)
        self.dyn = dyn
    def copy(self):
        return AddrExpr(self.off, self.dyn)
    def add_imm(self, n):
        return AddrExpr(self.off + int(n), self.dyn)
    def add_dyn(self, term):
        d = term if not self.dyn else f"({self.dyn})+({term})"
        return AddrExpr(self.off, d)
    def __repr__(self):
        base = f"BASE{self.off:+#x}" if self.off else "BASE"
        return base + (f"+{self.dyn}" if self.dyn else "")


def is_read(t):
    return t.startswith(("ldr ", "ldrh ", "ldrb ", "ldrsh ", "ldrsb "))


def is_write(t):
    return t.startswith(("str ", "strh ", "strb "))


def scan_func(aud, fa, initial_base_regs=None, initial_slot_regs=None):
    addr = {}
    slotval = {}
    for r in initial_base_regs or []:
        addr[r] = AddrExpr(0, "ARG_BASE")
    for r, origin in (initial_slot_regs or {}).items():
        slotval[r] = origin

    events = []
    base_calls = []
    slot_calls = []

    for pc in sorted(fa.insns):
        x = fa.insns[pc]
        t = nt(x.text)

        ml = LDR_LIT_RE.match(t)
        if ml and x.literal_value is not None:
            dst = ml.group(1)
            if x.literal_value == BASE:
                addr[dst] = AddrExpr(0)
            else:
                addr.pop(dst, None)
            slotval.pop(dst, None)

        mi = INDIRECT_RE.match(t)
        if mi:
            reg = mi.group(2)
            if reg in slotval:
                events.append(("SLOT_EXECUTE", pc, x.text, reg, slotval[reg]))
            else:
                events.append(("INDIRECT_OTHER", pc, x.text, reg, None))

        mm = MEM_RE.search(t)

        if mm and mm.group("base") in slotval:
            b = mm.group("base")
            events.append(("SLOT_DEREF", pc, x.text, b, slotval[b]))

        access_is_slot_read = False
        if mm and mm.group("base") in addr:
            b = mm.group("base")
            idx = mm.group("idx")
            imm = int(mm.group("imm"), 0) if mm.group("imm") else 0
            e = addr[b].add_imm(imm)
            if idx:
                e = e.add_dyn(idx)

            if 0x1C <= e.off <= 0x24:
                kind = "BASE_READ" if is_read(t) else ("BASE_WRITE" if is_write(t) else "BASE_MEM")
                events.append((kind, pc, x.text, repr(e), {"off": e.off, "dyn": e.dyn}))

            if is_read(t) and (e.off in (0x1C, 0x20) or (e.off == 0x1C and e.dyn)):
                md = LOAD_DEST_RE.match(t)
                if md:
                    dst = md.group(1)
                    origin = f"{repr(e)}@0x{pc:08X}"
                    slotval[dst] = origin
                    access_is_slot_read = True
                    events.append(("SLOT_LOAD", pc, x.text, dst, origin))

        ms = STORE_SRC_RE.match(t)
        if ms and ms.group(1) in slotval:
            r = ms.group(1)
            events.append(("SLOT_STORE", pc, x.text, r, slotval[r]))

        mc = CMP_RE.match(t)
        if mc and mc.group(1) in slotval:
            r = mc.group(1)
            events.append(("SLOT_COMPARE", pc, x.text, r, slotval[r]))

        if x.is_call and x.target is not None:
            norm, via = aud.normalized_target(x.target)
            bargs = [(r, repr(addr[r])) for r in ("r0","r1","r2","r3") if r in addr]
            sargs = [(r, slotval[r]) for r in ("r0","r1","r2","r3") if r in slotval]
            if bargs:
                base_calls.append((pc, norm, bargs, via))
                events.append(("CALL_WITH_BASE", pc, x.text, f"0x{norm:08X}", bargs))
            if sargs:
                slot_calls.append((pc, norm, sargs, via))
                events.append(("CALL_WITH_SLOT", pc, x.text, f"0x{norm:08X}", sargs))

            for r in ("r0","r1","r2","r3"):
                addr.pop(r, None)
                slotval.pop(r, None)
            continue

        m = MOV_RE.match(t)
        if m:
            dst, src = m.groups()
            if src in addr:
                addr[dst] = addr[src].copy()
            else:
                addr.pop(dst, None)
            if src in slotval:
                slotval[dst] = slotval[src]
            else:
                slotval.pop(dst, None)
            continue

        m = ADDI_RE.match(t)
        if m:
            dst, src, imm = m.groups()
            src = src or dst
            if src in addr:
                addr[dst] = addr[src].add_imm(int(imm, 0))
            else:
                addr.pop(dst, None)
            slotval.pop(dst, None)
            continue

        m = SUBI_RE.match(t)
        if m:
            dst, src, imm = m.groups()
            src = src or dst
            if src in addr:
                addr[dst] = addr[src].add_imm(-int(imm, 0))
            else:
                addr.pop(dst, None)
            slotval.pop(dst, None)
            continue

        m = ADD3_RE.match(t)
        if m:
            dst, a, b = m.groups()
            if a in addr and b not in addr:
                addr[dst] = addr[a].add_dyn(b)
            elif b in addr and a not in addr:
                addr[dst] = addr[b].add_dyn(a)
            else:
                addr.pop(dst, None)
            slotval.pop(dst, None)
            continue

        m = LSL_RE.match(t)
        if m:
            dst = m.group(1)
            addr.pop(dst, None)
            slotval.pop(dst, None)
            continue

        md = LOAD_DEST_RE.match(t)
        if md:
            dst = md.group(1)
            if not access_is_slot_read:
                slotval.pop(dst, None)
            if not (ml and x.literal_value == BASE):
                addr.pop(dst, None)
            continue

        gd = re.match(rf"^[a-z.]+\s+({REG})\b", t)
        if gd and not t.startswith(("cmp ", "tst ", "str", "push", "stm", "b", "bl")):
            dst = gd.group(1)
            if not (MOV_RE.match(t) or ADDI_RE.match(t) or SUBI_RE.match(t) or ADD3_RE.match(t)):
                addr.pop(dst, None)
                slotval.pop(dst, None)

    return events, base_calls, slot_calls


def focus_literals(fa):
    out = []
    for row in fa.literals:
        if row and isinstance(row[-1], int):
            v = row[-1]
            lab = FOCUS.get(v) or FOCUS.get(v & ~1)
            if lab:
                out.append((row[0], v, lab))
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

    hline("B. A.66 DERIVED WORKING-SLOT MAP")
    print(f"F0096060 base      = 0x{BASE:08X}")
    print(f"working slot 0     = 0x{SLOT0:08X}  [base+0x1C]")
    print(f"working slot 1     = 0x{SLOT1:08X}  [base+0x20]")
    print(f"working slot count = 0x{COUNT:08X}  [base+0x24]")
    print(f"source side table  = 0x{SOURCE_SIDE:08X}")
    print("A.66 FACT: 1033E770 stores r2 -> [r0+0x1C+r1*4] after bounds-checking r1.")
    dump_context(aud, COPIER, before=0x04, after=0x16, mark="COPIER")

    hline("C. RAW / DIRECT POINTER OCCURRENCES")
    for value, label in ((BASE,"BASE"),(SLOT0,"SLOT0"),(SLOT1,"SLOT1"),(COUNT,"COUNT")):
        print(f"\n{label} 0x{value:08X}")
        for img in aud.images:
            hits = raw_u32_hits(img, value)
            print(f"  {img.name}: raw_u32={len(hits)}")
            for a in hits[:40]:
                print(f"    0x{a:08X}")

    hline("D. ROOT FUNCTIONS THAT LOAD F0096060")
    sites = literal_sites(aud, BASE)
    owners = {}
    owner_sites = defaultdict(list)
    print(f"literal_sites={len(sites)}")
    for image_name, site, litaddr, text in sites:
        owner, fa = best_owner(aud, site)
        print(
            f"{image_name} site=0x{site:08X} pool=0x{litaddr:08X} "
            + (f"owner=0x{owner:08X}" if owner is not None else "owner=UNKNOWN")
        )
        if owner is not None:
            owners[owner] = fa
            owner_sites[owner].append(site)

    hline("E. ROOT WORKING-SLOT ACCESSES / USES")
    root_results = []
    all_base_calls = []
    all_slot_calls = []

    for entry, fa in sorted(owners.items()):
        events, base_calls, slot_calls = scan_func(aud, fa)
        relevant = [e for e in events if e[0] in {
            "BASE_READ","BASE_WRITE","SLOT_LOAD","SLOT_DEREF","SLOT_STORE",
            "SLOT_COMPARE","SLOT_EXECUTE","CALL_WITH_SLOT"
        }]
        if not relevant and not base_calls:
            continue
        root_results.append((entry, fa, events, base_calls, slot_calls))
        all_base_calls.extend((entry,)+x for x in base_calls)
        all_slot_calls.extend((entry,)+x for x in slot_calls)

        print(f"\nOWNER 0x{entry:08X} image={fa.image}")
        for e in relevant:
            print(f"  {e}")
        if base_calls:
            print("  base-derived calls:")
            for x in base_calls:
                print(f"    {x}")
        for site, v, lab in focus_literals(fa):
            print(f"  FOCUS 0x{site:08X}: 0x{v:08X} <{lab}>")

    hline("F. ONE-HOP CALLEES RECEIVING F0096060-DERIVED BASE")
    work = {}
    for parent, site, target, bargs, via in all_base_calls:
        for reg, expr in bargs:
            key = (target, reg)
            work.setdefault(key, []).append((parent, site, expr, via))

    onehop_results = []
    for (target, reg), rows in sorted(work.items())[:120]:
        try:
            cfa = audit_func(aud, target)
        except Exception as exc:
            print(f"\nCALLEE 0x{target:08X} initial_base={reg}: audit failed {exc!r}")
            continue

        events, base_calls2, slot_calls2 = scan_func(aud, cfa, initial_base_regs=[reg])
        relevant = [e for e in events if e[0] in {
            "BASE_READ","BASE_WRITE","SLOT_LOAD","SLOT_DEREF","SLOT_STORE",
            "SLOT_COMPARE","SLOT_EXECUTE","CALL_WITH_SLOT"
        }]
        if not relevant:
            continue

        onehop_results.append((target, reg, cfa, events, rows))
        print(f"\nCALLEE 0x{target:08X} image={cfa.image} initial_base={reg}")
        print(f"  reached_from={len(rows)} root call(s)")
        for parent, site, expr, via in rows[:10]:
            print(f"    parent=0x{parent:08X} site=0x{site:08X} expr={expr} via={via or 'DIRECT'}")
        for e in relevant:
            print(f"  {e}")
        for site, v, lab in focus_literals(cfa):
            print(f"  FOCUS 0x{site:08X}: 0x{v:08X} <{lab}>")

    hline("G. ONE-HOP CALLEES RECEIVING SLOT-LOADED VALUES")
    slot_work = {}
    for parent, site, target, sargs, via in all_slot_calls:
        for reg, origin in sargs:
            key = (target, reg)
            slot_work.setdefault(key, []).append((parent, site, origin, via))

    slot_callee_findings = []
    for (target, reg), rows in sorted(slot_work.items())[:120]:
        try:
            cfa = audit_func(aud, target)
        except Exception as exc:
            print(f"\nCALLEE 0x{target:08X} initial_slot={reg}: audit failed {exc!r}")
            continue
        events, _, _ = scan_func(
            aud, cfa,
            initial_slot_regs={reg: f"CALLER_SLOT->{reg}"}
        )
        relevant = [e for e in events if e[0] in {
            "SLOT_DEREF","SLOT_STORE","SLOT_COMPARE","SLOT_EXECUTE","CALL_WITH_SLOT"
        }]
        if not relevant:
            continue
        slot_callee_findings.append((target, reg, relevant, rows))
        print(f"\nCALLEE 0x{target:08X} image={cfa.image} initial_slot={reg}")
        for parent, site, origin, via in rows[:10]:
            print(f"  from parent=0x{parent:08X} site=0x{site:08X} origin={origin}")
        for e in relevant:
            print(f"  {e}")

    hline("H. CONTEXTS FOR STRONGEST SLOT READERS")
    scored = []
    for entry, fa, events, base_calls, slot_calls in root_results:
        loads = sum(1 for e in events if e[0] == "SLOT_LOAD")
        deref = sum(1 for e in events if e[0] == "SLOT_DEREF")
        execs = sum(1 for e in events if e[0] == "SLOT_EXECUTE")
        callslot = sum(1 for e in events if e[0] == "CALL_WITH_SLOT")
        score = loads*3 + deref*6 + execs*20 + callslot*5
        if score:
            scored.append((score, entry, fa, events))
    for target, reg, cfa, events, rows in onehop_results:
        loads = sum(1 for e in events if e[0] == "SLOT_LOAD")
        deref = sum(1 for e in events if e[0] == "SLOT_DEREF")
        execs = sum(1 for e in events if e[0] == "SLOT_EXECUTE")
        callslot = sum(1 for e in events if e[0] == "CALL_WITH_SLOT")
        score = loads*3 + deref*6 + execs*20 + callslot*5
        if score:
            scored.append((score, target, cfa, events))
    scored.sort(key=lambda x: (-x[0], x[1]))

    for score, entry, fa, events in scored[:12]:
        print(f"\nOWNER/CALLEE 0x{entry:08X} score={score}")
        sites2 = sorted({e[1] for e in events if e[0] in ("SLOT_LOAD","SLOT_DEREF","SLOT_EXECUTE","CALL_WITH_SLOT")})
        for site in sites2[:8]:
            dump_context(aud, site, before=0x38, after=0x48, mark="WORK_SLOT_USE")

    hline("I. AUDIO/FOCUS CO-LOCATION")
    hits = []
    seen_funcs = set()
    for _, entry, fa, _ in scored:
        if entry in seen_funcs:
            continue
        seen_funcs.add(entry)
        for site, v, lab in focus_literals(fa):
            hits.append((entry, site, v, lab))
    if hits:
        for entry, site, v, lab in hits:
            print(f"func=0x{entry:08X} site=0x{site:08X} value=0x{v:08X} <{lab}>")
    else:
        print("NONE")

    hline("J. DECISION GATE")
    all_events = []
    for _, _, events, _, _ in root_results:
        all_events.extend(events)
    for _, _, _, events, _ in onehop_results:
        all_events.extend(events)
    for _, _, relevant, _ in slot_callee_findings:
        all_events.extend(relevant)

    counts = defaultdict(int)
    for e in all_events:
        counts[e[0]] += 1

    print(f"SLOT_LOAD          = {counts['SLOT_LOAD']}")
    print(f"SLOT_DEREF         = {counts['SLOT_DEREF']}")
    print(f"SLOT_STORE         = {counts['SLOT_STORE']}")
    print(f"SLOT_COMPARE       = {counts['SLOT_COMPARE']}")
    print(f"CALL_WITH_SLOT     = {counts['CALL_WITH_SLOT']}")
    print(f"SLOT_EXECUTE       = {counts['SLOT_EXECUTE']}")
    print(f"one-hop base consumers with slot use = {len(onehop_results)}")
    print(f"one-hop slot-value consumers          = {len(slot_callee_findings)}")

    if counts["SLOT_EXECUTE"]:
        print(
            "RESULT: a value copied from F00960A0 into the F009607C working slots "
            "is mechanically proven to reach indirect execution."
        )
        print(
            "NEXT: recover the exact item/slot producer for that executable value and "
            "compare it with the native Audio launch chain."
        )
    elif counts["SLOT_DEREF"] or counts["CALL_WITH_SLOT"]:
        print(
            "RESULT: working-slot values are consumed as data/context or passed to helpers; "
            "no direct callback execution is proven in the bounded two-stage path."
        )
        print(
            "NEXT: classify the strongest slot-value consumer. If the use is UI/resource/layout, "
            "close F00960A0/F009607C as non-action state and pivot to selection/event dispatch."
        )
    elif counts["SLOT_LOAD"]:
        print(
            "RESULT: readers of the F009607C working slots are proven, but their loaded values "
            "remain opaque in the bounded path."
        )
        print(
            "NEXT: extend one more value-flow boundary only from the proven reader(s), not by "
            "repeating global xref scans."
        )
    else:
        print(
            "RESULT: no working-slot reader was recovered from direct or one-hop F0096060 base flow."
        )
        print(
            "NEXT: pivot to APIs receiving the current UI object rather than the global base."
        )

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a67_f009607c_working_slot_consumer_audit.txt"
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
