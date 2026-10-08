#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.66 - 0x1033E770 side-table value semantic audit

STRICTLY OFFLINE.
Reads only canonical extracted firmware images from the local repository.
No USB/COM/BROM/DA/device access. No flash write/erase/repack/patch.

A.65 proved a real indirect consumer of the F00960A0 area:
  0x103078A0 loads F00960A0[current_index*8] and dereferences byte 0 / byte 1.
  0x103078D0 loads dwords from F00960A0[current_index*8 + sub_index*4]
  and passes each dword as r2 to 0x1033E770(base=F0096060, sub_index, value).

This gate resolves the NEW unknown: what semantic role does r2 have inside
0x1033E770 and one direct callee boundary beyond it?

Goals:
1. Dump and classify 0x1033E770.
2. Taint-track incoming r2: pointer dereference, store, compare/arithmetic,
   call argument, or indirect BLX/BX.
3. Audit any direct callee that receives tainted r2-derived data.
4. Census all direct callers of 0x1033E770 and compare their argument shapes.
5. Re-state the exact 0x103078A0 descriptor gate and the 0x103078D0 -> 1033E770
   transfer so the decision is based on proven dataflow.
6. Decide whether F00960A0 is best classified as descriptor/context state,
   action/callback state, or still unknown.

This does NOT revisit B709/B702 topology, ROOT_MAPPER, F03BB8xx, or S13.2A.

Output:
research/f2/work/reports/s13_5a66_1033e770_side_value_semantics.txt
"""

from __future__ import annotations

import re
import sys
import traceback
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path

TITLE = "S13.5A.66 - 1033E770 SIDE-VALUE SEMANTICS"

TARGET = 0x1033E770
SOURCE_OWNER = 0x10307874
SIDE_BASE = 0xF00960A0
GLOBAL_BASE = 0xF0096060
KNOWN_WRITER_SENTINEL = 0x1039F2D4
KNOWN_RAM_VALUE = 0xF0115FBC

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
MOV_RE = re.compile(rf"^(?:movs?|mov)\s+({REG}),\s*({REG})$", re.I)
ADDI_RE = re.compile(rf"^adds?\s+({REG}),\s*(?:({REG}),\s*)?#(0x[0-9a-f]+|\d+)$", re.I)
SUBI_RE = re.compile(rf"^subs?\s+({REG}),\s*(?:({REG}),\s*)?#(0x[0-9a-f]+|\d+)$", re.I)
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
        return aud.audit_func(addr & ~1, max_span=0x2400, max_insns=4000)
    except TypeError:
        return aud.audit_func(addr & ~1)


def reverse_calls(aud, targets):
    targets = {x & ~1 for x in targets}
    out = {x: [] for x in targets}
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


def dump_function(aud, fa, marks=None):
    marks = marks or {}
    for addr in sorted(fa.insns):
        x = fa.insns[addr]
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
            lab = FOCUS.get(v) or FOCUS.get(v & ~1)
            extra.append(f"literal=0x{v:08X}" + (f"<{lab}>" if lab else ""))
            s = aud.string_at(v)
            if s:
                extra.append(f'STR="{s}"')
        suffix = (" ; " + " ".join(extra)) if extra else ""
        mark = f" <{marks[addr]}>" if addr in marks else ""
        print(f"0x{addr:08X}: {x.text}{suffix}{mark}")


def dump_context(aud, center, before=0x48, after=0x60, mark="SITE"):
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
            lab = FOCUS.get(v) or FOCUS.get(v & ~1)
            extra.append(f"literal=0x{v:08X}" + (f"<{lab}>" if lab else ""))
        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = f" <{mark}>" if pc == center else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{flag}")
        pc += max(2, x.size)


def function_strings(aud, fa):
    seen, out = set(), []
    for row in fa.literals:
        if not row or not isinstance(row[-1], int):
            continue
        v = row[-1]
        s = aud.string_at(v)
        if s and s not in seen:
            seen.add(s)
            out.append((v, s))
    return out


def classify_addr(aud, v):
    if v in FOCUS:
        return FOCUS[v]
    if (v & ~1) in FOCUS:
        return FOCUS[v & ~1]
    img = aud.image_for(v & ~1)
    if img is None:
        if 0xF0000000 <= v <= 0xFFFFFFFF:
            return "RAM/GLOBAL"
        return "RAW"
    if v & 1:
        return f"{img.name}_THUMB_PTR?"
    return f"{img.name}_PTR/DATA"


def taint_r2(aud, fa):
    """
    Conservative taint of incoming r2.
    taint[reg] = textual origin rooted at ARG_R2 or a dereference of it.
    """
    taint = {"r2": "ARG_R2"}
    events = []
    tainted_callees = []

    for addr in sorted(fa.insns):
        x = fa.insns[addr]
        t = nt(x.text)

        # Indirect control first.
        mi = INDIRECT_RE.match(t)
        if mi:
            reg = mi.group(2)
            if reg in taint:
                events.append(("INDIRECT_TAINT", addr, reg, taint[reg], x.text))
            else:
                events.append(("INDIRECT_OTHER", addr, reg, "", x.text))

        # Any memory dereference with tainted base.
        mm = MEM_RE.search(t)
        if mm:
            base = mm.group("base")
            if base in taint:
                kind = "MEM_FROM_TAINT"
                events.append((kind, addr, base, taint[base], x.text))
                md = LOAD_DEST_RE.match(t)
                if md:
                    taint[md.group(1)] = f"DEREF({taint[base]})@0x{addr:08X}"

        # Store tainted value.
        ms = STORE_SRC_RE.match(t)
        if ms and ms.group(1) in taint:
            reg = ms.group(1)
            events.append(("STORE_TAINT", addr, reg, taint[reg], x.text))

        # Compare/test tainted value.
        mc = CMP_RE.match(t)
        if mc and mc.group(1) in taint:
            reg = mc.group(1)
            events.append(("COMPARE_TAINT", addr, reg, taint[reg], x.text))

        # At direct calls, note tainted argument registers.
        if x.is_call and x.target is not None:
            norm, via = aud.normalized_target(x.target)
            args = [(r, taint[r]) for r in ("r0","r1","r2","r3") if r in taint]
            if args:
                events.append(("CALL_WITH_TAINT", addr, f"0x{norm:08X}", repr(args), x.text))
                tainted_callees.append((addr, norm, args, via))
            # AAPCS volatile clobber.
            for r in ("r0","r1","r2","r3"):
                taint.pop(r, None)
            continue

        # MOV propagation.
        m = MOV_RE.match(t)
        if m:
            dst, src = m.groups()
            if src in taint:
                taint[dst] = taint[src]
            else:
                taint.pop(dst, None)
            continue

        # ADD/SUB immediate preserves pointer/scalar taint.
        m = ADDI_RE.match(t)
        if m:
            dst, src, imm = m.groups()
            src = src or dst
            if src in taint:
                taint[dst] = f"{taint[src]}+{int(imm,0):#x}"
            else:
                taint.pop(dst, None)
            continue

        m = SUBI_RE.match(t)
        if m:
            dst, src, imm = m.groups()
            src = src or dst
            if src in taint:
                taint[dst] = f"{taint[src]}-{int(imm,0):#x}"
            else:
                taint.pop(dst, None)
            continue

        # Generic load not already marked from tainted base overwrites dest.
        md = LOAD_DEST_RE.match(t)
        if md:
            dst = md.group(1)
            if not (mm and mm.group("base") in taint):
                taint.pop(dst, None)
            continue

        # Conservative generic destination clobber.
        m = re.match(rf"^[a-z.]+\s+({REG})\b", t)
        if m and not t.startswith(("cmp ", "tst ", "str", "push", "stm", "b", "bl")):
            dst = m.group(1)
            if not (MOV_RE.match(t) or ADDI_RE.match(t) or SUBI_RE.match(t)):
                taint.pop(dst, None)

    return events, tainted_callees


def caller_arg_window(aud, site, owner_fa):
    addrs = [a for a in sorted(owner_fa.insns) if site - 0x28 <= a <= site]
    return [(a, owner_fa.insns[a].text) for a in addrs]


def raw_bytes(aud, addr, n=24):
    img = aud.image_for(addr)
    if img is None:
        return None
    off = addr - img.base
    return img.data[off:off+n]


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

    hline("B. A.65 PROVEN SOURCE DATAFLOW")
    print(
        "At 0x103078A0 the first dword at F00960A0[current_index*8] is loaded "
        "and immediately dereferenced as a data pointer (byte 0 / byte 1)."
    )
    dump_context(aud, 0x103078A0, before=0x18, after=0x22, mark="FIRST_DWORD_DESCRIPTOR_GATE")
    print()
    print(
        "At 0x103078D0 a dword from F00960A0[current_index*8 + sub_index*4] "
        "is loaded into r2 and passed to 0x1033E770."
    )
    dump_context(aud, 0x103078D0, before=0x16, after=0x18, mark="SIDE_DWORD_TO_R2")

    hline("C. 0x1033E770 FUNCTION BODY")
    fa = audit_func(aud, TARGET)
    print(f"image={fa.image} insns={len(fa.insns)} calls={len(fa.calls)} literals={len(fa.literals)}")
    dump_function(aud, fa)
    strings = function_strings(aud, fa)
    print("\nStrings:")
    if strings:
        for v, s in strings:
            print(f'  0x{v:08X}: "{s}"')
    else:
        print("  NONE")

    hline("D. INCOMING r2 TAINT CLASSIFICATION")
    events, tainted_callees = taint_r2(aud, fa)
    print(f"taint_events={len(events)}")
    for kind, addr, a, b, text in events:
        print(f"{kind:18s} 0x{addr:08X}: {text} ; {a} ; {b}")

    summary = defaultdict(int)
    for e in events:
        summary[e[0]] += 1
    print("\nSummary:")
    for k in sorted(summary):
        print(f"  {k}={summary[k]}")

    hline("E. ONE-HOP CALLEES RECEIVING r2-DERIVED DATA")
    unique = {}
    for site, target, args, via in tainted_callees:
        unique.setdefault(target, []).append((site, args, via))

    if not unique:
        print("NONE")
    for target, rows in sorted(unique.items()):
        print(f"\nCALLEE 0x{target:08X} tainted_calls={len(rows)}")
        for site, args, via in rows:
            print(f"  callsite=0x{site:08X} args={args} via={via or 'DIRECT'}")
        try:
            cfa = audit_func(aud, target)
            print(f"  image={cfa.image} insns={len(cfa.insns)} calls={len(cfa.calls)}")
            dump_function(aud, cfa)
            cevents, _ = taint_r2(aud, cfa)
            # Do not claim this is exact positional continuation unless taint remains in r2;
            # this secondary dump is contextual only.
            if cevents:
                print("  NOTE: independent incoming-r2 taint profile of callee:")
                for ev in cevents[:80]:
                    print(f"    {ev}")
        except Exception as exc:
            print(f"  audit failed: {exc!r}")

    hline("F. ALL DIRECT CALLERS OF 0x1033E770")
    rev = reverse_calls(aud, {TARGET})
    callers = rev.get(TARGET, [])
    print(f"direct_callers={len(callers)}")
    for image_name, site, raw, via in callers:
        owner, ofa = best_owner(aud, site)
        print(
            f"\n{image_name} callsite=0x{site:08X} via={via or 'DIRECT'} "
            + (f"owner=0x{owner:08X}" if owner is not None else "owner=UNKNOWN")
        )
        if ofa is not None:
            for addr, text in caller_arg_window(aud, site, ofa):
                print(f"  0x{addr:08X}: {text}")
        dump_context(aud, site, before=0x34, after=0x28, mark="CALL_1033E770")

    hline("G. KNOWN SIDE-TABLE VALUE SHAPES")
    b = raw_bytes(aud, KNOWN_WRITER_SENTINEL, 24)
    print(f"0x{KNOWN_WRITER_SENTINEL:08X} classification={classify_addr(aud, KNOWN_WRITER_SENTINEL)}")
    if b is not None:
        print("  bytes=" + b.hex(" "))
        print(f"  byte0=0x{b[0]:02X} byte1=0x{b[1]:02X}")
        print(
            "  A.65 descriptor gate would reject this value when both first bytes are zero."
        )
    print(f"\n0x{KNOWN_RAM_VALUE:08X} classification={classify_addr(aud, KNOWN_RAM_VALUE)}")
    print("  static bytes unavailable because this is RAM/global space.")

    hline("H. AUDIO/FOCUS LITERAL CO-LOCATION")
    focus_hits = []
    for row in fa.literals:
        if row and isinstance(row[-1], int):
            v = row[-1]
            lab = FOCUS.get(v) or FOCUS.get(v & ~1)
            if lab:
                focus_hits.append((row[0], v, lab))
    if focus_hits:
        for site, v, lab in focus_hits:
            print(f"0x{site:08X}: 0x{v:08X} <{lab}>")
    else:
        print("NONE")

    hline("I. DECISION GATE")
    mem = summary.get("MEM_FROM_TAINT", 0)
    stores = summary.get("STORE_TAINT", 0)
    calls = summary.get("CALL_WITH_TAINT", 0)
    indirect = summary.get("INDIRECT_TAINT", 0)
    compares = summary.get("COMPARE_TAINT", 0)

    print(f"r2-derived memory dereferences = {mem}")
    print(f"r2-derived stores              = {stores}")
    print(f"r2-derived direct-call uses    = {calls}")
    print(f"r2-derived indirect control    = {indirect}")
    print(f"r2-derived compare/test        = {compares}")

    if indirect:
        print(
            "RESULT: executable callback semantics are proven for at least one r2-derived path."
        )
        print(
            "NEXT: enumerate producer values by visible item and compare with the native Audio chain."
        )
    elif mem or stores or calls:
        print(
            "RESULT: 0x1033E770 consumes the side-table dword as data/context (pointer/state) "
            "within the bounded path; direct callback execution is not proven."
        )
        print(
            "NEXT: classify the exact destination/helper receiving this context. If it is rendering/"
            "layout metadata, close F00960A0 as non-action state and pivot to the selection/event "
            "dispatcher for visible items."
        )
    else:
        print(
            "RESULT: bounded static use of incoming r2 remains opaque."
        )
        print(
            "NEXT: inspect all caller shapes and the first callee boundary before assigning semantics."
        )

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a66_1033e770_side_value_semantics.txt"
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
