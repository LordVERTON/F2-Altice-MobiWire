#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.65 - F00960xx neighboring-base / indirect side-table consumer audit

STRICTLY OFFLINE.
Reads only canonical extracted firmware images from the local repository.
No USB/COM/BROM/DA/device access. No flash write/erase/repack/patch.

A.64 proved that exact references to F00960A0 are writers only:
  - 102FFEC8 writes value -> F00960A0[index*8]
  - 1039F2A0 writes an ADR-derived pointer
  - 103A1D58 writes F0115F8C+0x30
and found no direct reference to F00960A4.

The remaining new question is whether readers reach the same side-table
INDIRECTLY through a neighboring F00960xx base (e.g. F0096060 + offset)
or through an address derived from such a base.

This gate:
1. inventories every code literal in F0096000..F0096100;
2. recovers owner functions;
3. symbolically propagates neighboring-base addresses through MOV/ADD/SUB;
4. reports reads/writes whose effective constant component lands in the
   F00960A0/F00960A4 per-item area;
5. tracks values loaded from that area into BLX/BX register targets;
6. classifies A.64's two new direct writers as code-pointer-like vs data/context.

It does NOT revisit B709/B702 topology, ROOT_MAPPER, or the old S13.2A POC.

Output:
research/f2/work/reports/s13_5a65_f00960xx_neighbor_indirect_consumer_audit.txt
"""

from __future__ import annotations

import re
import sys
import traceback
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path

TITLE = "S13.5A.65 - F00960XX NEIGHBOR / INDIRECT CONSUMER AUDIT"

WINDOW_LO = 0xF0096000
WINDOW_HI = 0xF0096100
TABLE = 0xF00960A0
TABLE_PLUS4 = 0xF00960A4
TABLE_RANGE_LO = TABLE
TABLE_RANGE_HI = TABLE + 0x80  # first 16 x 8-byte item slots

KNOWN_WRITERS = {
    0x102FFEC8: "SIDE_TABLE_WRITER",
    0x1039F2A0: "DIRECT_WRITER_ADR",
    0x103A1D58: "DIRECT_WRITER_RAM_PTR",
}

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
ADDI_RE = re.compile(
    rf"^adds?\s+({REG}),\s*(?:({REG}),\s*)?#(0x[0-9a-f]+|\d+)$", re.I
)
SUBI_RE = re.compile(
    rf"^subs?\s+({REG}),\s*(?:({REG}),\s*)?#(0x[0-9a-f]+|\d+)$", re.I
)
LSL_RE = re.compile(rf"^lsls?\s+({REG}),\s*({REG}),\s*#(0x[0-9a-f]+|\d+)$", re.I)
MEM_RE = re.compile(
    rf"\[(?P<base>{REG}|sp|lr)"
    rf"(?:,\s*(?P<idx>{REG}))?"
    rf"(?:,\s*#(?P<imm>-?(?:0x[0-9a-f]+|\d+)))?\]",
    re.I,
)
LOAD_DEST_RE = re.compile(rf"^ldr(?:b|h|sb|sh)?\s+({REG}),", re.I)
INDIRECT_RE = re.compile(rf"^(blx|bx)\s+({REG})$", re.I)
ADR_RE = re.compile(rf"^adr\s+({REG}),\s*#(0x[0-9a-f]+|\d+)$", re.I)


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
        return aud.audit_func(addr & ~1, max_span=0x3000, max_insns=5000)
    except TypeError:
        return aud.audit_func(addr & ~1)


def candidate_entries(aud, site, back=0x900):
    img = aud.image_for(site)
    if img is None:
        return []
    start = max(img.base, site - back) & ~1
    out = []
    seen = set()
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


def classify_addr(aud, v):
    if v in FOCUS:
        return FOCUS[v]
    if (v & ~1) in FOCUS:
        return FOCUS[v & ~1]
    img = aud.image_for(v & ~1)
    if img is None:
        if WINDOW_LO <= v < WINDOW_HI:
            return "F00960xx_RAM"
        if 0xF0000000 <= v <= 0xFFFFFFFF:
            return "RAM/GLOBAL"
        return "RAW"
    x = aud.decode_one(v & ~1)
    if x is not None and (v & 1):
        return f"{img.name}_THUMB_PTR?"
    return f"{img.name}_PTR/DATA"


def literal_sites_in_window(aud):
    rows = []
    for img in aud.images:
        pc = img.base & ~1
        while pc < img.end - 2:
            x = aud.decode_one(pc)
            if x is not None and x.literal_value is not None:
                v = x.literal_value
                if WINDOW_LO <= v < WINDOW_HI:
                    rows.append((img.name, pc, x.literal_addr, v, x.text))
            pc += 2
    return rows


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


def dump_context(aud, center, before=0x50, after=0x70, mark="SITE"):
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
        if x.literal_value is not None:
            v = x.literal_value
            tag = ""
            if WINDOW_LO <= v < WINDOW_HI:
                tag = "F00960XX"
            elif v in FOCUS or (v & ~1) in FOCUS:
                tag = FOCUS.get(v) or FOCUS.get(v & ~1)
            extra.append(f"literal=0x{v:08X}" + (f"<{tag}>" if tag else ""))
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            extra.append(f"target=0x{norm:08X}" + (f"[{via}]" if via else ""))
        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = f" <{mark}>" if pc == center else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{flag}")
        pc += max(2, x.size)


class Expr:
    """constant base plus textual dynamic term; sufficient for address-family tracing."""
    __slots__ = ("const", "dyn")

    def __init__(self, const, dyn=""):
        self.const = const & 0xFFFFFFFF
        self.dyn = dyn

    def copy(self):
        return Expr(self.const, self.dyn)

    def add_imm(self, n):
        return Expr((self.const + n) & 0xFFFFFFFF, self.dyn)

    def add_dyn(self, term):
        if not term:
            return self.copy()
        dyn = term if not self.dyn else f"({self.dyn})+({term})"
        return Expr(self.const, dyn)

    def __repr__(self):
        return f"0x{self.const:08X}" + (f"+{self.dyn}" if self.dyn else "")


def is_read(t):
    return t.startswith(("ldr ", "ldrh ", "ldrb ", "ldrsh ", "ldrsb "))


def is_write(t):
    return t.startswith(("str ", "strh ", "strb "))


def generic_dest(t):
    m = re.match(rf"^[a-z.]+\s+({REG})\b", t)
    return m.group(1) if m else None


def symbolic_scan(aud, fa):
    """
    Track only addresses derived from F0096000..F00960FF literals.
    Separately track the provenance of loaded values from the side-table area.
    """
    addr_expr = {}
    value_origin = {}  # reg -> (load_site, effective_base_const, text)
    events = []

    for addr in sorted(fa.insns):
        x = fa.insns[addr]
        t = nt(x.text)

        # Record indirect control before clobbering anything.
        mi = INDIRECT_RE.match(t)
        if mi:
            reg = mi.group(2)
            origin = value_origin.get(reg)
            events.append({
                "kind": "INDIRECT",
                "site": addr,
                "text": x.text,
                "reg": reg,
                "origin": origin,
            })

        # Literal load of neighboring F00960xx base.
        ml = LDR_LIT_RE.match(t)
        if ml and x.literal_value is not None:
            dst = ml.group(1)
            if WINDOW_LO <= x.literal_value < WINDOW_HI:
                addr_expr[dst] = Expr(x.literal_value)
            else:
                addr_expr.pop(dst, None)
            value_origin.pop(dst, None)

        # Memory use via a derived address.
        mm = MEM_RE.search(t)
        if mm:
            base = mm.group("base")
            idx = mm.group("idx")
            imm = int(mm.group("imm"), 0) if mm.group("imm") else 0
            if base in addr_expr:
                e = addr_expr[base].add_imm(imm)
                if idx:
                    e = e.add_dyn(idx)
                near = TABLE - 0x40 <= e.const < TABLE + 0x100
                if near:
                    kind = "READ" if is_read(t) else ("WRITE" if is_write(t) else "MEM")
                    ev = {
                        "kind": kind,
                        "site": addr,
                        "text": x.text,
                        "expr": repr(e),
                        "const": e.const,
                        "dyn": e.dyn,
                    }
                    events.append(ev)
                    if kind == "READ":
                        md = LOAD_DEST_RE.match(t)
                        if md:
                            value_origin[md.group(1)] = (addr, e.const, x.text)

        # Calls clobber volatile regs.
        if x.is_call:
            for r in ("r0", "r1", "r2", "r3"):
                addr_expr.pop(r, None)
                value_origin.pop(r, None)
            continue

        # Register copies.
        m = MOV_RE.match(t)
        if m:
            dst, src = m.groups()
            if src in addr_expr:
                addr_expr[dst] = addr_expr[src].copy()
            else:
                addr_expr.pop(dst, None)
            if src in value_origin:
                value_origin[dst] = value_origin[src]
            else:
                value_origin.pop(dst, None)
            continue

        # Add/sub immediate to an address expression.
        m = ADDI_RE.match(t)
        if m:
            dst, src, imm = m.groups()
            src = src or dst
            if src in addr_expr:
                addr_expr[dst] = addr_expr[src].add_imm(int(imm, 0))
            else:
                addr_expr.pop(dst, None)
            value_origin.pop(dst, None)
            continue

        m = SUBI_RE.match(t)
        if m:
            dst, src, imm = m.groups()
            src = src or dst
            if src in addr_expr:
                addr_expr[dst] = addr_expr[src].add_imm(-int(imm, 0))
            else:
                addr_expr.pop(dst, None)
            value_origin.pop(dst, None)
            continue

        # Register addition: preserve whichever side is a tracked address.
        m = ADD3_RE.match(t)
        if m:
            dst, a, b = m.groups()
            if a in addr_expr and b not in addr_expr:
                addr_expr[dst] = addr_expr[a].add_dyn(b)
            elif b in addr_expr and a not in addr_expr:
                addr_expr[dst] = addr_expr[b].add_dyn(a)
            else:
                addr_expr.pop(dst, None)
            value_origin.pop(dst, None)
            continue

        # LSL destroys an address base, but remember textual scaling isn't needed;
        # subsequent ADD with this register is represented as a dynamic term.
        m = LSL_RE.match(t)
        if m:
            dst = m.group(1)
            addr_expr.pop(dst, None)
            value_origin.pop(dst, None)
            continue

        # Generic load sets data value and overwrites any address expression unless
        # it was already handled as literal load.
        if is_read(t):
            d = generic_dest(t)
            if d and not (ml and x.literal_value is not None):
                addr_expr.pop(d, None)
                # value_origin is set above only if the load came from derived side table;
                # otherwise clear it.
                if not (mm and mm.group("base") in addr_expr):
                    value_origin.pop(d, None)
            continue

        # Conservative clobber on obvious destination writes.
        d = generic_dest(t)
        if d and not t.startswith(("cmp ", "tst ", "str", "push", "stm", "b", "bl")):
            if not (MOV_RE.match(t) or ADDI_RE.match(t) or SUBI_RE.match(t) or ADD3_RE.match(t)):
                addr_expr.pop(d, None)
                value_origin.pop(d, None)

    return events


def dump_raw(aud, addr, size=32):
    img = aud.image_for(addr)
    if img is None:
        print(f"0x{addr:08X}: outside firmware images ({classify_addr(aud, addr)})")
        return
    off = addr - img.base
    data = img.data[off:off+size]
    print(f"0x{addr:08X} {img.name} bytes[{len(data)}] = {data.hex(' ')}")


def adr_target(addr, text):
    m = ADR_RE.match(nt(text))
    if not m:
        return None
    imm = int(m.group(2), 0)
    # Thumb ADR uses Align(PC,4) with PC = instruction address + 4.
    return (((addr + 4) & ~3) + imm) & 0xFFFFFFFF


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

    hline("B. A.64 WRITER-VALUE CLASSIFICATION")
    # 1039F2C8: ADR r1,#8 -> value stored by 1039F2CA.
    x = aud.decode_one(0x1039F2C8)
    if x is not None:
        target = adr_target(x.addr, x.text)
        print(f"1039F2C8: {x.text}")
        print(f"  ADR target = {('0x%08X' % target) if target is not None else 'UNKNOWN'}")
        if target is not None:
            print(f"  classification = {classify_addr(aud, target)}")
            print(f"  bit0 = {target & 1}")
            dump_raw(aud, target, 32)

    ram_ptr = 0xF0115F8C + 0x30
    print(f"\n103A1D58 path stores F0115F8C+0x30 = 0x{ram_ptr:08X}")
    print(f"  classification = {classify_addr(aud, ram_ptr)}")
    print("Interpretation guard: these examples argue against treating every side-table dword as a direct code callback.")

    hline("C. ALL F0096000..F00960FF CODE LITERALS")
    sites = literal_sites_in_window(aud)
    print(f"neighbor_literal_loads={len(sites)}")
    owners = {}
    owner_sites = defaultdict(list)

    for image_name, site, litaddr, value, text in sites:
        owner, fa = best_owner(aud, site)
        print(
            f"{image_name} site=0x{site:08X} pool=0x{litaddr:08X} "
            f"value=0x{value:08X} owner="
            + (f"0x{owner:08X}" if owner is not None else "UNKNOWN")
        )
        if owner is not None:
            owners[owner] = fa
            owner_sites[owner].append((site, value))

    hline("D. SYMBOLIC NEIGHBOR-BASE ACCESS CLASSIFICATION")
    ranked = []
    for entry, fa in owners.items():
        events = symbolic_scan(aud, fa)
        reads = [e for e in events if e["kind"] == "READ"]
        writes = [e for e in events if e["kind"] == "WRITE"]
        indirect = [e for e in events if e["kind"] == "INDIRECT"]
        dispatch = [e for e in indirect if e.get("origin") is not None]
        score = 5 * len(reads) + 20 * len(dispatch) + 3 * len(indirect) - len(writes)
        if entry in KNOWN_WRITERS:
            score -= 5
        ranked.append((score, entry, fa, events, reads, writes, indirect, dispatch))

    ranked.sort(key=lambda r: (-r[0], r[1]))

    for score, entry, fa, events, reads, writes, indirect, dispatch in ranked:
        print(
            f"\nOWNER 0x{entry:08X} image={fa.image} score={score} "
            f"reads={len(reads)} writes={len(writes)} "
            f"indirect={len(indirect)} proven_dispatch={len(dispatch)}"
        )
        if entry in KNOWN_WRITERS:
            print(f"  known={KNOWN_WRITERS[entry]}")
        print("  literals:")
        for site, value in owner_sites[entry]:
            print(f"    0x{site:08X} -> 0x{value:08X}")
        for e in events:
            if e["kind"] in ("READ", "WRITE", "MEM"):
                print(
                    f"  {e['kind']} 0x{e['site']:08X}: {e['text']} "
                    f"effective={e['expr']}"
                )
            elif e["kind"] == "INDIRECT":
                print(
                    f"  INDIRECT 0x{e['site']:08X}: {e['text']} "
                    f"origin={e.get('origin')}"
                )

    hline("E. CONTEXTS FOR ALL SIDE-TABLE-AREA READS")
    read_owners = []
    for score, entry, fa, events, reads, writes, indirect, dispatch in ranked:
        if not reads:
            continue
        read_owners.append(entry)
        print(f"\n----- OWNER 0x{entry:08X} -----")
        for e in reads:
            print(f"\nREAD effective={e['expr']}")
            dump_context(aud, e["site"], before=0x70, after=0x90, mark="SIDE_TABLE_READ")

    hline("F. PROVEN TABLE-LOAD -> INDIRECT CONTROL CHAINS")
    chains = []
    for score, entry, fa, events, reads, writes, indirect, dispatch in ranked:
        for e in dispatch:
            chains.append((entry, e))
            print(
                f"owner=0x{entry:08X} indirect@0x{e['site']:08X} "
                f"{e['text']} origin={e['origin']}"
            )
            dump_context(aud, e["site"], before=0x70, after=0x30, mark="DISPATCH")

    if not chains:
        print("NONE")

    hline("G. REVERSE CALLERS OF NEW READING OWNERS")
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
            dump_context(aud, site, before=0x50, after=0x50, mark="READER_CALL")
        if len(rows) > 60:
            print("  ... truncated")

    hline("H. NEIGHBOR GLOBAL FAMILY CENSUS")
    by_value = defaultdict(list)
    for image_name, site, litaddr, value, text in sites:
        by_value[value].append((image_name, site))
    for value in sorted(by_value):
        print(f"0x{value:08X}: refs={len(by_value[value])}")
        for image_name, site in by_value[value]:
            print(f"  {image_name} 0x{site:08X}")

    hline("I. FOCUS AUDIO POINTER CO-LOCATION IN READER OWNERS")
    total_focus = 0
    for score, entry, fa, events, reads, writes, indirect, dispatch in ranked:
        if not reads:
            continue
        hits = []
        for row in fa.literals:
            if row and isinstance(row[-1], int):
                v = row[-1]
                lab = FOCUS.get(v) or FOCUS.get(v & ~1)
                if lab:
                    hits.append((row[0], v, lab))
        if hits:
            print(f"\nowner=0x{entry:08X}")
            for site, value, lab in hits:
                print(f"  0x{site:08X}: 0x{value:08X} <{lab}>")
                total_focus += 1
    if total_focus == 0:
        print("No Audio/focus literals co-located in new table readers.")

    hline("J. DECISION GATE")
    print(f"neighbor literals                 = {len(sites)}")
    print(f"distinct neighboring-base owners = {len(owners)}")
    print(f"owners reading side-table area    = {len(read_owners)}")
    print(f"proven table-load->BLX/BX chains  = {len(chains)}")

    if chains:
        best_entry, best = chains[0]
        print(
            f"RESULT: callback-style dispatch is mechanically proven in owner "
            f"0x{best_entry:08X}."
        )
        print(
            "NEXT: classify the exact slot/field and enumerate producer values for "
            "visible menu items, then compare against the native Audio entry chain."
        )
    elif read_owners:
        print(
            "RESULT: indirect neighboring-base consumer(s) of F00960A0 were recovered, "
            "but no same-function execution of the loaded dword is proven."
        )
        print(
            "NEXT: trace the loaded value one function boundary into its consumer; "
            "treat it as context/user-data until executable use is proven."
        )
    else:
        print(
            "RESULT: no read consumer was recovered even through F0096000..F00960FF "
            "neighbor-base derivation."
        )
        print(
            "NEXT: pivot from address xrefs to the APIs that set/get the current item "
            "index and the UI callback/event dispatcher, then backslice their user-data "
            "argument to the side-table."
        )

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a65_f00960xx_neighbor_indirect_consumer_audit.txt"
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
