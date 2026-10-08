#!/usr/bin/env python3
"""
S13.5A.6 - GENERIC MENU BUILDER PARENT-FLOW / FIXED-RELATION AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.5 established two distinct facts:

  1) 0x103430xx calls:
       ENUM_CHILD_IDS
       GET_CHILD_COUNT
       GET_CHILD_META
     and stores the returned child count at an object +0x48 before iterating
     the returned children. This is the strongest generic menu-builder path.

  2) 0x103A1D18 uses parent 0x346C, enumerates its children, and searches
     specifically for child 0x3473 (= parent + 7). This is a proven static
     parent->child relation, but NOT automatically Multimedia.

This pass focuses only on:
  - recovering the exact parent-ID source at 0x10343068 / 0x1034306E;
  - locating the enclosing function start and its direct callers;
  - tracing writes/reads of +0x14 / +0x18 / +0x40 / +0x48 around that chain;
  - classifying 0x346C -> 0x3473 separately;
  - checking whether 0x346C/0x3473 structurally co-locate with
    0x8313 / 0x8321 / 0x8928.

NO USB/COM.
NO PHONE ACCESS.
NO FLASH WRITE.
NO PATCH.
NO REPACK.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

# Exact ALICE veneer callers established by S13.5A.5
ENUM_CALL  = 0x10343068
COUNT_CALL = 0x1034306E
META_CALL  = 0x103430CA
COUNT_CHILD_CALL = 0x103430D4

# Fixed relation positive control
FIXED_FUNC_HINT = 0x103A1D18
FIXED_COUNT_CALL = 0x103A1D28
FIXED_ENUM_CALL  = 0x103A1D32
FIXED_PARENT = 0x346C
FIXED_CHILD  = 0x3473

VENEERS = {
    "GET_CHILD_META":  0x102FA0C4,
    "ENUM_CHILD_IDS":  0x102FC35C,
    "GET_CHILD_COUNT": 0x102FC3EC,
}

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    FIXED_PARENT: "FIXED_PARENT_346C",
    FIXED_CHILD: "FIXED_CHILD_3473",
}

FIELD_LABELS = {
    0x14: "parent/menu-id candidate",
    0x18: "selected/child-id candidate",
    0x40: "children-array candidate",
    0x48: "child-count candidate",
}

md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md_t.detail = True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md_a.detail = True


class Tee:
    def __init__(self, *streams):
        self.streams = streams
    def write(self, s):
        for x in self.streams:
            x.write(s)
        return len(s)
    def flush(self):
        for x in self.streams:
            x.flush()


@dataclass
class Image:
    data: bytes
    base: int = ALICE_BASE
    @property
    def end(self): return self.base + len(self.data)
    def contains(self, a): return self.base <= a < self.end
    def off(self, a): return a - self.base


def banner(s):
    print()
    print("=" * 124)
    print(s)
    print("=" * 124)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def u16(data, off):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def all_hits(data: bytes, needle: bytes):
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def fmt(insn):
    return f"0x{insn.address:08X}: {insn.bytes.hex(' '):<14} {insn.mnemonic:<9} {insn.op_str}"


def direct_target(insn):
    if insn.mnemonic not in {"b", "bl", "blx"} or not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def validate(path: Path):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing ALICE: {path}")
    b = path.read_bytes()
    h = sha256(b)
    print(f"ALICE = {path}")
    print(f"  size   = 0x{len(b):X}")
    print(f"  sha256 = {h}")
    if len(b) != ALICE_SIZE or h.lower() != ALICE_SHA256:
        raise SystemExit("ABORT: canonical ALICE identity mismatch")
    print("[PASS] canonical ALICE")
    return Image(b)


def dis1(img: Image, addr: int, mode="THUMB"):
    if not img.contains(addr):
        return None
    md = md_t if mode == "THUMB" else md_a
    size = 4
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+size], addr, count=1))
    return xs[0] if xs else None


def is_thumb_prologue(insn):
    if not insn:
        return False
    return (
        (insn.mnemonic == "push" and "lr" in insn.op_str)
        or insn.mnemonic in {"stmdb", "stm"}
        and "lr" in insn.op_str
    )


def contains_exact_boundaries(img: Image, start: int, targets, max_end=0x10343110):
    if not img.contains(start):
        return (False, [])
    code = img.data[img.off(start):img.off(min(img.end, max_end))]
    insns = list(md_t.disasm(code, start))
    addrs = {x.address for x in insns}
    return (all(t in addrs for t in targets), insns)


def find_enclosing_prologues(img: Image, target_calls, back=0x300):
    first = min(target_calls)
    candidates = []
    lo = max(img.base, first - back) & ~1
    for a in range(lo, first + 1, 2):
        insn = dis1(img, a, "THUMB")
        if not is_thumb_prologue(insn):
            continue
        ok, insns = contains_exact_boundaries(img, a, target_calls)
        if ok:
            candidates.append((a, insns))
    return candidates


def decode_from(img: Image, start: int, end: int):
    return [x for x in md_t.disasm(img.data[img.off(start):img.off(end)], start) if x.address < end]


def reg_name(insn, r):
    try:
        return insn.reg_name(r)
    except Exception:
        return f"reg{r}"


def mem_note(insn):
    notes = []
    for op in insn.operands:
        if op.type == ARM_OP_MEM:
            d = op.mem.disp
            if d in FIELD_LABELS:
                notes.append(FIELD_LABELS[d])
    return notes


def print_region(img: Image, start: int, end: int, marks=None):
    marks = marks or set()
    for insn in decode_from(img, start, end):
        tag = ">>>" if insn.address in marks else "   "
        notes = mem_note(insn)
        tgt = direct_target(insn)
        if tgt is not None:
            for n, v in VENEERS.items():
                if (tgt & ~1) == (v & ~1):
                    notes.append(n)
        print(tag, fmt(insn) + ((" ; " + ", ".join(notes)) if notes else ""))


def writes_reg(insn, reg):
    if not insn.operands:
        return False
    op0 = insn.operands[0]
    return op0.type == ARM_OP_REG and op0.reg == reg


def literal_value(img: Image, insn):
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    d, s = insn.operands[0], insn.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None
    pc = (insn.address + 4) & ~3
    la = (pc + s.mem.disp) & 0xFFFFFFFF
    if not img.contains(la):
        return None
    return (d.reg, la, u32(img.data, img.off(la)))


def reverse_source(img: Image, insns, call_addr: int, reg_name_wanted="r0", depth=0):
    """
    Conservative backwards slice in the current straight-line history.
    It follows MOV aliases and recognizes immediate/literal/memory sources.
    Calls and branches are reported as barriers rather than guessed through.
    """
    if depth > 8:
        return "UNKNOWN(depth-limit)"

    before = [x for x in insns if x.address < call_addr]
    wanted_id = None

    # Recover the capstone register ID from nearby operands.
    for x in reversed(before):
        for op in x.operands:
            if op.type == ARM_OP_REG and reg_name(x, op.reg) == reg_name_wanted:
                wanted_id = op.reg
                break
        if wanted_id is not None:
            break

    if wanted_id is None:
        return f"UNKNOWN({reg_name_wanted} unseen)"

    for i in range(len(before)-1, -1, -1):
        x = before[i]

        # Don't silently cross a prior function call if the wanted register is
        # caller-clobbered and the call occurs after the last known assignment.
        if x.mnemonic in {"bl", "blx"}:
            return f"UNKNOWN(clobber barrier @0x{x.address:08X})"

        if not writes_reg(x, wanted_id):
            continue

        lit = literal_value(img, x)
        if lit and lit[0] == wanted_id:
            value = lit[2]
            low = value & 0xFFFF
            tag = f" <{KNOWN_IDS[low]}>" if low in KNOWN_IDS else ""
            return f"CONST 0x{value:08X}{tag} via literal @0x{lit[1]:08X}"

        ops = x.operands
        m = x.mnemonic

        if m in {"mov", "movs"} and len(ops) >= 2:
            s = ops[1]
            if s.type == ARM_OP_IMM:
                return f"CONST 0x{s.imm & 0xFFFFFFFF:08X} via {m} @0x{x.address:08X}"
            if s.type == ARM_OP_REG:
                srcn = reg_name(x, s.reg)
                prior = before[:i]
                return (
                    f"{reg_name_wanted} <- {srcn} @0x{x.address:08X} <- "
                    + reverse_source(img, prior + [x], x.address, srcn, depth+1)
                )

        if m.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            mem = ops[1].mem
            basen = reg_name(x, mem.base) if mem.base else "?"
            d = mem.disp
            label = FIELD_LABELS.get(d)
            suffix = f" <{label}>" if label else ""
            return f"MEM {m} [{basen}{d:+#x}] @0x{x.address:08X}{suffix}"

        if m in {"add", "adds", "sub", "subs"}:
            return f"EXPR {x.mnemonic} {x.op_str} @0x{x.address:08X}"

        return f"UNKNOWN(writer {x.mnemonic} {x.op_str} @0x{x.address:08X})"

    return f"ARG/UNKNOWN({reg_name_wanted} inherited at function entry)"


def scan_direct_calls(img: Image, target: int):
    out = []
    # Thumb BL/BLX
    for off in range(0, len(img.data)-4, 2):
        h1 = u16(img.data, off)
        h2 = u16(img.data, off+2)
        if h1 is None or h2 is None:
            continue
        if (h1 & 0xF800) != 0xF000 or (h2 & 0xC000) != 0xC000:
            continue
        xs = list(md_t.disasm(img.data[off:off+4], img.base+off, count=1))
        if not xs:
            continue
        x = xs[0]
        if x.mnemonic not in {"bl", "blx"}:
            continue
        t = direct_target(x)
        if t is not None and (t & ~1) == (target & ~1):
            out.append(("THUMB", x))

    # ARM BL/BLX
    for off in range(0, len(img.data)-4, 4):
        word = u32(img.data, off)
        if word is None:
            continue
        if not ((word & 0x0E000000) == 0x0A000000 or (word & 0xFE000000) == 0xFA000000):
            continue
        xs = list(md_a.disasm(img.data[off:off+4], img.base+off, count=1))
        if not xs:
            continue
        x = xs[0]
        if x.mnemonic not in {"bl", "blx"}:
            continue
        t = direct_target(x)
        if t is not None and (t & ~1) == (target & ~1):
            out.append(("ARM", x))

    uniq = {}
    for mode, x in out:
        uniq[(mode, x.address)] = (mode, x)
    return [uniq[k] for k in sorted(uniq, key=lambda z: (z[1], z[0]))]


def scan_field_accesses(img: Image, start: int, end: int):
    hits = []
    for x in decode_from(img, start, end):
        for op in x.operands:
            if op.type == ARM_OP_MEM and op.mem.disp in FIELD_LABELS:
                hits.append((x, op.mem.disp, FIELD_LABELS[op.mem.disp]))
    return hits


def occurrences_u16(img: Image, value: int):
    pat = struct.pack("<H", value)
    return [img.base + off for off in all_hits(img.data, pat)]


def colocations(img: Image, a: int, b: int, radius=0x100):
    ah = occurrences_u16(img, a)
    bh = occurrences_u16(img, b)
    pairs = []
    for x in ah:
        for y in bh:
            if abs(x-y) <= radius:
                pairs.append((x, y, y-x))
    return pairs


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    ap.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a6_generic_menu_builder_parent_flow.txt",
    )
    return ap.parse_args()


def pth(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    args = parse_args()
    root = Path.cwd()
    alice_path = pth(root, args.alice)
    report_path = pth(root, args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    cap = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, cap)

    try:
        banner("S13.5A.6 - GENERIC MENU BUILDER PARENT-FLOW / FIXED-RELATION AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUT")
        img = validate(alice_path)

        banner("B. RAW TARGET REGION 0x10343040..0x10343100")
        rs = 0x10343040
        re = 0x10343100
        raw = img.data[img.off(rs):img.off(re)]
        print(f"raw bytes {rs:08X}..{re:08X}:")
        for i in range(0, len(raw), 16):
            chunk = raw[i:i+16]
            print(f"0x{rs+i:08X}: {chunk.hex(' ')}")
        print()
        print("Thumb decode anchored at 0x10343040:")
        print_region(
            img, rs, re,
            {ENUM_CALL, COUNT_CALL, META_CALL, COUNT_CHILD_CALL}
        )

        banner("C. ENCLOSING FUNCTION CANDIDATES FOR 0x10343068/6E/CA/D4")
        required = [ENUM_CALL, COUNT_CALL, META_CALL, COUNT_CHILD_CALL]
        cands = find_enclosing_prologues(img, required, back=0x400)

        print(f"candidate prologues reaching all four calls = {len(cands)}")
        for a, insns in cands[-20:]:
            print(f"  0x{a:08X}: {fmt(dis1(img,a,'THUMB'))}")

        if cands:
            func_start = cands[-1][0]
            print(f"\n[PROMOTED LOCAL FUNCTION START CANDIDATE] 0x{func_start:08X}")
        else:
            func_start = 0x10343048
            print(
                "\n[WARN] no prologue candidate reached all four calls; "
                "fallback local anchor = 0x10343048"
            )

        # Disassemble from promoted local start through return region.
        insns = decode_from(img, func_start, 0x10343100)

        banner("D. EXACT PARENT FLOW AT GENERIC BUILDER CALLS")
        for label, ca in [
            ("ENUM_CHILD_IDS", ENUM_CALL),
            ("GET_CHILD_COUNT(parent)", COUNT_CALL),
            ("GET_CHILD_META(child)", META_CALL),
            ("GET_CHILD_COUNT(child)", COUNT_CHILD_CALL),
        ]:
            print(f"{label} @0x{ca:08X}")
            print(f"  r0 source: {reverse_source(img, insns, ca, 'r0')}")
            if label == "ENUM_CHILD_IDS":
                print(f"  r1 source: {reverse_source(img, insns, ca, 'r1')}")
            print()

        banner("E. +0x14/+0x18/+0x40/+0x48 ACCESSES IN GENERIC BUILDER")
        fields = scan_field_accesses(img, func_start, 0x10343100)
        print(f"field access count = {len(fields)}")
        for x, disp, label in fields:
            print(f"0x{x.address:08X}: {x.mnemonic:<8} {x.op_str:<30} <{label}>")

        banner("F. DIRECT CALLERS OF GENERIC BUILDER CANDIDATE")
        callers = scan_direct_calls(img, func_start)
        print(f"target function candidate = 0x{func_start:08X}")
        print(f"direct callers = {len(callers)}")
        for mode, x in callers:
            print(f"\n{mode} caller: {fmt(x)}")
            if mode == "THUMB":
                lo = max(img.base, x.address - 0x80) & ~1
                hi = min(img.end, x.address + 0x20)
                local = decode_from(img, lo, hi)
                print(f"  incoming r0: {reverse_source(img, local, x.address, 'r0')}")
                print("  nearby field accesses:")
                fh = scan_field_accesses(img, lo, hi)
                if not fh:
                    print("    none")
                for y, disp, label in fh:
                    print(f"    0x{y.address:08X}: {y.mnemonic} {y.op_str} <{label}>")

        banner("G. FIXED RELATION 0x346C -> 0x3473")
        fixed = decode_from(img, FIXED_FUNC_HINT, 0x103A1D58)
        print_region(
            img,
            FIXED_FUNC_HINT,
            0x103A1D58,
            {FIXED_COUNT_CALL, FIXED_ENUM_CALL},
        )
        print()
        print(f"COUNT r0 = {reverse_source(img, fixed, FIXED_COUNT_CALL, 'r0')}")
        print(f"ENUM  r0 = {reverse_source(img, fixed, FIXED_ENUM_CALL, 'r0')}")
        print(
            "Observed search target after ENUM: "
            "r2 = r5 + 7 = 0x3473 when r5=0x346C."
        )
        print(
            "[FACT] This function asks for children of 0x346C and scans them "
            "for 0x3473."
        )
        print(
            "[NOT PROVEN] 0x346C is Multimedia. Keep this relation as a "
            "separate positive-control menu relation."
        )

        banner("H. 0x346C / 0x3473 CO-LOCATION WITH IMAGE/AUDIO IDS")
        for value, label in KNOWN_IDS.items():
            hs = occurrences_u16(img, value)
            print(f"0x{value:04X} <{label}> occurrences = {len(hs)}")
            for a in hs[:20]:
                print(f"  0x{a:08X}")
            if len(hs) > 20:
                print(f"  ... {len(hs)-20} more")

        for fixed_id, fixed_name in [
            (FIXED_PARENT, "0x346C"),
            (FIXED_CHILD, "0x3473"),
        ]:
            for menu_id, menu_name in [
                (0x8313, "IMAGE_A"),
                (0x8321, "IMAGE_B"),
                (0x8928, "AUDIO"),
            ]:
                ps = colocations(img, fixed_id, menu_id, radius=0x100)
                print(
                    f"{fixed_name} vs {menu_name} within ±0x100: {len(ps)} pair(s)"
                )
                for a, b, d in ps[:20]:
                    print(f"  0x{a:08X} <-> 0x{b:08X} delta={d:+#x}")

        banner("I. DECISION GATE")
        parent_enum = reverse_source(img, insns, ENUM_CALL, "r0")
        parent_count = reverse_source(img, insns, COUNT_CALL, "r0")

        print(f"generic ENUM parent source : {parent_enum}")
        print(f"generic COUNT parent source: {parent_count}")
        print(f"generic builder direct callers: {len(callers)}")
        print()

        if "+0x14" in parent_enum or "+0x14" in parent_count:
            print("[PASS] generic builder parent flow reaches a +0x14 field.")
            print("[NEXT] Trace the writer of that exact +0x14 field through the")
            print("       direct caller(s), then recover the concrete ID used when")
            print("       entering the observed Multimedia screen.")
        elif parent_enum.startswith("CONST") and parent_count.startswith("CONST"):
            print("[PASS] generic builder uses a statically recoverable parent.")
            print("[NEXT] Enumerate/identify that parent's children structurally.")
        else:
            print("[NEXT] Parent source is still dynamic/aliased.")
            print("       Use the promoted function start and direct callers above")
            print("       to trace the object passed into the generic builder.")
            print("       Do not return to broad raw-ID scanning.")

        print()
        print("Fixed relation 0x346C -> 0x3473: PROVEN")
        print("0x346C == Multimedia            : NOT PROVEN")
        print("0x8928 in Multimedia            : UNKNOWN")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {report_path}")
        return 0

    finally:
        sys.stdout = old
        report_path.write_text(cap.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
