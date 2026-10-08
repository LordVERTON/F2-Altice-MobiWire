#!/usr/bin/env python3
"""
S13.5A.13 - CURRENT-CALLBACK DISPATCHER ARGUMENT / CALLER AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.12 recovered the exact callback dispatch sequence:

    0x1031CC90  ldr r0, =0xF0096018
    0x1031CC92  ldr r1, [r0,#0x44]   ; callback = *(0xF009605C)
    0x1031CC94  ldr r0, =<special/fallback callback>
    0x1031CC96  cmp r1, r0
    0x1031CC98  beq ...
    0x1031CC9A  mov r0, r4
    0x1031CC9C  blx r1

The automatic A.12 counter said "indirect dispatches=0", but the detailed
disassembly proves the BLX. That counter is superseded.

This pass answers only:
  1) What is r4 at 0x1031CC9A?
  2) What is the exact enclosing dispatcher function?
  3) Who calls or references that dispatcher?
  4) What value is supplied as its r0 argument?
  5) Is that value structurally a menu/list selection/highlight index?

No raw menu-ID census.
No patch generation.
No phone access.
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

CALLBACK_BASE = 0xF0096018
CALLBACK_SLOT = 0xF009605C

DISPATCH_SEED = 0x1031CC90
SLOT_READ = 0x1031CC92
CALLBACK_COMPARE_LOAD = 0x1031CC94
ARG_MOVE = 0x1031CC9A
INDIRECT_CALL = 0x1031CC9C

SELECT_CB = 0x10342FC4
SELECT_CB_THUMB = SELECT_CB | 1

KNOWN_HELPERS = {
    0x10315514: "CHILD_ID_AT_INDEX",
    0x10317C58: "CURRENT_CALLBACK_SETTER",
    0x10342FC4: "GENERIC_SELECT_CB",
    0x10387D94: "ENTER_SUBMENU_HANDLER",
}

md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md_t.detail = True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md_a.detail = True


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
        return len(s)

    def flush(self):
        for st in self.streams:
            st.flush()


@dataclass
class Image:
    data: bytes
    base: int = ALICE_BASE

    @property
    def end(self):
        return self.base + len(self.data)

    def contains(self, addr: int):
        return self.base <= addr < self.end

    def off(self, addr: int):
        return addr - self.base


def banner(s: str):
    print()
    print("=" * 132)
    print(s)
    print("=" * 132)


def sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def validate(path: Path):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical ALICE: {path}")
    data = path.read_bytes()
    got = sha256(data)
    print(f"ALICE = {path}")
    print(f"  runtime base = 0x{ALICE_BASE:08X}")
    print(f"  size         = 0x{len(data):X}")
    print(f"  sha256       = {got}")
    if len(data) != ALICE_SIZE:
        raise SystemExit("ABORT: canonical ALICE size mismatch")
    if got.lower() != ALICE_SHA256:
        raise SystemExit("ABORT: canonical ALICE SHA256 mismatch")
    print("[PASS] canonical ALICE")
    return Image(data)


def decode1(img: Image, addr: int, mode="THUMB"):
    if not img.contains(addr):
        return None
    md = md_t if mode == "THUMB" else md_a
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+4], addr, count=1))
    return xs[0] if xs else None


def dis_thumb(img: Image, start: int, end: int):
    if not img.contains(start):
        return []
    end = min(end, img.end)
    return [
        x for x in md_t.disasm(img.data[img.off(start):img.off(end)], start)
        if x.address < end
    ]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<9} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None
    op = x.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def literal_load(img: Image, x, mode="THUMB"):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None
    d, s = x.operands[0], x.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None

    pc = ((x.address + 4) & ~3) if mode == "THUMB" else (x.address + 8)
    la = (pc + s.mem.disp) & 0xFFFFFFFF
    if not img.contains(la):
        return None

    return x.reg_name(d.reg), d.reg, la, u32(img.data, img.off(la))


def is_prologue(x):
    if x is None:
        return False
    if x.mnemonic == "push" and "lr" in x.op_str:
        return True
    if x.mnemonic in {"stmdb", "stm"} and "lr" in x.op_str:
        return True
    return False


def is_return(x):
    if x is None:
        return False
    if x.mnemonic == "pop" and "pc" in x.op_str:
        return True
    if x.mnemonic == "bx" and x.op_str.strip() == "lr":
        return True
    return False


def reg_written(x):
    if not x.operands:
        return None
    op0 = x.operands[0]
    if op0.type == ARM_OP_REG:
        return op0.reg
    return None


def all_hits(data: bytes, needle: bytes):
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def print_region(img: Image, start: int, end: int, marks=None):
    marks = marks or set()
    for x in dis_thumb(img, start, end):
        notes = []
        t = direct_target(x)
        if t is not None:
            name = KNOWN_HELPERS.get(t & ~1)
            notes.append(
                f"target=0x{t:08X}"
                + (f" <{name}>" if name else "")
            )

        lit = literal_load(img, x)
        if lit:
            rn, _, la, val = lit
            extra = []
            if val == CALLBACK_BASE:
                extra.append("CALLBACK_BASE")
            if val == CALLBACK_SLOT:
                extra.append("CALLBACK_SLOT")
            if (val & ~1) == SELECT_CB:
                extra.append("SELECT_CB")
            suffix = f" <{'|'.join(extra)}>" if extra else ""
            notes.append(f"literal@0x{la:08X}=0x{val:08X}->{rn}{suffix}")

        if (
            x.mnemonic in {"blx", "bx"}
            and x.operands
            and x.operands[0].type == ARM_OP_REG
        ):
            notes.append(f"INDIRECT via {x.reg_name(x.operands[0].reg)}")

        tag = ">>>" if x.address in marks else "   "
        print(tag, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def candidate_prologues(img: Image, target: int, back=0x300, forward=0x220):
    """
    Find Thumb prologues whose linear disassembly includes the target address.
    We deliberately do not stop at the first POP because prior passes showed
    valid branches can jump past an early return.
    """
    lo = max(img.base, target-back) & ~1
    out = []

    for a in range(lo, target+1, 2):
        x = decode1(img, a)
        if not is_prologue(x):
            continue
        xs = dis_thumb(img, a, min(img.end, a+forward))
        if any(z.address == target for z in xs):
            out.append(a)

    return out


def enclosing_dispatcher(img: Image):
    cands = candidate_prologues(img, INDIRECT_CALL, back=0x400, forward=0x500)
    if not cands:
        return None, None, []

    # Nearest prologue is usually the actual function start. Print all so the
    # result remains auditable.
    start = cands[-1]

    xs = dis_thumb(img, start, min(img.end, start+0x600))

    # Find a plausible terminal return after the dispatch branch and fallback.
    # Do not use an early POP before 0x1031CC9C.
    end = None
    for x in xs:
        if x.address >= 0x1031CCAE and is_return(x):
            end = x.address + len(x.bytes)
            break

    if end is None:
        end = min(img.end, start+0x180)

    return start, end, cands


def r4_writes_before_dispatch(img: Image, start: int):
    xs = dis_thumb(img, start, INDIRECT_CALL)
    rid = None
    for x in xs:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == "r4":
                rid = op.reg
                break
        if rid is not None:
            break

    if rid is None:
        return []

    return [x for x in xs if reg_written(x) == rid]


def resolve_r4_semantics(img: Image, start: int):
    writes = r4_writes_before_dispatch(img, start)

    if not writes:
        return "ARG/INHERITED r4", writes

    last = writes[-1]
    ops = last.operands

    if last.mnemonic in {"mov", "movs"} and len(ops) >= 2:
        s = ops[1]
        if s.type == ARM_OP_REG:
            srcn = last.reg_name(s.reg)
            if srcn == "r0":
                # Check no later r4 writes; by construction last is final.
                return (
                    f"r4 <- incoming/current r0 at 0x{last.address:08X}; "
                    "no later r4 write before callback dispatch"
                ), writes
            return f"r4 <- {srcn} at 0x{last.address:08X}", writes
        if s.type == ARM_OP_IMM:
            return f"r4 <- CONST 0x{s.imm & 0xFFFFFFFF:08X} at 0x{last.address:08X}", writes

    if last.mnemonic.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
        m = ops[1].mem
        return (
            f"r4 <- MEM {last.mnemonic} "
            f"[{last.reg_name(m.base)}{m.disp:+#x}] @0x{last.address:08X}"
        ), writes

    return f"r4 last writer = {last.mnemonic} {last.op_str} @0x{last.address:08X}", writes


def scan_direct_calls(img: Image, target: int):
    out = []

    # Thumb BL/BLX immediate
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

    # ARM BL/BLX immediate
    for off in range(0, len(img.data)-4, 4):
        w = u32(img.data, off)
        if w is None:
            continue
        if not (
            (w & 0x0E000000) == 0x0A000000
            or (w & 0xFE000000) == 0xFA000000
        ):
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

    uniq = {(m, x.address): (m, x) for m, x in out}
    return [uniq[k] for k in sorted(uniq, key=lambda q: (q[1], q[0]))]


def raw_pointer_refs(img: Image, target: int):
    vals = {(target & ~1) & 0xFFFFFFFF, (target | 1) & 0xFFFFFFFF}
    hits = []
    for v in vals:
        for off in all_hits(img.data, struct.pack("<I", v)):
            hits.append((img.base+off, v))
    return sorted(set(hits))


def real_literal_xrefs_to_word(img: Image, word_addr: int):
    """
    Real Thumb PC-literal loads that use exactly this word as their literal.
    """
    out = []
    lo = max(img.base, word_addr-0x500) & ~1

    for a in range(lo, word_addr+1, 2):
        x = decode1(img, a)
        if x is None:
            continue
        lit = literal_load(img, x)
        if lit and lit[2] == word_addr:
            out.append((x, lit[3]))

    return out


def reg_id_by_name(insns, name):
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == name:
                return op.reg
    return None


def backward_source(img: Image, insns, before_addr: int, name: str, depth=0):
    if depth > 10:
        return "UNKNOWN(depth-limit)"

    hist = [x for x in insns if x.address < before_addr]
    rid = reg_id_by_name(hist, name)
    if rid is None:
        return f"UNKNOWN({name} unseen)"

    caller_saved = name in {"r0", "r1", "r2", "r3", "r12", "lr", "ip"}

    for i in range(len(hist)-1, -1, -1):
        x = hist[i]

        if x.mnemonic in {"bl", "blx"} and caller_saved:
            return f"UNKNOWN({name} clobbered by call @0x{x.address:08X})"

        if reg_written(x) != rid:
            continue

        lit = literal_load(img, x)
        if lit and lit[1] == rid:
            return f"CONST 0x{lit[3]:08X} via literal @0x{lit[2]:08X}"

        ops = x.operands

        if x.mnemonic in {"mov", "movs"} and len(ops) >= 2:
            s = ops[1]
            if s.type == ARM_OP_IMM:
                return f"CONST 0x{s.imm & 0xFFFFFFFF:08X} via {x.mnemonic} @0x{x.address:08X}"
            if s.type == ARM_OP_REG:
                sn = x.reg_name(s.reg)
                return (
                    f"{name} <- {sn} @0x{x.address:08X} <- "
                    + backward_source(img, hist[:i+1], x.address, sn, depth+1)
                )

        if x.mnemonic.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            m = ops[1].mem
            return (
                f"MEM {x.mnemonic} "
                f"[{x.reg_name(m.base)}{m.disp:+#x}] @0x{x.address:08X}"
            )

        if x.mnemonic in {"add", "adds", "sub", "subs", "lsls", "lsrs"}:
            return f"EXPR {x.mnemonic} {x.op_str} @0x{x.address:08X}"

        return f"UNKNOWN(writer {x.mnemonic} {x.op_str} @0x{x.address:08X})"

    return f"ARG/INHERITED {name}"


def enclosing_start_for_callsite(img: Image, addr: int, back=0x400):
    cands = candidate_prologues(img, addr, back=back, forward=0x700)
    return cands[-1] if cands else None


def detect_index_like_source(text: str):
    """
    Conservative textual classifier for the slicer result.
    It never promotes to FACT by itself.
    """
    t = text.lower()
    if "ldrb" in t or "ldrh" in t:
        return "SMALL_INTEGER_FIELD_CANDIDATE"
    if "const" in t:
        return "CONSTANT"
    if "arg/inherited" in t:
        return "CALLER_ARGUMENT"
    if "expr" in t:
        return "EXPRESSION"
    return "UNKNOWN"


def audit_fallback_literal(img: Image):
    x = decode1(img, CALLBACK_COMPARE_LOAD)
    lit = literal_load(img, x)
    print(f"compare-load instruction: {fmt(x) if x else 'UNRESOLVED'}")

    if not lit:
        print("comparison literal: UNRESOLVED")
        return None, None

    _, _, la, val = lit
    print(f"comparison literal @0x{la:08X} = 0x{val:08X}")

    p = val & ~1
    if img.contains(p):
        print(f"comparison pointer targets ALICE @0x{p:08X}")
        print_region(img, p, min(img.end, p+0x50))
    else:
        print("comparison value does not point inside canonical ALICE")

    return la, val


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    ap.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a13_dispatcher_argument_caller_audit.txt",
    )
    args = ap.parse_args()

    root = Path.cwd()

    alice_path = Path(args.alice)
    if not alice_path.is_absolute():
        alice_path = root / alice_path

    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = root / report_path

    report_path.parent.mkdir(parents=True, exist_ok=True)

    capture = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, capture)

    try:
        banner("S13.5A.13 - CURRENT-CALLBACK DISPATCHER ARGUMENT / CALLER AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUT")
        img = validate(alice_path)

        banner("B. EXACT DISPATCH SITE")
        print_region(
            img,
            0x1031CC80,
            0x1031CCB8,
            {SLOT_READ, CALLBACK_COMPARE_LOAD, ARG_MOVE, INDIRECT_CALL},
        )

        banner("C. ENCLOSING DISPATCHER FUNCTION")
        start, end, cands = enclosing_dispatcher(img)
        print(f"candidate prologues reaching 0x{INDIRECT_CALL:08X} = {len(cands)}")
        for a in cands:
            p = decode1(img, a)
            print(f"  0x{a:08X}: {fmt(p) if p else 'decode-fail'}")

        if start is None:
            print("[FAIL] dispatcher prologue not recovered")
            return 4

        print()
        print(f"[PROMOTED FUNCTION CANDIDATE] 0x{start:08X}..0x{end:08X}")
        print_region(
            img,
            start,
            end,
            {SLOT_READ, ARG_MOVE, INDIRECT_CALL},
        )

        banner("D. r4 PROVENANCE AT CALLBACK DISPATCH")
        semantic, writes = resolve_r4_semantics(img, start)
        print(f"r4 writes before 0x{INDIRECT_CALL:08X} = {len(writes)}")
        for x in writes:
            print(f"  {fmt(x)}")

        print()
        print(f"r4 semantic result: {semantic}")

        print()
        print("callback argument instruction:")
        print(f"  {fmt(decode1(img, ARG_MOVE))}")
        print("indirect transfer:")
        print(f"  {fmt(decode1(img, INDIRECT_CALL))}")

        r4_from_input_r0 = (
            "r4 <- incoming/current r0" in semantic
        )

        banner("E. SPECIAL/FALLBACK CALLBACK COMPARISON")
        compare_lit_addr, compare_value = audit_fallback_literal(img)

        banner("F. DIRECT CALLERS OF DISPATCHER")
        callers = scan_direct_calls(img, start)
        print(f"dispatcher = 0x{start:08X}")
        print(f"direct callers = {len(callers)}")

        caller_classifications = []

        for mode, x in callers:
            print()
            print(f"{mode} caller: {fmt(x)}")
            if mode != "THUMB":
                continue

            fs = enclosing_start_for_callsite(img, x.address)
            if fs is None:
                lo = max(img.base, x.address-0x80)
                hi = min(img.end, x.address+0x20)
                ins = dis_thumb(img, lo, hi)
                print("  enclosing function: UNKNOWN")
            else:
                lo = fs
                hi = min(img.end, fs+0x700)
                ins = dis_thumb(img, lo, hi)
                print(f"  enclosing function start = 0x{fs:08X}")

            r0src = backward_source(img, ins, x.address, "r0")
            cls = detect_index_like_source(r0src)
            caller_classifications.append((x.address, r0src, cls))

            print(f"  r0 source: {r0src}")
            print(f"  source class: {cls}")

            print("  local context:")
            print_region(
                img,
                max(lo, x.address-0x40),
                min(hi, x.address+0x20),
                {x.address},
            )

        banner("G. FUNCTION-POINTER REFERENCES TO DISPATCHER")
        ptrs = raw_pointer_refs(img, start)
        print(f"raw pointer refs = {len(ptrs)}")

        for addr, val in ptrs:
            print()
            print(f"pointer word @0x{addr:08X} = 0x{val:08X}")
            xrefs = real_literal_xrefs_to_word(img, addr)
            print(f"  real Thumb literal xrefs = {len(xrefs)}")
            for x, loaded in xrefs:
                print(f"    {fmt(x)} -> 0x{loaded:08X}")
                fs = enclosing_start_for_callsite(img, x.address)
                if fs is not None:
                    print(f"      enclosing function start = 0x{fs:08X}")
                    print_region(
                        img,
                        max(fs, x.address-0x30),
                        min(img.end, x.address+0x50),
                        {x.address},
                    )

        banner("H. ALL LOCAL USES OF CURRENT CALLBACK SLOT")
        # Focus the known global context around F0096018 xrefs that actually use +0x44.
        base_raw = all_hits(img.data, struct.pack("<I", CALLBACK_BASE))
        print(f"raw CALLBACK_BASE words = {len(base_raw)}")

        slot_users = []
        for roff in base_raw:
            la = img.base + roff
            for a in range(max(img.base, la-0x500) & ~1, la+1, 2):
                x = decode1(img, a)
                lit = literal_load(img, x)
                if not lit or lit[2] != la or lit[3] != CALLBACK_BASE:
                    continue

                # Decode short local path and report exact +0x44 reads/writes.
                xs = dis_thumb(img, x.address, min(img.end, x.address+0x60))
                seed_reg = lit[1]

                aliases = {seed_reg}
                for z in xs[1:]:
                    if z.mnemonic in {"mov", "movs"} and len(z.operands) >= 2:
                        d, s = z.operands[0], z.operands[1]
                        if (
                            d.type == ARM_OP_REG
                            and s.type == ARM_OP_REG
                            and s.reg in aliases
                        ):
                            aliases.add(d.reg)

                    for op in z.operands:
                        if (
                            op.type == ARM_OP_MEM
                            and op.mem.base in aliases
                            and op.mem.disp == 0x44
                        ):
                            slot_users.append((x, z))

        uniq = {}
        for seed, user in slot_users:
            uniq[(seed.address, user.address)] = (seed, user)
        slot_users = [uniq[k] for k in sorted(uniq)]

        print(f"exact +0x44 slot users = {len(slot_users)}")
        for seed, user in slot_users:
            rw = "WRITE" if user.mnemonic.startswith("str") else "READ"
            print(f"  {rw}: seed {fmt(seed)} -> {fmt(user)}")

        banner("I. DECISION GATE")
        print(f"dispatcher function start                  = 0x{start:08X}")
        print(f"r4 <- dispatcher input r0                  = {'PASS' if r4_from_input_r0 else 'OPEN'}")
        print(f"exact slot read @0x1031CC92               = PASS")
        print(f"exact indirect callback transfer @0x1031CC9C = PASS")
        print(f"direct callers of dispatcher               = {len(callers)}")
        print(f"raw function-pointer refs                   = {len(ptrs)}")
        print()

        if r4_from_input_r0:
            print("[PASS] Dispatcher forwards its incoming/current r0 through r4")
            print("       to the callback at 0x1031CC9C.")
        else:
            print("[OPEN] r4 was not proven to preserve dispatcher input r0.")

        index_like = [
            (a, src, cls)
            for a, src, cls in caller_classifications
            if cls == "SMALL_INTEGER_FIELD_CANDIDATE"
        ]

        if index_like:
            print()
            print("[STRONG CANDIDATE] At least one direct caller supplies a byte/halfword")
            print("integer field as dispatcher r0. Audit those exact caller object fields")
            print("against menu/list cursor/highlight state before promoting UI-index semantics.")
            for a, src, cls in index_like:
                print(f"  call@0x{a:08X}: {src}")
        elif callers:
            print()
            print("[NEXT] Dispatcher input provenance is recovered at caller sites above.")
            print("       Continue only through the strongest caller/source object until")
            print("       selection/highlight index semantics are structurally proven.")
        elif ptrs:
            print()
            print("[NEXT] Dispatcher is callback/function-pointer driven.")
            print("       Follow the real pointer owners/xrefs printed above and recover")
            print("       the argument used at the indirect invocation of this dispatcher.")
        else:
            print()
            print("[NEXT] No static owner yet; use exact dispatcher address/pointer only.")
            print("       Do not return to broad ID scanning.")

        print()
        print("PROVEN CHAIN SO FAR:")
        print("  F009605C -> current callback")
        print("  dispatcher reads F009605C")
        print("  dispatcher invokes current callback via BLX")
        print("  SELECT_CB(r0) -> CHILD_ID_AT_INDEX(r0)")
        print("  child ID -> descriptor+0x18")
        print("  enter-submenu: +0x18 -> +0x14")
        print()
        print("STILL UNKNOWN:")
        print("  whether dispatcher input r0 is definitively the list/highlight index")
        print("  numeric ID corresponding to visible Multimedia")
        print("  FM Radio child ID")
        print("  exact Multimedia children[]")
        print("  whether 0x8928 is absent vs present-but-filtered")
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
        report_path.write_text(capture.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
