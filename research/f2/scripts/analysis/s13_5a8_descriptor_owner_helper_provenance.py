#!/usr/bin/env python3
"""
S13.5A.8 - DESCRIPTOR OWNER / HELPER PROVENANCE AUDIT

STRICTLY OFFLINE / READ-ONLY.

Why this pass exists
--------------------
S13.5A.7 proved:

  - 0x10340ADC receives the menu descriptor in r1.
  - it copies r1 -> r4 and reads [r4 + 0x14].
  - that +0x14 value reaches 0x10343050, which feeds the real
    ENUM_CHILD_IDS + GET_CHILD_COUNT path.
  - 0x10340ADC does not write +0x14.
  - direct callers of 0x10340ADC are only:
        0x1033F4FC  (wrapper A, function 0x1033F4F4)
        0x10347442  (wrapper B, function 0x10347432)

So the next question is object identity, not raw field offsets.

This audit:
  A. validates canonical ALICE;
  B. disassembles wrapper A / wrapper B exactly;
  C. resolves the helper called by wrapper B immediately before r1 <- r0;
  D. finds direct callers and exact function-pointer references to both wrappers;
  E. traces wrapper A's descriptor source *(arg1 + 8);
  F. scans all direct callsites to wrapper-B helper and classifies how the
     returned r0 is used (read/write +0x14, stored at +8, passed to 0x10340ADC);
  G. scans only STRUCTURALLY RELATED +0x14 writes, not all raw +0x14 stores;
  H. emits the next proof gate.

No USB/COM.
No phone access.
No flash write.
No patch.
No repack.
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

CONSUMER = 0x10340ADC

WRAPPER_A = 0x1033F4F4
WRAPPER_A_CALL = 0x1033F4FC

WRAPPER_B = 0x10347432
WRAPPER_B_HELPER_CALL = 0x1034743A
WRAPPER_B_CALL = 0x10347442

OFF_PARENT = 0x14
OFF_OWNER_SLOT = 0x08

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0x346C: "FIXED_PARENT_346C",
    0x3473: "FIXED_CHILD_3473",
    0xB0EC: "B0EC",
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


def banner(s):
    print()
    print("=" * 126)
    print(s)
    print("=" * 126)


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


def fmt(x):
    return (
        f"0x{x.address:08X}: {x.bytes.hex(' '):<14} "
        f"{x.mnemonic:<9} {x.op_str}"
    )


def validate(path: Path):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical ALICE: {path}")
    b = path.read_bytes()
    h = sha256(b)
    print(f"ALICE = {path}")
    print(f"  size   = 0x{len(b):X}")
    print(f"  sha256 = {h}")
    if len(b) != ALICE_SIZE or h.lower() != ALICE_SHA256:
        raise SystemExit("ABORT: canonical ALICE identity mismatch")
    print("[PASS] canonical ALICE")
    return Image(b)


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


def direct_target(insn):
    if insn.mnemonic not in {"b", "bl", "blx"} or not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def literal_load(img: Image, insn):
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    d, s = insn.operands[0], insn.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None
    pc = (insn.address + 4) & ~3
    la = (pc + s.mem.disp) & 0xFFFFFFFF
    if not img.contains(la):
        return None
    return d.reg, la, u32(img.data, img.off(la))


def is_prologue(x):
    return bool(x and x.mnemonic == "push" and "lr" in x.op_str)


def is_return(x):
    return bool(
        x and (
            (x.mnemonic == "pop" and "pc" in x.op_str)
            or (x.mnemonic == "bx" and x.op_str.strip() == "lr")
        )
    )


def enclosing_function(img: Image, addr: int, back=0x400, max_len=0x700):
    lo = max(img.base, addr - back) & ~1
    candidates = []

    for a in range(lo, addr + 1, 2):
        p = decode1(img, a)
        if not is_prologue(p):
            continue
        xs = dis_thumb(img, a, min(img.end, a + max_len))
        if any(x.address == addr for x in xs):
            candidates.append(a)

    if not candidates:
        return None, None

    start = candidates[-1]
    xs = dis_thumb(img, start, min(img.end, start + max_len))
    end = None
    for x in xs:
        if x.address >= addr and is_return(x):
            end = x.address + len(x.bytes)
            break
    return start, end or min(img.end, start + max_len)


def print_region(img: Image, start: int, end: int, marks=None):
    marks = marks or set()
    for x in dis_thumb(img, start, end):
        tag = ">>>" if x.address in marks else "   "
        notes = []
        tgt = direct_target(x)
        if tgt is not None:
            notes.append(f"target=0x{tgt:08X}")
        for op in x.operands:
            if op.type == ARM_OP_MEM:
                if op.mem.disp == OFF_PARENT:
                    notes.append(f"PARENT_FIELD via {x.reg_name(op.mem.base)}+0x14")
                elif op.mem.disp == OFF_OWNER_SLOT:
                    notes.append(f"OWNER_SLOT via {x.reg_name(op.mem.base)}+0x08")
        print(tag, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


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
        if not (
            (word & 0x0E000000) == 0x0A000000
            or (word & 0xFE000000) == 0xFA000000
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

    uniq = {}
    for mode, x in out:
        uniq[(mode, x.address)] = (mode, x)
    return [uniq[k] for k in sorted(uniq, key=lambda z: (z[1], z[0]))]


def all_hits(data: bytes, needle: bytes):
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def pointer_refs(img: Image, target: int):
    vals = [target & 0xFFFFFFFF, (target | 1) & 0xFFFFFFFF]
    hits = []
    for v in vals:
        pat = struct.pack("<I", v)
        for off in all_hits(img.data, pat):
            hits.append((img.base + off, v))
    return sorted(set(hits))


def register_id(insns, name):
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == name:
                return op.reg
    return None


def written_reg(x):
    if not x.operands:
        return None
    op0 = x.operands[0]
    return op0.reg if op0.type == ARM_OP_REG else None


def backward_source(img: Image, insns, before_addr: int, name: str, depth=0):
    if depth > 10:
        return "UNKNOWN(depth-limit)"

    hist = [x for x in insns if x.address < before_addr]
    rid = register_id(hist, name)
    if rid is None:
        return f"UNKNOWN({name} unseen)"

    caller_saved = name in {"r0", "r1", "r2", "r3", "r12", "lr"}

    for i in range(len(hist)-1, -1, -1):
        x = hist[i]

        if x.mnemonic in {"bl", "blx"} and caller_saved:
            return f"UNKNOWN({name} clobbered by call @0x{x.address:08X})"

        if written_reg(x) != rid:
            continue

        lit = literal_load(img, x)
        if lit and lit[0] == rid:
            v = lit[2]
            low = v & 0xFFFF
            tag = f" <{KNOWN_IDS[low]}>" if low in KNOWN_IDS else ""
            return f"CONST 0x{v:08X}{tag} via literal @0x{lit[1]:08X}"

        ops = x.operands
        m = x.mnemonic

        if m in {"mov", "movs"} and len(ops) >= 2:
            s = ops[1]
            if s.type == ARM_OP_IMM:
                v = s.imm & 0xFFFFFFFF
                low = v & 0xFFFF
                tag = f" <{KNOWN_IDS[low]}>" if low in KNOWN_IDS else ""
                return f"CONST 0x{v:08X}{tag} via {m} @0x{x.address:08X}"
            if s.type == ARM_OP_REG:
                srcn = x.reg_name(s.reg)
                return (
                    f"{name} <- {srcn} @0x{x.address:08X} <- "
                    + backward_source(img, hist[:i+1], x.address, srcn, depth+1)
                )

        if m.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            mem = ops[1].mem
            basen = x.reg_name(mem.base) if mem.base else "?"
            return (
                f"MEM {m} [{basen}{mem.disp:+#x}] "
                f"@0x{x.address:08X}"
            )

        if m in {"add", "adds", "sub", "subs"}:
            return f"EXPR {m} {x.op_str} @0x{x.address:08X}"

        return f"UNKNOWN(writer {m} {x.op_str} @0x{x.address:08X})"

    return f"ARG/INHERITED {name}"


def nearby_ids(img: Image, center: int, radius=0x120):
    lo = max(0, img.off(center)-radius)
    hi = min(len(img.data), img.off(center)+radius)
    out = []
    for v, name in KNOWN_IDS.items():
        pat = struct.pack("<H", v)
        p = img.data.find(pat, lo, hi)
        while p >= 0:
            out.append((img.base+p, v, name))
            p = img.data.find(pat, p+1, hi)
    return sorted(out)


def classify_helper_return_use(img: Image, call_addr: int, max_bytes=0x50):
    """
    Track aliases of helper return r0 forward for a short basic local window.

    We care about:
      - mov rX,r0
      - ldrh ..., [alias,#0x14]
      - strh ..., [alias,#0x14]
      - str alias,[container,#8]
      - mov r1,alias followed by call CONSUMER
    """
    start = call_addr + 4
    xs = dis_thumb(img, start, min(img.end, start + max_bytes))

    aliases = {"r0"}
    events = []

    for x in xs:
        # stop at return
        if is_return(x):
            break

        # alias propagation via mov/movs
        if x.mnemonic in {"mov", "movs"} and len(x.operands) >= 2:
            d, s = x.operands[0], x.operands[1]
            if d.type == ARM_OP_REG and s.type == ARM_OP_REG:
                dn = x.reg_name(d.reg)
                sn = x.reg_name(s.reg)
                if sn in aliases:
                    aliases.add(dn)
                    events.append(("ALIAS", x, f"{dn} <- {sn}"))

        # memory use via alias base
        for op in x.operands:
            if op.type != ARM_OP_MEM:
                continue
            base = x.reg_name(op.mem.base) if op.mem.base else "?"
            disp = op.mem.disp
            if base not in aliases:
                continue

            if x.mnemonic.startswith("ldr") and disp == OFF_PARENT:
                events.append(("READ_PARENT", x, f"[{base}+0x14]"))
            elif x.mnemonic.startswith("str") and disp == OFF_PARENT:
                events.append(("WRITE_PARENT", x, f"[{base}+0x14]"))
            elif x.mnemonic.startswith("str") and disp == OFF_OWNER_SLOT:
                events.append(("STORE_ALIAS_AT_PLUS8", x, f"[{base}+0x08]"))
            else:
                events.append(("MEM_USE", x, f"[{base}{disp:+#x}]"))

        # storing alias value into some container +8:
        if x.mnemonic.startswith("str") and len(x.operands) >= 2:
            src, mem = x.operands[0], x.operands[1]
            if src.type == ARM_OP_REG and mem.type == ARM_OP_MEM:
                sn = x.reg_name(src.reg)
                if sn in aliases and mem.mem.disp == OFF_OWNER_SLOT:
                    bn = x.reg_name(mem.mem.base)
                    events.append(
                        ("STORE_DESCRIPTOR_TO_OWNER_PLUS8", x, f"{sn} -> [{bn}+8]")
                    )

        # exact consumer call
        tgt = direct_target(x)
        if tgt is not None and (tgt & ~1) == (CONSUMER & ~1):
            events.append(("CALL_CONSUMER", x, f"0x{CONSUMER:08X}"))

        # Calls clobber r0-r3; preserved aliases r4-r7 survive.
        if x.mnemonic in {"bl", "blx"}:
            aliases = {a for a in aliases if a in {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"}}

    return aliases, events


def related_parent_writers(img: Image, relevant_functions: set[int]):
    """
    Return STRH/STR writers to +0x14 only when the containing function is
    one of the structurally relevant functions already discovered.
    """
    out = []
    for fs in sorted(relevant_functions):
        if fs is None:
            continue
        # find a modest function end
        _, fe = enclosing_function(img, fs, back=2, max_len=0x700)
        if fe is None:
            fe = min(img.end, fs + 0x700)
        for x in dis_thumb(img, fs, fe):
            if not x.mnemonic.startswith("str") or len(x.operands) < 2:
                continue
            mem = x.operands[1]
            if mem.type == ARM_OP_MEM and mem.mem.disp == OFF_PARENT:
                out.append((fs, fe, x))
    return out


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a8_descriptor_owner_helper_provenance.txt",
    )
    return p.parse_args()


def path(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    args = parse_args()
    root = Path.cwd()
    ap = path(root, args.alice)
    rp = path(root, args.report)
    rp.parent.mkdir(parents=True, exist_ok=True)

    capture = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, capture)

    try:
        banner("S13.5A.8 - DESCRIPTOR OWNER / HELPER PROVENANCE AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUT")
        img = validate(ap)

        banner("B. EXACT WRAPPER DISASSEMBLY")
        print("WRAPPER A:")
        print_region(img, WRAPPER_A, WRAPPER_A + 0x20, {WRAPPER_A_CALL})
        print()
        print("WRAPPER B:")
        print_region(
            img,
            WRAPPER_B,
            WRAPPER_B + 0x24,
            {WRAPPER_B_HELPER_CALL, WRAPPER_B_CALL},
        )

        helper_insn = decode1(img, WRAPPER_B_HELPER_CALL)
        helper_target = direct_target(helper_insn) if helper_insn else None
        print()
        if helper_target is None:
            print("[FAIL] could not resolve wrapper-B helper target")
            return 4

        print(
            f"[FACT] wrapper-B helper call @0x{WRAPPER_B_HELPER_CALL:08X} "
            f"targets 0x{helper_target:08X}"
        )

        banner("C. WRAPPER CALLERS + FUNCTION-POINTER REFERENCES")
        wrapper_info = {}

        for name, target in [("WRAPPER_A", WRAPPER_A), ("WRAPPER_B", WRAPPER_B)]:
            calls = scan_direct_calls(img, target)
            ptrs = pointer_refs(img, target)
            wrapper_info[name] = {"calls": calls, "ptrs": ptrs}

            print()
            print(f"{name} = 0x{target:08X}")
            print(f"direct callers = {len(calls)}")
            for mode, x in calls:
                print(f"  {mode} {fmt(x)}")
                fs, fe = enclosing_function(img, x.address)
                if fs is not None:
                    insns = dis_thumb(img, fs, fe)
                    print(f"    enclosing=0x{fs:08X}..0x{fe:08X}")
                    for rn in ("r0", "r1", "r2", "r3"):
                        print(
                            f"    {rn}: "
                            f"{backward_source(img, insns, x.address, rn)}"
                        )
                    ids = nearby_ids(img, x.address)
                    if ids:
                        print("    nearby known IDs:")
                        for a, v, lab in ids[:20]:
                            print(f"      0x{a:08X}: 0x{v:04X} <{lab}>")

            print(f"exact raw pointer refs = {len(ptrs)}")
            for a, v in ptrs:
                print(
                    f"  pointer word @0x{a:08X} = 0x{v:08X}"
                )

        banner("D. WRAPPER-A OWNER SLOT *(arg1 + 8)")
        print(
            "S13.5A.7 observed wrapper A passing r1 = *(incoming_r1 + 8) "
            "to 0x10340ADC."
        )
        print("The caller chain below is therefore treated as owner/container provenance.")
        print()

        relevant_functions = {WRAPPER_A, WRAPPER_B}

        for mode, x in wrapper_info["WRAPPER_A"]["calls"]:
            fs, fe = enclosing_function(img, x.address)
            if fs is None:
                continue
            relevant_functions.add(fs)
            insns = dis_thumb(img, fs, fe)
            print(f"WRAPPER_A caller @0x{x.address:08X} in 0x{fs:08X}..0x{fe:08X}")
            print(f"  incoming r1 container: {backward_source(img, insns, x.address, 'r1')}")
            print_region(
                img,
                max(fs, x.address - 0x50) & ~1,
                min(fe, x.address + 0x30),
                {x.address},
            )

        banner("E. WRAPPER-B HELPER CALLER CENSUS")
        helper_calls = scan_direct_calls(img, helper_target)
        print(f"helper = 0x{helper_target:08X}")
        print(f"direct helper callers = {len(helper_calls)}")

        helper_related_functions = set()

        for mode, x in helper_calls:
            print()
            print(f"{mode} helper call: {fmt(x)}")
            fs, fe = enclosing_function(img, x.address)
            if fs is not None:
                helper_related_functions.add(fs)
                relevant_functions.add(fs)
                print(f"  enclosing=0x{fs:08X}..0x{fe:08X}")
                insns = dis_thumb(img, fs, fe)
                for rn in ("r0", "r1", "r2", "r3"):
                    print(
                        f"  {rn} before helper: "
                        f"{backward_source(img, insns, x.address, rn)}"
                    )

            aliases, events = classify_helper_return_use(img, x.address)
            print(f"  surviving aliases after local scan: {sorted(aliases)}")
            if not events:
                print("  return-use events: none resolved")
            for kind, ev, desc in events:
                print(f"  {kind:<32} {fmt(ev)} | {desc}")

            ids = nearby_ids(img, x.address)
            if ids:
                print("  nearby known IDs (supporting only):")
                for a, v, lab in ids[:20]:
                    print(f"    0x{a:08X}: 0x{v:04X} <{lab}>")

        banner("F. HELPER IMPLEMENTATION")
        hfs, hfe = enclosing_function(img, helper_target)
        if hfs is None:
            hfs = helper_target & ~1
            hfe = min(img.end, hfs + 0x100)
            print("[WARN] helper prologue not recovered; using direct target window")
        else:
            relevant_functions.add(hfs)

        print(f"helper function candidate = 0x{hfs:08X}..0x{hfe:08X}")
        print_region(img, hfs, hfe)

        banner("G. STRUCTURALLY RELATED +0x14 WRITES ONLY")
        # Include direct callers of wrapper B and helper functions in relevance set.
        for name in ("WRAPPER_A", "WRAPPER_B"):
            for mode, x in wrapper_info[name]["calls"]:
                fs, fe = enclosing_function(img, x.address)
                if fs is not None:
                    relevant_functions.add(fs)

        writes = related_parent_writers(img, relevant_functions)
        print(f"relevant functions audited = {len(relevant_functions)}")
        print(f"related +0x14 write sites   = {len(writes)}")

        for fs, fe, x in writes:
            print()
            print(
                f"WRITE in function 0x{fs:08X}..0x{fe:08X}: "
                f"{fmt(x)}"
            )
            src = None
            if x.operands and x.operands[0].type == ARM_OP_REG:
                srcn = x.reg_name(x.operands[0].reg)
                insns = dis_thumb(img, fs, fe)
                src = backward_source(img, insns, x.address, srcn)
                print(f"  value source = {src}")

            ids = nearby_ids(img, x.address, 0x180)
            if ids:
                print("  nearby known IDs:")
                for a, v, lab in ids[:30]:
                    print(f"    0x{a:08X}: 0x{v:04X} <{lab}>")

            print("  context:")
            print_region(
                img,
                max(fs, x.address - 0x40) & ~1,
                min(fe, x.address + 0x40),
                {x.address},
            )

        banner("H. WRAPPER / HELPER OWNERSHIP SUMMARY")

        # Detect if helper itself or helper callers structurally touch +0x14.
        helper_parent_events = []
        for mode, x in helper_calls:
            aliases, events = classify_helper_return_use(img, x.address)
            for kind, ev, desc in events:
                if kind in {"READ_PARENT", "WRITE_PARENT", "CALL_CONSUMER"}:
                    helper_parent_events.append((x.address, kind, ev.address, desc))

        print(f"wrapper A direct callers  = {len(wrapper_info['WRAPPER_A']['calls'])}")
        print(f"wrapper A pointer refs     = {len(wrapper_info['WRAPPER_A']['ptrs'])}")
        print(f"wrapper B direct callers  = {len(wrapper_info['WRAPPER_B']['calls'])}")
        print(f"wrapper B pointer refs     = {len(wrapper_info['WRAPPER_B']['ptrs'])}")
        print(f"helper direct callers      = {len(helper_calls)}")
        print(f"helper parent/consumer events = {len(helper_parent_events)}")
        print(f"related +0x14 writes       = {len(writes)}")
        print()

        for ca, kind, ea, desc in helper_parent_events:
            print(
                f"helper call 0x{ca:08X} -> {kind} "
                f"@0x{ea:08X} {desc}"
            )

        print()
        if writes:
            print("[PASS] structurally related current-parent writer(s) recovered.")
            print("[NEXT] Promote the strongest writer by descriptor identity and")
            print("       resolve the concrete value reaching +0x14.")
        elif helper_parent_events:
            print("[PASS] helper-return provenance reaches the current-parent/consumer path.")
            print("[NEXT] Trace helper ownership one level farther to the writer/initializer.")
        elif wrapper_info["WRAPPER_A"]["ptrs"] or wrapper_info["WRAPPER_B"]["ptrs"]:
            print("[NEXT] Resolve wrapper function-pointer registration owners.")
            print("       Their callback registration context may identify the UI/menu family.")
        else:
            print("[NEXT] No writer yet. Continue only through wrapper/helper ownership.")
            print("       Do not resume broad +0x14/+0x18 offset scans.")

        print()
        print("CONFIRMED:")
        print("  0x10340ADC descriptor argument = r1")
        print("  descriptor +0x14 feeds real menu providers")
        print()
        print("NOT YET CONFIRMED:")
        print("  +0x18 belongs to this same descriptor as selected child")
        print("  numeric Multimedia parent ID")
        print("  FM Radio child ID")
        print("  exact Multimedia children[]")
        print("  0x8928 present-vs-absent in Multimedia")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {rp}")

        return 0

    finally:
        sys.stdout = old
        rp.write_text(capture.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
