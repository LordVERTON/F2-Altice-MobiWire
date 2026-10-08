#!/usr/bin/env python3
"""
S13.5A.5 - CANONICAL ALICE MENU-VENEER CALLER / PARENT-FLOW AUDIT

STRICTLY OFFLINE / READ-ONLY.

Purpose
-------
S13.5A.4 proved that canonical ALICE contains the exact Thumb targets for:
  GET_CHILD_COUNT  0xF02D8871
  ENUM_CHILD_IDS   0xF032ACDD
  GET_CHILD_META   0xF02F9CCD

A prior ALICE audit established that these occurrences live immediately after
the standard ARM import veneer instruction:

    04 F0 1F E5        ; ARM: ldr pc, [pc, #-4]
    <target word>

Therefore this pass does NOT treat the 8-byte objects as menu records.
It treats them as ALICE -> platform import veneers and resolves WHO CALLS
THE VENEERS.

The key question is:
    which ALICE code invokes the child-count / child-enumeration providers,
    and what value is in r0 (parent ID) at those call sites?

This script:
  A. validates canonical ALICE (and optional translated ALICE);
  B. locates exact ARM veneers for the menu providers;
  C. finds direct ARM and Thumb BL/BLX calls to those veneer addresses;
  D. finds literal/indirect references to the veneers;
  E. performs conservative local argument slicing for r0/r1/r2/r3;
  F. labels descriptor-like field accesses (+0x14, +0x18, +0x40, +0x48);
  G. groups nearby COUNT/ENUM callsites;
  H. emits a strict decision gate.

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

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

# -----------------------------------------------------------------------------
# Canonical baseline
# -----------------------------------------------------------------------------

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

# Optional derived file seen in the existing research tree.
ALICE_TRANSLATED_SHA256 = "1eec7ce448cb4aefdcc6f3c8d68741a358d09b3f6dbda1ba4487602eabda1495"

ARM_VENEER = bytes.fromhex("04 F0 1F E5")  # E51FF004: ldr pc,[pc,#-4]

TARGETS = {
    "GET_CHILD_COUNT": 0xF02D8871,
    "ENUM_CHILD_IDS":  0xF032ACDD,
    "GET_CHILD_META":  0xF02F9CCD,
    # Secondary control only; do not promote this to registry constructor.
    "F02D8888_CONTROL": 0xF02D8889,
}

# Expected veneer starts derived from S13.5A.4 raw-target offsets:
# target word is at veneer_start + 4.
EXPECTED_VENEERS = {
    "GET_CHILD_META":  ALICE_BASE + 0xAB4C4,
    "ENUM_CHILD_IDS":  ALICE_BASE + 0xAD75C,
    "GET_CHILD_COUNT": ALICE_BASE + 0xAD7EC,
    "F02D8888_CONTROL": ALICE_BASE + 0xADB04,
}

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0xB0EC: "B0EC",
    0xB0ED: "B0ED",
}

FIELD_LABELS = {
    0x14: "descriptor.parent_id candidate",
    0x18: "descriptor.selected_id candidate",
    0x40: "descriptor.children buffer candidate",
    0x48: "descriptor.child_count candidate",
}

md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md_arm.detail = True
md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md_thumb.detail = True


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for stream in self.streams:
            stream.write(s)
        return len(s)

    def flush(self):
        for stream in self.streams:
            stream.flush()


@dataclass
class Image:
    name: str
    data: bytes
    base: int

    @property
    def end(self):
        return self.base + len(self.data)

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.end

    def off(self, addr: int) -> int:
        return addr - self.base


@dataclass
class Sym:
    kind: str
    value: Optional[int] = None
    desc: str = ""

    def text(self):
        if self.kind == "CONST" and self.value is not None:
            extra = ""
            low = self.value & 0xFFFF
            if low in KNOWN_IDS:
                extra = f" <{KNOWN_IDS[low]}>"
            return f"CONST 0x{self.value & 0xFFFFFFFF:08X}{extra}" + (
                f" via {self.desc}" if self.desc else ""
            )
        return self.kind + (f" ({self.desc})" if self.desc else "")


def banner(s):
    print()
    print("=" * 122)
    print(s)
    print("=" * 122)


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


def verify_required(path: Path):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical ALICE: {path}")
    data = path.read_bytes()
    got = sha256(data)
    print(f"ALICE = {path}")
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {got}")
    if len(data) != ALICE_SIZE or got.lower() != ALICE_SHA256:
        raise SystemExit("ABORT: canonical ALICE identity mismatch")
    print("[PASS] canonical ALICE")
    return Image("ALICE", data, ALICE_BASE)


def verify_optional_translated(path: Path):
    if not path.is_file():
        print(f"ALICE_TRANSLATED = {path}")
        print("[INFO] optional translated ALICE missing; raw ALICE audit continues")
        return None
    data = path.read_bytes()
    got = sha256(data)
    print(f"ALICE_TRANSLATED = {path}")
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {got}")
    if len(data) != ALICE_SIZE or got.lower() != ALICE_TRANSLATED_SHA256:
        print("[WARN] translated ALICE identity mismatch; skipping it")
        return None
    print("[PASS] known translated ALICE")
    return Image("ALICE_TRANSLATED", data, ALICE_BASE)


def md_for(mode):
    return md_arm if mode == "ARM" else md_thumb


def direct_target(insn):
    if insn.mnemonic not in {"b", "bl", "blx"}:
        return None
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type != ARM_OP_IMM:
        return None
    return op.imm & 0xFFFFFFFF


def fmt(insn):
    return (
        f"0x{insn.address:08X}: {insn.bytes.hex(' '):<14} "
        f"{insn.mnemonic:<9} {insn.op_str}"
    )


def scan_direct_calls(img: Image, target: int):
    hits = []

    # ARM branches/calls. Pre-filter branch-family encodings.
    for off in range(0, len(img.data) - 4, 4):
        word = u32(img.data, off)
        if word is None:
            continue
        is_b_family = (word & 0x0E000000) == 0x0A000000
        is_blx_imm = (word & 0xFE000000) == 0xFA000000
        if not (is_b_family or is_blx_imm):
            continue
        insns = list(md_arm.disasm(img.data[off:off + 4], img.base + off, count=1))
        if not insns:
            continue
        insn = insns[0]
        if insn.mnemonic not in {"bl", "blx"}:
            continue
        tgt = direct_target(insn)
        if tgt is not None and (tgt & ~1) == (target & ~1):
            hits.append(("ARM", insn))

    # Thumb-2 BL/BLX. Decode only likely 32-bit branch prefixes.
    for off in range(0, len(img.data) - 4, 2):
        h1 = u16(img.data, off)
        h2 = u16(img.data, off + 2)
        if h1 is None or h2 is None:
            continue
        if (h1 & 0xF800) != 0xF000:
            continue
        if (h2 & 0xC000) != 0xC000:
            continue
        insns = list(md_thumb.disasm(img.data[off:off + 4], img.base + off, count=1))
        if not insns:
            continue
        insn = insns[0]
        if insn.mnemonic not in {"bl", "blx"}:
            continue
        tgt = direct_target(insn)
        if tgt is not None and (tgt & ~1) == (target & ~1):
            hits.append(("THUMB", insn))

    # Deduplicate address+mode.
    uniq = {}
    for mode, insn in hits:
        uniq[(mode, insn.address)] = (mode, insn)
    return [uniq[k] for k in sorted(uniq, key=lambda x: (x[1], x[0]))]


def find_veneers(img: Image, thumb_target: int):
    needle = ARM_VENEER + struct.pack("<I", thumb_target)
    return [img.base + off for off in all_hits(img.data, needle)]


def arm_literal_info(img: Image, insn):
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    dst, src = insn.operands[0], insn.operands[1]
    if dst.type != ARM_OP_REG or src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
        return None
    pc = insn.address + 8
    lit_addr = (pc + src.mem.disp) & 0xFFFFFFFF
    if not img.contains(lit_addr):
        return None
    val = u32(img.data, img.off(lit_addr))
    return (dst.reg, lit_addr, val)


def thumb_literal_info(img: Image, insn):
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    dst, src = insn.operands[0], insn.operands[1]
    if dst.type != ARM_OP_REG or src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
        return None
    pc = (insn.address + 4) & ~3
    lit_addr = (pc + src.mem.disp) & 0xFFFFFFFF
    if not img.contains(lit_addr):
        return None
    val = u32(img.data, img.off(lit_addr))
    return (dst.reg, lit_addr, val)


def scan_literal_refs(img: Image, value: int):
    """
    Find real PC-literal LDRs that load an exact value, in ARM or Thumb mode.
    Narrow search around raw occurrences to avoid linear-disassembling all data.
    """
    out = []
    raw_positions = all_hits(img.data, struct.pack("<I", value & 0xFFFFFFFF))

    for raw_off in raw_positions:
        lit_addr = img.base + raw_off

        # ARM candidates in the preceding 0x100 bytes.
        start = max(0, raw_off - 0x100)
        start &= ~3
        for off in range(start, raw_off + 1, 4):
            insns = list(md_arm.disasm(img.data[off:off + 4], img.base + off, count=1))
            if not insns:
                continue
            insn = insns[0]
            info = arm_literal_info(img, insn)
            if info and info[1] == lit_addr and info[2] == value:
                out.append(("ARM", insn, info[0], lit_addr))

        # Thumb candidates.
        start = max(0, raw_off - 0x100) & ~1
        for off in range(start, raw_off + 1, 2):
            insns = list(md_thumb.disasm(img.data[off:off + 4], img.base + off, count=1))
            if not insns:
                continue
            insn = insns[0]
            info = thumb_literal_info(img, insn)
            if info and info[1] == lit_addr and info[2] == value:
                out.append(("THUMB", insn, info[0], lit_addr))

    uniq = {}
    for item in out:
        mode, insn, reg, lit = item
        uniq[(mode, insn.address)] = item
    return [uniq[k] for k in sorted(uniq, key=lambda x: (x[1], x[0]))]


def decode_path_to_call(img: Image, mode: str, call_addr: int, back=0xA0):
    """
    Choose a conservative sequential instruction path ending exactly at call_addr.
    For Thumb, try every even start because starting in the middle of a 32-bit
    instruction can desynchronise a naive window.
    """
    md = md_for(mode)
    call_off = img.off(call_addr)
    if mode == "ARM":
        start_off = max(0, call_off - back) & ~3
        code = img.data[start_off:call_off + 4]
        insns = list(md.disasm(code, img.base + start_off))
        return [x for x in insns if x.address <= call_addr]

    best = []
    lo = max(0, call_off - back) & ~1
    for start_off in range(lo, call_off + 1, 2):
        code = img.data[start_off:call_off + 4]
        insns = list(md.disasm(code, img.base + start_off))
        path = []
        found = False
        for x in insns:
            if x.address > call_addr:
                break
            path.append(x)
            if x.address == call_addr:
                found = True
                break
        if found and len(path) > len(best):
            best = path
    return best


def label_mem(insn, op):
    disp = op.mem.disp & 0xFFFFFFFF
    signed_disp = op.mem.disp
    base = insn.reg_name(op.mem.base) if op.mem.base else "?"
    label = FIELD_LABELS.get(signed_disp)
    txt = f"[{base}{signed_disp:+#x}]"
    if label:
        txt += f" <{label}>"
    return txt


def propagate(path, mode):
    regs = {}
    md = md_for(mode)

    def get(r):
        return regs.get(r, Sym("UNKNOWN", None, md.reg_name(r)))

    def set_unknown(r, why):
        regs[r] = Sym("UNKNOWN", None, why)

    for insn in path:
        if insn.mnemonic in {"bl", "blx"}:
            # Do not clobber on the final target call; caller arguments are
            # needed immediately before it.
            if insn is path[-1]:
                break
            for rn in ("r0", "r1", "r2", "r3", "r12", "lr"):
                rid = None
                # discover register id through operands / capstone name lookup
                for x in path:
                    for op in x.operands:
                        if op.type == ARM_OP_REG and x.reg_name(op.reg) == rn:
                            rid = op.reg
                            break
                    if rid is not None:
                        break
                if rid is not None:
                    set_unknown(rid, f"clobbered by call @0x{insn.address:08X}")
            continue

        ops = insn.operands
        if not ops or ops[0].type != ARM_OP_REG:
            continue
        dst = ops[0].reg

        lit = arm_literal_info if mode == "ARM" else thumb_literal_info
        li = lit(current_img, insn)
        if li:
            regs[dst] = Sym("CONST", li[2], f"literal @0x{li[1]:08X}")
            continue

        m = insn.mnemonic

        if m in {"mov", "movs"} and len(ops) >= 2:
            src = ops[1]
            if src.type == ARM_OP_IMM:
                regs[dst] = Sym("CONST", src.imm & 0xFFFFFFFF, f"{m} imm @0x{insn.address:08X}")
            elif src.type == ARM_OP_REG:
                regs[dst] = get(src.reg)
            else:
                set_unknown(dst, m)
            continue

        if m == "movw" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            old = get(dst)
            high = (old.value & 0xFFFF0000) if old.kind == "CONST" and old.value is not None else 0
            regs[dst] = Sym("CONST", high | (ops[1].imm & 0xFFFF), f"movw @0x{insn.address:08X}")
            continue

        if m == "movt" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            old = get(dst)
            low = (old.value & 0xFFFF) if old.kind == "CONST" and old.value is not None else 0
            regs[dst] = Sym("CONST", low | ((ops[1].imm & 0xFFFF) << 16), f"movt @0x{insn.address:08X}")
            continue

        if m == "adr" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            regs[dst] = Sym("CONST", ops[1].imm & 0xFFFFFFFF, f"adr @0x{insn.address:08X}")
            continue

        if m.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            mem = ops[1]
            regs[dst] = Sym(
                "MEM",
                None,
                f"{m} {label_mem(insn, mem)} @0x{insn.address:08X}",
            )
            continue

        if m in {"add", "adds", "sub", "subs"}:
            # two-operand immediate: dst = dst +/- imm
            if len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                old = get(dst)
                if old.kind == "CONST" and old.value is not None:
                    delta = ops[1].imm
                    val = old.value + delta if m.startswith("add") else old.value - delta
                    regs[dst] = Sym("CONST", val & 0xFFFFFFFF, f"{m} @0x{insn.address:08X}")
                else:
                    regs[dst] = Sym("EXPR", None, f"{old.text()} {m} 0x{ops[1].imm:X}")
                continue

            # three operand form.
            if len(ops) >= 3 and ops[1].type == ARM_OP_REG:
                src = get(ops[1].reg)
                if ops[2].type == ARM_OP_IMM:
                    delta = ops[2].imm
                    if src.kind == "CONST" and src.value is not None:
                        val = src.value + delta if m.startswith("add") else src.value - delta
                        regs[dst] = Sym("CONST", val & 0xFFFFFFFF, f"{m} @0x{insn.address:08X}")
                    else:
                        label = FIELD_LABELS.get(delta)
                        desc = f"{src.text()} {m} 0x{delta:X}"
                        if label:
                            desc += f" <{label}>"
                        regs[dst] = Sym("EXPR", None, desc)
                    continue
                if ops[2].type == ARM_OP_REG:
                    regs[dst] = Sym("EXPR", None, f"{src.text()} {m} {get(ops[2].reg).text()}")
                    continue

        if m in {"lsl", "lsls", "lsr", "lsrs"}:
            set_unknown(dst, f"{m} @0x{insn.address:08X}")
            continue

        # Any unmodelled instruction writing dst invalidates it.
        set_unknown(dst, f"{m} @0x{insn.address:08X}")

    # Build by register names.
    result = {}
    for rn in ("r0", "r1", "r2", "r3"):
        found = None
        for insn in reversed(path):
            for op in insn.operands:
                if op.type == ARM_OP_REG and insn.reg_name(op.reg) == rn:
                    found = op.reg
                    break
            if found is not None:
                break
        result[rn] = get(found) if found is not None else Sym("UNKNOWN", None, "not observed")
    return result


def print_call_window(img: Image, mode: str, call_addr: int, before=0x60, after=0x30):
    md = md_for(mode)
    if mode == "ARM":
        start = max(img.base, call_addr - before) & ~3
    else:
        start = max(img.base, call_addr - before) & ~1
    end = min(img.end, call_addr + after)
    for insn in md.disasm(img.data[img.off(start):img.off(end)], start):
        if insn.address > call_addr + after:
            break
        mark = ">>>" if insn.address == call_addr else "   "
        notes = []
        for op in insn.operands:
            if op.type == ARM_OP_MEM and op.mem.disp in FIELD_LABELS:
                notes.append(FIELD_LABELS[op.mem.disp])
        tgt = direct_target(insn)
        if tgt is not None:
            notes.append(f"target=0x{tgt:08X}")
        print(mark, fmt(insn) + ((" ; " + ", ".join(notes)) if notes else ""))


def post_call_semantics(img: Image, mode: str, call_addr: int, max_insns=18):
    md = md_for(mode)
    start = call_addr + (4 if mode == "ARM" else 4)
    if not img.contains(start):
        return []
    out = []
    for insn in md.disasm(img.data[img.off(start):img.off(start) + 0x60], start):
        out.append(insn)
        if len(out) >= max_insns:
            break
        if insn.mnemonic in {"bx"} and insn.op_str.strip() == "lr":
            break
        if insn.mnemonic == "pop" and "pc" in insn.op_str:
            break
    notes = []
    for insn in out:
        if insn.mnemonic.startswith("str") and len(insn.operands) >= 2:
            src, mem = insn.operands[0], insn.operands[1]
            if src.type == ARM_OP_REG and mem.type == ARM_OP_MEM:
                srcn = insn.reg_name(src.reg)
                disp = mem.mem.disp
                if srcn == "r0" or disp in FIELD_LABELS:
                    label = FIELD_LABELS.get(disp, "")
                    notes.append(
                        f"0x{insn.address:08X} {insn.mnemonic} {insn.op_str}"
                        + (f" <{label}>" if label else "")
                    )
        if insn.mnemonic == "cmp" and insn.op_str.startswith("r0"):
            notes.append(f"0x{insn.address:08X} cmp {insn.op_str}")
    return notes


def supporting_ids_near(img: Image, addr: int, radius=0x100):
    off = img.off(addr)
    lo = max(0, off - radius)
    hi = min(len(img.data), off + radius)
    hits = []
    for value, label in KNOWN_IDS.items():
        pat = struct.pack("<H", value)
        p = img.data.find(pat, lo, hi)
        while p >= 0:
            hits.append((img.base + p, value, label))
            p = img.data.find(pat, p + 1, hi)
    return sorted(hits)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    p.add_argument(
        "--translated",
        default="research/f2/work/extracted/altice_alice/alice-translated-py.bin",
    )
    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a5_alice_menu_veneer_caller_audit.txt",
    )
    return p.parse_args()


def make_path(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    global current_img

    args = parse_args()
    root = Path.cwd()
    ap = make_path(root, args.alice)
    tp = make_path(root, args.translated)
    rp = make_path(root, args.report)
    rp.parent.mkdir(parents=True, exist_ok=True)

    capture = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = Tee(old_stdout, capture)

    try:
        banner("S13.5A.5 - CANONICAL ALICE MENU-VENEER CALLER / PARENT-FLOW AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")

        banner("A. CANONICAL INPUTS")
        alice = verify_required(ap)
        translated = verify_optional_translated(tp)
        images = [alice] + ([translated] if translated else [])

        banner("B. EXACT ARM VENEERS")
        veneers = {}
        for name, target in TARGETS.items():
            found = find_veneers(alice, target)
            veneers[name] = found
            print(f"{name}: target Thumb=0x{target:08X}")
            print(f"  veneers found = {len(found)}")
            for v in found:
                off = alice.off(v)
                raw = alice.data[off:off + 8]
                expected = EXPECTED_VENEERS.get(name)
                tag = " [EXPECTED]" if expected == v else ""
                print(
                    f"  veneer=0x{v:08X} ALICE+0x{off:X}{tag} "
                    f"bytes={raw.hex(' ')}"
                )
            exp = EXPECTED_VENEERS.get(name)
            if exp is not None and exp not in found:
                print(f"  [WARN] expected veneer 0x{exp:08X} not found")

        provider_names = ["GET_CHILD_COUNT", "ENUM_CHILD_IDS", "GET_CHILD_META"]

        banner("C. DIRECT CALLERS OF ALICE VENEERS")
        all_calls = {}

        for img in images:
            current_img = img
            print()
            print("#" * 122)
            print(img.name)
            print("#" * 122)

            for name in provider_names + ["F02D8888_CONTROL"]:
                vlist = veneers.get(name, [])
                if not vlist:
                    print(f"\n{name}: no canonical raw-ALICE veneer -> skip")
                    continue

                # Same offsets/runtime addresses are used for translated image.
                for veneer in vlist:
                    print()
                    print("-" * 122)
                    print(f"{name}: veneer 0x{veneer:08X}")
                    calls = scan_direct_calls(img, veneer)
                    all_calls[(img.name, name, veneer)] = calls
                    print(f"direct BL/BLX callers = {len(calls)}")

                    for mode, insn in calls:
                        print()
                        print(f"CALL {img.name} {mode} {fmt(insn)}")
                        path = decode_path_to_call(img, mode, insn.address)
                        argsym = propagate(path, mode)

                        wanted = ("r0",)
                        if name == "ENUM_CHILD_IDS":
                            wanted = ("r0", "r1")
                        elif name == "F02D8888_CONTROL":
                            wanted = ("r0", "r1", "r2")

                        for rn in wanted:
                            print(f"  {rn}: {argsym[rn].text()}")

                        post = post_call_semantics(img, mode, insn.address)
                        if post:
                            print("  post-call semantic hints:")
                            for s in post:
                                print(f"    {s}")

                        near = supporting_ids_near(img, insn.address)
                        if near:
                            print("  supporting U16 IDs within ±0x100:")
                            for a, value, label in near[:30]:
                                print(f"    0x{a:08X}: 0x{value:04X} <{label}>")
                            if len(near) > 30:
                                print(f"    ... {len(near)-30} more")

                        print("  disassembly window:")
                        print_call_window(img, mode, insn.address)

        banner("D. LITERAL / INDIRECT REFERENCES TO VENEERS")
        for img in images:
            current_img = img
            print()
            print(f"### {img.name}")
            for name in provider_names:
                for veneer in veneers.get(name, []):
                    refs = scan_literal_refs(img, veneer)
                    raw = all_hits(img.data, struct.pack("<I", veneer))
                    print(
                        f"{name} veneer=0x{veneer:08X}: "
                        f"raw pointer words={len(raw)} real PC-literal refs={len(refs)}"
                    )
                    for off in raw[:20]:
                        print(f"  RAW {img.name}+0x{off:X} runtime=0x{img.base+off:08X}")
                    for mode, insn, reg, lit_addr in refs:
                        print(
                            f"  {mode} {fmt(insn)} -> "
                            f"{insn.reg_name(reg)} loads veneer via literal 0x{lit_addr:08X}"
                        )

        banner("E. NEARBY COUNT / ENUM PAIRS")
        pairs = []
        for img in images:
            count_calls = []
            enum_calls = []
            for veneer in veneers.get("GET_CHILD_COUNT", []):
                count_calls.extend(
                    (mode, insn.address)
                    for mode, insn in all_calls.get(
                        (img.name, "GET_CHILD_COUNT", veneer), []
                    )
                )
            for veneer in veneers.get("ENUM_CHILD_IDS", []):
                enum_calls.extend(
                    (mode, insn.address)
                    for mode, insn in all_calls.get(
                        (img.name, "ENUM_CHILD_IDS", veneer), []
                    )
                )

            print(f"{img.name}: COUNT callers={len(count_calls)} ENUM callers={len(enum_calls)}")
            for cmode, ca in count_calls:
                for emode, ea in enum_calls:
                    if cmode == emode and abs(ca - ea) <= 0x300:
                        d = ea - ca
                        pairs.append((img.name, cmode, ca, ea, d))
                        print(
                            f"  pair {cmode}: COUNT@0x{ca:08X} "
                            f"ENUM@0x{ea:08X} delta={d:+#x}"
                        )

        banner("F. DECISION GATE")

        raw_counts = {}
        for name in provider_names:
            raw_counts[name] = sum(
                len(all_calls.get((img.name, name, veneer), []))
                for img in images
                for veneer in veneers.get(name, [])
            )

        for name in provider_names:
            print(f"{name} direct veneer callers (all audited images) = {raw_counts[name]}")
        print(f"nearby COUNT/ENUM pairs = {len(pairs)}")
        print()

        if raw_counts["GET_CHILD_COUNT"] or raw_counts["ENUM_CHILD_IDS"]:
            print("[NEXT] Promote the real ALICE provider caller(s).")
            print("       Recover the r0 parent flow at COUNT/ENUM callsites.")
            print("       If r0 comes from descriptor+0x14, trace the writer of +0x14")
            print("       in that same caller chain until a static menu ID is reached.")
        else:
            print("[NEXT] No direct BL/BLX caller recovered.")
            print("       Follow literal/indirect references to the veneer addresses,")
            print("       then identify the dispatch slot that invokes COUNT/ENUM.")

        print()
        print("Do NOT call any ID 'Multimedia' unless:")
        print("  1. the same parent reaches the provider path, AND")
        print("  2. its recovered child list matches the observed Multimedia menu, OR")
        print("  3. the caller chain structurally identifies the Multimedia descriptor.")
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
        sys.stdout = old_stdout
        rp.write_text(capture.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
