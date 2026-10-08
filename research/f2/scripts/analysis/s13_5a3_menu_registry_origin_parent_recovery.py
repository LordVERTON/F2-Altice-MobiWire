#!/usr/bin/env python3
"""
S13.5A.3 - ZIMAGE menu registry origin + parent-ID recovery audit

STRICTLY OFFLINE / READ-ONLY.

Purpose
-------
Continue S13.5A.2 from the canonical ZIMAGE only.

Known from S13.5A.2:
    F02D8870 = GET_CHILD_COUNT
    F032ACDC = ENUM_CHILD_IDS
    F02F9CCC = GET_CHILD_META
    F02E01B0 = common parent-id -> registry-index helper

    registry root global = F007F044
    neighboring global   = F007F048

    record stride        = 0x10
    record + 0x02        = u16 child_count
    record + 0x08        = u16 GET_CHILD_META field
    record + 0x0C        = pointer to u16 child IDs

This audit does NOT access USB/COM, does NOT generate a patch, and does NOT
write or repack firmware.

Main gates:
  A. Verify canonical ZIMAGE identity.
  B. Fully dump / semantically annotate F02E01B0.
  C. Find all literal references to F007F044 / F007F048 and classify nearby
     reads/writes/initializers.
  D. Validate and backward-slice direct callers of GET_CHILD_COUNT and
     GET_CHILD_META.
  E. Find direct calls and exact function-pointer references to ENUM_CHILD_IDS,
     including Thumb pointer F032ACDD.
  F. Produce candidate parent IDs only when a constant can be propagated into r0.
  G. Keep raw-ID evidence separate from proven parent/child relations.

Default input:
  research/f2/work/extracted/altice_platform/zimage.bin

Default report:
  research/f2/work/reports/s13_5a3_menu_registry_origin_parent_recovery.txt
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

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import (
        ARM_OP_IMM,
        ARM_OP_MEM,
        ARM_OP_REG,
        ARM_REG_PC,
    )
except Exception as exc:
    print(f"ERROR: capstone import failed: {exc}")
    raise SystemExit(2)


# --------------------------------------------------------------------------------------
# Canonical S13 constants
# --------------------------------------------------------------------------------------

ZIMAGE_BASE = 0xF023CA50
EXPECTED_ZIMAGE_SIZE = 0x185E98
EXPECTED_ZIMAGE_SHA256 = (
    "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
)

GET_CHILD_COUNT = 0xF02D8870
ENUM_CHILD_IDS = 0xF032ACDC
ENUM_CHILD_IDS_THUMB = 0xF032ACDD
GET_CHILD_META = 0xF02F9CCC
PARENT_TO_INDEX = 0xF02E01B0

REGISTRY_GLOBAL = 0xF007F044
LOOKUP_GLOBAL = 0xF007F048

IMAGE_A = 0x8313
IMAGE_B = 0x8321
AUDIO = 0x8928

# S13.5A.2 direct-call census; A.3 revalidates these before slicing.
EXPECTED_COUNT_CALLERS = {
    0xF0305E82,
    0xF030791A,
    0xF030934C,
    0xF0310306,
    0xF0329CD0,
}

EXPECTED_META_CALLERS = {
    0xF02F524C,
    0xF03002D4,
}

KNOWN_NAMES = {
    GET_CHILD_COUNT: "GET_CHILD_COUNT",
    ENUM_CHILD_IDS: "ENUM_CHILD_IDS",
    ENUM_CHILD_IDS_THUMB: "ENUM_CHILD_IDS Thumb",
    GET_CHILD_META: "GET_CHILD_META",
    PARENT_TO_INDEX: "PARENT_TO_INDEX",
    REGISTRY_GLOBAL: "REGISTRY_GLOBAL",
    LOOKUP_GLOBAL: "LOOKUP_GLOBAL",
}


# --------------------------------------------------------------------------------------
# Output / utilities
# --------------------------------------------------------------------------------------

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


def banner(title: str) -> None:
    print()
    print("=" * 118)
    print(title)
    print("=" * 118)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def addr_to_off(addr: int) -> int:
    return addr - ZIMAGE_BASE


def in_zimage(addr: int, data: bytes) -> bool:
    off = addr_to_off(addr & ~1)
    return 0 <= off < len(data)


def name_of(addr: int) -> str:
    return KNOWN_NAMES.get(addr, KNOWN_NAMES.get(addr & ~1, ""))


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True


def decode_one(data: bytes, addr: int):
    off = addr_to_off(addr)
    if off < 0 or off >= len(data):
        return None
    insns = list(md.disasm(data[off:off + 4], addr, count=1))
    return insns[0] if insns else None


def direct_target(insn) -> Optional[int]:
    if insn.mnemonic not in {
        "bl", "blx", "b", "b.w", "beq", "bne", "bhi", "bls", "bcc", "bcs",
        "bgt", "blt", "bge", "ble", "cbz", "cbnz",
    }:
        return None
    if not insn.operands:
        return None
    if insn.operands[0].type != ARM_OP_IMM:
        return None
    return insn.operands[0].imm & 0xFFFFFFFF


def literal_load(insn, data: bytes):
    if not insn.mnemonic.startswith("ldr"):
        return None
    if len(insn.operands) < 2:
        return None

    dst = insn.operands[0]
    src = insn.operands[1]

    if dst.type != ARM_OP_REG or src.type != ARM_OP_MEM:
        return None
    if src.mem.base != ARM_REG_PC:
        return None

    pc = (insn.address + 4) & ~3
    lit_addr = (pc + src.mem.disp) & 0xFFFFFFFF
    lit_off = addr_to_off(lit_addr)
    value = u32(data, lit_off)
    if value is None:
        return None

    return {
        "dst_reg_id": dst.reg,
        "dst": insn.reg_name(dst.reg),
        "literal_addr": lit_addr,
        "value": value,
    }


def fmt_insn(insn, data: bytes) -> str:
    comments = []

    tgt = direct_target(insn)
    if tgt is not None:
        label = name_of(tgt)
        comments.append(
            f"TARGET=0x{tgt:08X}" + (f" <{label}>" if label else "")
        )

    lit = literal_load(insn, data)
    if lit:
        label = name_of(lit["value"])
        loc = "ZIMAGE" if in_zimage(lit["value"], data) else "NON_ZIMAGE"
        comments.append(
            f"LITERAL[0x{lit['literal_addr']:08X}]=0x{lit['value']:08X} "
            f"{loc} -> {lit['dst']}"
            + (f" <{label}>" if label else "")
        )

    suffix = ""
    if comments:
        suffix = " ; " + " ; ".join(comments)

    return (
        f"0x{insn.address:08X}: {insn.bytes.hex(' '):<14} "
        f"{insn.mnemonic:<9} {insn.op_str:<36}{suffix}"
    )


def disasm_range(data: bytes, start: int, size: int):
    off = addr_to_off(start)
    if off < 0:
        return []
    blob = data[off:min(len(data), off + size)]
    return list(md.disasm(blob, start))


def dump_window(data: bytes, center: int, before: int = 0x40, after: int = 0x60) -> None:
    start = max(ZIMAGE_BASE, (center - before) & ~1)
    end = min(ZIMAGE_BASE + len(data), center + after)
    for insn in disasm_range(data, start, end - start):
        marker = ">>>" if insn.address == center else "   "
        print(marker, fmt_insn(insn, data))


def find_all(data: bytes, value: int) -> list[int]:
    pat = struct.pack("<I", value & 0xFFFFFFFF)
    out = []
    pos = 0
    while True:
        pos = data.find(pat, pos)
        if pos < 0:
            break
        out.append(pos)
        pos += 1
    return out


# --------------------------------------------------------------------------------------
# Direct-call scanner
# --------------------------------------------------------------------------------------

def looks_like_thumb32_branch(data: bytes, off: int) -> bool:
    h1 = u16(data, off)
    h2 = u16(data, off + 2)
    if h1 is None or h2 is None:
        return False
    # Thumb-2 BL/BLX family prefilter. Capstone does final classification.
    return (h1 & 0xF800) == 0xF000 and (h2 & 0xC000) == 0xC000


def scan_direct_calls_to(data: bytes, targets: set[int]):
    norm_targets = {x & ~1 for x in targets}
    hits = []
    for off in range(0, len(data) - 4, 2):
        if not looks_like_thumb32_branch(data, off):
            continue
        addr = ZIMAGE_BASE + off
        insn = decode_one(data, addr)
        if insn is None or insn.mnemonic not in {"bl", "blx"}:
            continue
        tgt = direct_target(insn)
        if tgt is None:
            continue
        if (tgt & ~1) in norm_targets:
            hits.append((insn.address, tgt, insn))
    return hits


# --------------------------------------------------------------------------------------
# Literal-address xrefs / global access classification
# --------------------------------------------------------------------------------------

@dataclass
class LiteralXref:
    insn_addr: int
    literal_addr: int
    loaded_value: int
    dst: str
    dst_reg_id: int


def find_literal_xrefs_to_word(data: bytes, word_value: int) -> list[LiteralXref]:
    """
    Find LDR-literal instructions whose literal word equals word_value.

    We first locate the raw word. A Thumb PC-relative literal load can only
    address a nearby pool, so we scan at most ~0x1100 bytes before each pool.
    """
    raw_positions = find_all(data, word_value)
    hits: dict[int, LiteralXref] = {}

    for lit_off in raw_positions:
        lit_addr = ZIMAGE_BASE + lit_off
        start_off = max(0, lit_off - 0x1100)
        start_off &= ~1

        for off in range(start_off, min(lit_off + 2, len(data) - 2), 2):
            insn = decode_one(data, ZIMAGE_BASE + off)
            if insn is None:
                continue
            lit = literal_load(insn, data)
            if not lit:
                continue
            if lit["literal_addr"] != lit_addr:
                continue
            if lit["value"] != word_value:
                continue

            hits[insn.address] = LiteralXref(
                insn_addr=insn.address,
                literal_addr=lit_addr,
                loaded_value=word_value,
                dst=lit["dst"],
                dst_reg_id=lit["dst_reg_id"],
            )

    return [hits[k] for k in sorted(hits)]


def memory_base_reg(insn):
    for op in insn.operands:
        if op.type == ARM_OP_MEM:
            return op.mem.base
    return None


def classify_global_use(data: bytes, xref: LiteralXref, max_insns: int = 24):
    """
    Light local classification after:
        LDR rN, =F007F044/F007F048

    It looks for dereference reads/writes through the loaded register before
    that register is obviously overwritten. This is evidence, not a full SSA.
    """
    start = xref.insn_addr
    insns = disasm_range(data, start, 0x70)
    tracked = xref.dst_reg_id
    events = []

    for i, insn in enumerate(insns):
        if i == 0:
            continue
        if i > max_insns:
            break

        # Calls/returns delimit the local confidence window.
        if insn.mnemonic in {"bl", "blx"}:
            events.append(("CALL_BOUNDARY", insn))
            continue
        if insn.mnemonic == "pop" and "pc" in insn.op_str:
            break

        base = memory_base_reg(insn)
        if base == tracked:
            if insn.mnemonic.startswith(("ldr", "ldm")):
                events.append(("READ_THROUGH_GLOBAL_ADDR", insn))
            elif insn.mnemonic.startswith(("str", "stm")):
                events.append(("WRITE_THROUGH_GLOBAL_ADDR", insn))
            else:
                events.append(("MEMORY_USE_THROUGH_GLOBAL_ADDR", insn))

        # If the tracked register is directly written with a non-memory value,
        # stop after recording the current instruction.
        if insn.operands and insn.operands[0].type == ARM_OP_REG:
            if insn.operands[0].reg == tracked:
                if insn.mnemonic.startswith("ldr") and base == tracked:
                    # e.g. ldr r1,[r1] transforms address -> value; keep no longer.
                    break
                if insn.mnemonic not in {"cmp", "tst"}:
                    break

    return events


# --------------------------------------------------------------------------------------
# Lightweight constant propagation for r0 before provider calls
# --------------------------------------------------------------------------------------

@dataclass
class SymVal:
    kind: str
    value: Optional[int] = None
    source: str = ""

    def __str__(self):
        if self.kind == "CONST" and self.value is not None:
            return f"CONST 0x{self.value & 0xFFFFFFFF:08X} ({self.value & 0xFFFFFFFF}) via {self.source}"
        return f"{self.kind}" + (f" via {self.source}" if self.source else "")


def unknown(source="") -> SymVal:
    return SymVal("UNKNOWN", None, source)


def const(value: int, source="") -> SymVal:
    return SymVal("CONST", value & 0xFFFFFFFF, source)


def eval_call_arg_r0(data: bytes, call_addr: int, before: int = 0x80):
    """
    Conservative forward propagation over the local disassembly window.

    Supports:
      mov/movs reg,#imm
      mov reg,reg
      movw/movt
      adr
      ldr reg,=literal
      adds/subs with immediate when source is constant
      eors reg,reg -> 0 (common zeroing)

    Loads from ordinary memory make destination UNKNOWN.
    Any call before the target invalidates r0-r3 conservatively.
    """
    start = max(ZIMAGE_BASE, (call_addr - before) & ~1)
    insns = [i for i in disasm_range(data, start, call_addr - start + 4)
             if i.address <= call_addr]

    regs: dict[int, SymVal] = {}

    def get(reg_id):
        return regs.get(reg_id, unknown())

    for insn in insns:
        if insn.address == call_addr:
            break

        m = insn.mnemonic
        ops = insn.operands

        if m in {"bl", "blx"}:
            # AAPCS caller-saved registers.
            for rid in list(regs):
                rn = insn.reg_name(rid)
                if rn in {"r0", "r1", "r2", "r3", "r12", "lr"}:
                    regs[rid] = unknown(f"clobbered by call @0x{insn.address:08X}")
            continue

        if not ops or ops[0].type != ARM_OP_REG:
            continue

        dst = ops[0].reg
        dst_name = insn.reg_name(dst)

        # LDR literal.
        lit = literal_load(insn, data)
        if lit is not None:
            regs[dst] = const(lit["value"], f"literal @0x{lit['literal_addr']:08X}")
            continue

        # Ordinary loads: unknown runtime data.
        if m.startswith("ldr"):
            regs[dst] = unknown(f"{m} memory load @0x{insn.address:08X}")
            continue

        if m in {"mov", "movs"} and len(ops) >= 2:
            if ops[1].type == ARM_OP_IMM:
                regs[dst] = const(ops[1].imm, f"{m} immediate @0x{insn.address:08X}")
            elif ops[1].type == ARM_OP_REG:
                regs[dst] = get(ops[1].reg)
            else:
                regs[dst] = unknown(f"{m} unsupported source")
            continue

        if m == "movw" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            prev = get(dst)
            high = (prev.value & 0xFFFF0000) if prev.kind == "CONST" and prev.value is not None else 0
            regs[dst] = const(high | (ops[1].imm & 0xFFFF), f"movw @0x{insn.address:08X}")
            continue

        if m == "movt" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            prev = get(dst)
            low = (prev.value & 0xFFFF) if prev.kind == "CONST" and prev.value is not None else 0
            regs[dst] = const(low | ((ops[1].imm & 0xFFFF) << 16), f"movt @0x{insn.address:08X}")
            continue

        if m in {"add", "adds", "sub", "subs"}:
            # Forms:
            #   adds r0, #imm
            #   add r0, r1, #imm
            try:
                if len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                    prev = get(dst)
                    if prev.kind == "CONST" and prev.value is not None:
                        delta = ops[1].imm
                        regs[dst] = const(
                            prev.value + delta if m.startswith("add") else prev.value - delta,
                            f"{m} immediate @0x{insn.address:08X}",
                        )
                    else:
                        regs[dst] = unknown(f"{m} with unknown dst")
                elif len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                    src = get(ops[1].reg)
                    if src.kind == "CONST" and src.value is not None:
                        delta = ops[2].imm
                        regs[dst] = const(
                            src.value + delta if m.startswith("add") else src.value - delta,
                            f"{m} immediate @0x{insn.address:08X}",
                        )
                    else:
                        regs[dst] = unknown(f"{m} with unknown src")
                else:
                    regs[dst] = unknown(f"{m} unsupported form")
            except Exception:
                regs[dst] = unknown(f"{m} parse failure")
            continue

        if m in {"eor", "eors"} and len(ops) >= 2:
            # eors rX,rX is a reliable zeroing idiom.
            same = False
            if len(ops) == 2 and ops[1].type == ARM_OP_REG:
                same = ops[1].reg == dst
            elif len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_REG:
                same = ops[1].reg == ops[2].reg
            if same:
                regs[dst] = const(0, f"{m} self-zero @0x{insn.address:08X}")
            else:
                regs[dst] = unknown(f"{m}")
            continue

        # Any instruction that writes dst but is not modeled invalidates it.
        if dst_name.startswith("r"):
            regs[dst] = unknown(f"unmodeled {m} @0x{insn.address:08X}")

    # r0 is ARM register id 66 in Capstone ARM, but never hardcode it:
    r0_id = None
    for insn in insns:
        for op in insn.operands:
            if op.type == ARM_OP_REG and insn.reg_name(op.reg) == "r0":
                r0_id = op.reg
                break
        if r0_id is not None:
            break

    if r0_id is None:
        return unknown("r0 not encountered"), insns

    return get(r0_id), insns


# --------------------------------------------------------------------------------------
# F02E01B0 helper analysis
# --------------------------------------------------------------------------------------

def dump_helper(data: bytes) -> None:
    banner("B. F02E01B0 PARENT-ID -> REGISTRY-INDEX HELPER")

    if not in_zimage(PARENT_TO_INDEX, data):
        print("[FAIL] helper outside canonical ZIMAGE")
        return

    print(f"[PASS] helper 0x{PARENT_TO_INDEX:08X} inside ZIMAGE")
    print(f"       ZIMAGE+0x{addr_to_off(PARENT_TO_INDEX):X}")

    # S13.5A.2 reported 30 instructions. Dump a bounded region and stop at
    # the first return-like instruction after a reasonable minimum.
    insns = disasm_range(data, PARENT_TO_INDEX, 0xA0)
    count = 0
    for insn in insns:
        print(fmt_insn(insn, data))
        count += 1
        if count >= 6:
            if insn.mnemonic == "pop" and "pc" in insn.op_str:
                break
            if insn.mnemonic in {"bx"} and insn.op_str.strip() == "lr":
                break

    print()
    print(f"instructions dumped = {count}")

    # Local semantic anchors.
    refs = []
    for insn in insns[:max(count, 30)]:
        lit = literal_load(insn, data)
        if lit and lit["value"] in {REGISTRY_GLOBAL, LOOKUP_GLOBAL}:
            refs.append((insn.address, lit["value"], lit["dst"]))
    for addr, val, dst in refs:
        print(f"[ANCHOR] 0x{addr:08X}: {dst} <- 0x{val:08X} <{name_of(val)}>")

    if not refs:
        print("[WARN] no direct literal anchor to F007F044/F048 in helper window")


# --------------------------------------------------------------------------------------
# Provider caller slices
# --------------------------------------------------------------------------------------

def analyze_provider_callers(data: bytes, target: int, expected: set[int], label: str):
    banner(f"D. {label} DIRECT CALLERS + r0 BACKWARD SLICE")

    hits = scan_direct_calls_to(data, {target})
    hit_addrs = {addr for addr, _, _ in hits}

    print(f"target = 0x{target:08X}")
    print(f"direct calls found = {len(hits)}")
    print("found callsites:")
    for addr in sorted(hit_addrs):
        print(f"  0x{addr:08X}")

    if expected:
        missing = sorted(expected - hit_addrs)
        extra = sorted(hit_addrs - expected)
        if not missing and not extra:
            print("[PASS] direct-call set matches S13.5A.2")
        else:
            print(f"[WARN] missing expected = {[hex(x) for x in missing]}")
            print(f"[WARN] extra found      = {[hex(x) for x in extra]}")

    candidates = []

    for call_addr in sorted(hit_addrs):
        print()
        print("-" * 118)
        print(f"CALLSITE 0x{call_addr:08X}")
        val, _ = eval_call_arg_r0(data, call_addr)

        print(f"r0 at call: {val}")
        if val.kind == "CONST" and val.value is not None:
            parent_id = val.value & 0xFFFF
            high = val.value >> 16
            print(f"  -> low16 candidate parent_id = 0x{parent_id:04X}")
            if high == 0:
                print("  -> [CANDIDATE] exact 16-bit constant parent ID")
                candidates.append((call_addr, parent_id))
            else:
                print("  -> constant is wider than u16; do not promote automatically")
        else:
            print("  -> parent ID not statically constant in this local slice")

        dump_window(data, call_addr, before=0x60, after=0x20)

    return candidates


# --------------------------------------------------------------------------------------
# ENUM_CHILD_IDS direct/indirect references
# --------------------------------------------------------------------------------------

def analyze_enum_refs(data: bytes):
    banner("E. ENUM_CHILD_IDS DIRECT + FUNCTION-POINTER REFERENCES")

    direct = scan_direct_calls_to(data, {ENUM_CHILD_IDS})
    print(f"direct BL/BLX calls = {len(direct)}")
    for addr, tgt, insn in direct:
        print(f"  0x{addr:08X} -> 0x{tgt:08X}  {insn.mnemonic} {insn.op_str}")

    for ptr in (ENUM_CHILD_IDS, ENUM_CHILD_IDS_THUMB):
        positions = find_all(data, ptr)
        print()
        print(f"exact raw pointer 0x{ptr:08X}: {len(positions)} occurrence(s)")
        for off in positions:
            runtime = ZIMAGE_BASE + off
            print(f"  ZIMAGE+0x{off:X} runtime=0x{runtime:08X}")
            # Show surrounding words; function tables are often easier to see as data.
            start = max(0, off - 0x20)
            end = min(len(data), off + 0x24)
            start &= ~3
            for woff in range(start, end - 3, 4):
                v = u32(data, woff)
                mark = ">>>" if woff == off else "   "
                label = name_of(v or 0)
                print(
                    f"{mark} +0x{woff:06X} 0x{ZIMAGE_BASE + woff:08X}: "
                    f"0x{(v or 0):08X}" + (f" <{label}>" if label else "")
                )

    return direct


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="S13.5A.3 offline menu registry origin + parent-ID recovery"
    )
    p.add_argument(
        "--zimage",
        default="research/f2/work/extracted/altice_platform/zimage.bin",
        help="Canonical decompressed ZIMAGE path",
    )
    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a3_menu_registry_origin_parent_recovery.txt",
        help="Report output path",
    )
    return p.parse_args()


def main():
    args = parse_args()
    root = Path.cwd()
    zpath = Path(args.zimage)
    if not zpath.is_absolute():
        zpath = root / zpath

    rpath = Path(args.report)
    if not rpath.is_absolute():
        rpath = root / rpath
    rpath.parent.mkdir(parents=True, exist_ok=True)

    buffer = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = Tee(old_stdout, buffer)

    exit_code = 0
    try:
        banner("S13.5A.3 - ZIMAGE MENU REGISTRY ORIGIN + PARENT-ID RECOVERY")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")
        print()

        print("[A] INPUT")
        print(f"ZIMAGE = {zpath}")

        if not zpath.exists():
            print("[FAIL] ZIMAGE file missing")
            return 2

        data = zpath.read_bytes()
        digest = sha256(data)

        print(f"size   = 0x{len(data):X}")
        print(f"sha256 = {digest}")

        if len(data) != EXPECTED_ZIMAGE_SIZE:
            print(
                f"[FAIL] canonical size mismatch: expected 0x{EXPECTED_ZIMAGE_SIZE:X}"
            )
            return 3

        if digest.lower() != EXPECTED_ZIMAGE_SHA256.lower():
            print("[FAIL] canonical ZIMAGE SHA256 mismatch")
            print("Refusing to mix firmware baselines.")
            return 4

        print("[PASS] canonical ZIMAGE identity")

        # Provider/helper physical presence.
        banner("A. CANONICAL ADDRESS CHECKS")
        for addr, label in [
            (GET_CHILD_COUNT, "GET_CHILD_COUNT"),
            (ENUM_CHILD_IDS, "ENUM_CHILD_IDS"),
            (GET_CHILD_META, "GET_CHILD_META"),
            (PARENT_TO_INDEX, "PARENT_TO_INDEX"),
        ]:
            if in_zimage(addr, data):
                print(
                    f"[PASS] {label:<18} 0x{addr:08X} "
                    f"ZIMAGE+0x{addr_to_off(addr):X}"
                )
            else:
                print(f"[FAIL] {label} outside ZIMAGE")
                exit_code = max(exit_code, 5)

        dump_helper(data)

        # Global references.
        banner("C. F007F044 / F007F048 LITERAL XREF + ACCESS CENSUS")
        global_summary = {}
        for gv, label in [
            (REGISTRY_GLOBAL, "REGISTRY_GLOBAL"),
            (LOOKUP_GLOBAL, "LOOKUP_GLOBAL"),
        ]:
            print()
            print("-" * 118)
            print(f"{label} = 0x{gv:08X}")
            raw = find_all(data, gv)
            xrefs = find_literal_xrefs_to_word(data, gv)
            print(f"raw 32-bit literal occurrences = {len(raw)}")
            print(f"real PC-literal LDR xrefs       = {len(xrefs)}")

            reads = []
            writes = []

            for off in raw:
                print(f"  literal ZIMAGE+0x{off:X} runtime=0x{ZIMAGE_BASE + off:08X}")

            for xr in xrefs:
                print()
                print(
                    f"XREF 0x{xr.insn_addr:08X}: {xr.dst} <- "
                    f"[literal 0x{xr.literal_addr:08X}] = 0x{gv:08X}"
                )
                events = classify_global_use(data, xr)
                if not events:
                    print("  local dereference classification: no resolved event")
                for kind, insn in events:
                    print(f"  {kind}: {fmt_insn(insn, data)}")
                    if kind.startswith("READ"):
                        reads.append(insn.address)
                    if kind.startswith("WRITE"):
                        writes.append(insn.address)

                dump_window(data, xr.insn_addr, before=0x20, after=0x60)

            global_summary[gv] = {
                "raw": raw,
                "xrefs": xrefs,
                "reads": sorted(set(reads)),
                "writes": sorted(set(writes)),
            }

            print()
            print(f"SUMMARY {label}")
            print(f"  classified read-through sites : {len(set(reads))}")
            print(f"  classified write-through sites: {len(set(writes))}")
            for a in sorted(set(writes)):
                print(f"    WRITE candidate @0x{a:08X}")

        # Provider callers / parent candidates.
        count_candidates = analyze_provider_callers(
            data,
            GET_CHILD_COUNT,
            EXPECTED_COUNT_CALLERS,
            "GET_CHILD_COUNT",
        )

        meta_candidates = analyze_provider_callers(
            data,
            GET_CHILD_META,
            EXPECTED_META_CALLERS,
            "GET_CHILD_META",
        )

        enum_direct = analyze_enum_refs(data)

        # Consolidate candidate parent IDs.
        banner("F. CONSOLIDATED STATIC PARENT-ID CANDIDATES")
        by_id: dict[int, list[str]] = {}

        for call, pid in count_candidates:
            by_id.setdefault(pid, []).append(f"GET_CHILD_COUNT call@0x{call:08X}")
        for call, pid in meta_candidates:
            by_id.setdefault(pid, []).append(f"GET_CHILD_META call@0x{call:08X}")

        if not by_id:
            print("No parent ID could be promoted to a static constant.")
            print("This is a valid result: next pivot is the initializer/dataflow of F007F044/F048.")
        else:
            for pid, evidence in sorted(by_id.items()):
                print(f"parent candidate 0x{pid:04X}")
                for item in evidence:
                    print(f"  - {item}")

        # Strict decision gate.
        banner("S13.5A.3 DECISION GATE")

        registry_writes = global_summary[REGISTRY_GLOBAL]["writes"]
        lookup_writes = global_summary[LOOKUP_GLOBAL]["writes"]

        print("Interpretation order:")
        print("  1. Trust only canonical-ZIMAGE code paths.")
        print("  2. Promote parent IDs only when r0 is statically constant at a provider call.")
        print("  3. Treat F007F044/F048 write sites as initializer candidates, not proven semantics.")
        print("  4. Treat raw function pointers / raw U16 IDs as supporting evidence only.")
        print("  5. Do not call a parent 'Multimedia' until its children are structurally recovered.")
        print()

        print(f"registry-global write candidates = {len(registry_writes)}")
        print(f"lookup-global write candidates   = {len(lookup_writes)}")
        print(f"static parent IDs promoted       = {len(by_id)}")
        print(f"ENUM direct calls                = {len(enum_direct)}")
        print()

        if registry_writes or lookup_writes:
            print("[NEXT] Deep-slice the global initializer candidate(s) to their source table/allocation.")
        elif by_id:
            print("[NEXT] Resolve F02E01B0 for promoted parent IDs and recover the corresponding record source.")
        else:
            print("[NEXT] No initializer or constant parent recovered yet.")
            print("       Extend the slice around F02E01B0 and indirect provider tables; do NOT patch.")

        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {rpath}")

        return exit_code

    finally:
        sys.stdout = old_stdout
        rpath.write_text(buffer.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
