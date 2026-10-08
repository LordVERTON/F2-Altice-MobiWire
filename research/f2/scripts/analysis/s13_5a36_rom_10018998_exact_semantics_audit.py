#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.36 - ROM 0x10018998 EXACT SEMANTICS AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no D3 / D5 / D6
- no write / erase
- no phone access

Background
----------
A.35 proved that BOOT_ZIMAGE address F0210588 contains the ARM veneer:

    F0210588: LDR PC, [PC, #-4]
    literal : 0x10018998

The filter bitmap initializer calls F0210588 with:

    r0 = F00C1624
    r1 = (*(u32 *)F007F04C >> 3) + 1

Repository mapping already used by project analysis maps the early physical
dump as runtime ROM at base 0x10000000. Therefore 0x10018998 corresponds to
physical dump offset 0x18998.

A.36 guards the canonical dump and decodes the TRUE ARM implementation at
0x10018998. It also inspects nearby target 0x100189D8.

No semantic label is promoted automatically. The report prints enough exact
ARM instructions / stores / branches to decide whether 0x10018998 zeroes
r1 bytes beginning at r0.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from capstone import (
        Cs,
        CS_ARCH_ARM,
        CS_MODE_ARM,
        CS_MODE_LITTLE_ENDIAN,
        CS_GRP_CALL,
        CS_GRP_JUMP,
        CS_OP_IMM,
        CS_OP_MEM,
        CS_OP_REG,
    )
    from capstone.arm import (
        ARM_REG_PC,
        ARM_REG_LR,
    )
except Exception as exc:
    raise SystemExit(
        "capstone is required in the project venv.\n"
        r"Use C:\Users\verto\mtkclient\.venv\Scripts\python.exe" "\n"
        f"Import error: {exc}"
    )

TITLE = "S13.5A.36 - ROM 0x10018998 EXACT SEMANTICS AUDIT"

DUMP_SIZE = 0x400000
DUMP_SHA256 = "2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922"

ROM_BASE = 0x10000000
ROM_END = 0x1004C20C

TARGET = 0x10018998
NEIGHBOR = 0x100189D8

VENEER = 0xF0210588
VENEER_NEIGHBOR = 0xF02105B8

FILTER_BITMAP = 0xF00C1624
FILTER_BOUND = 0xF007F04C


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Image:
    name: str
    data: bytes
    base: int

    @property
    def end(self) -> int:
        return self.base + len(self.data)

    def contains(self, addr: int, n: int = 1) -> bool:
        return self.base <= addr and addr + n <= self.end

    def read(self, addr: int, n: int) -> bytes:
        if not self.contains(addr, n):
            raise ValueError(f"{self.name}: out of range 0x{addr:08X}+0x{n:X}")
        return self.data[addr - self.base: addr - self.base + n]

    def read_u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.read(addr, 4))[0]


@dataclass
class Insn:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    target: Optional[int] = None
    is_call: bool = False
    is_jump: bool = False
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None

    @property
    def text(self) -> str:
        return f"{self.mnemonic:<10} {self.op_str}".rstrip()


@dataclass
class FunctionAudit:
    entry: int
    visited: Dict[int, Insn] = field(default_factory=dict)
    calls: List[Tuple[int, int]] = field(default_factory=list)
    branches: List[Tuple[int, int]] = field(default_factory=list)
    stores: List[int] = field(default_factory=list)
    loads: List[int] = field(default_factory=list)
    truncated: bool = False


class ArmAuditor:
    def __init__(self, rom: Image):
        self.rom = rom
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def decode_one(self, addr: int) -> Optional[Insn]:
        if addr & 3:
            return None
        if not self.rom.contains(addr, 4):
            return None

        ds = list(self.md.disasm(self.rom.read(addr, 4), addr, count=1))
        if not ds:
            return None

        ci = ds[0]
        is_call = bool(ci.group(CS_GRP_CALL))
        is_jump = bool(ci.group(CS_GRP_JUMP))

        target = None
        if (is_call or is_jump) and ci.operands:
            op0 = ci.operands[0]
            if op0.type == CS_OP_IMM:
                target = int(op0.imm) & 0xFFFFFFFF

        literal_addr = None
        literal_value = None

        # ARM-state PC points to current + 8.
        if ci.mnemonic.lower().startswith("ldr") and len(ci.operands) >= 2:
            op = ci.operands[1]
            if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                literal_addr = (addr + 8 + int(op.mem.disp)) & 0xFFFFFFFF
                if self.rom.contains(literal_addr, 4):
                    literal_value = self.rom.read_u32(literal_addr)

        return Insn(
            addr=addr,
            size=ci.size,
            mnemonic=ci.mnemonic,
            op_str=ci.op_str,
            target=target,
            is_call=is_call,
            is_jump=is_jump,
            literal_addr=literal_addr,
            literal_value=literal_value,
        )

    @staticmethod
    def is_return(ins: Insn) -> bool:
        m = ins.mnemonic.lower()
        o = ins.op_str.lower().replace(" ", "")

        if m == "bx" and o == "lr":
            return True
        if m == "mov" and o == "pc,lr":
            return True
        if m.startswith("ldm") and "pc" in o:
            return True
        if m == "pop" and "pc" in o:
            return True
        return False

    @staticmethod
    def is_unconditional_branch(ins: Insn) -> bool:
        # Capstone keeps condition suffixes in mnemonic for ARM:
        # b, beq, bne, bgt, etc.
        return ins.mnemonic.lower() == "b"

    @staticmethod
    def is_store(ins: Insn) -> bool:
        m = ins.mnemonic.lower()
        return m.startswith("str") or m.startswith("stm")

    @staticmethod
    def is_load(ins: Insn) -> bool:
        m = ins.mnemonic.lower()
        return m.startswith("ldr") or m.startswith("ldm")

    def audit_function(
        self,
        entry: int,
        max_span: int = 0x300,
        max_insns: int = 1200,
    ) -> FunctionAudit:
        out = FunctionAudit(entry=entry)
        q = deque([entry])
        seen: Set[int] = set()

        lo = entry
        hi = entry + max_span

        while q and len(seen) < max_insns:
            addr = q.popleft()

            if addr in seen:
                continue
            if addr < lo or addr >= hi:
                out.truncated = True
                continue

            ins = self.decode_one(addr)
            if ins is None:
                continue

            seen.add(addr)
            out.visited[addr] = ins

            if self.is_store(ins):
                out.stores.append(addr)
            if self.is_load(ins):
                out.loads.append(addr)

            if ins.is_call and ins.target is not None:
                out.calls.append((addr, ins.target))
                # Function call returns to next instruction.
                q.append(addr + 4)
                continue

            if self.is_return(ins):
                continue

            if ins.is_jump:
                if ins.target is not None:
                    out.branches.append((addr, ins.target))
                    # Follow in-function direct branch target.
                    if lo <= ins.target < hi:
                        q.append(ins.target)
                if not self.is_unconditional_branch(ins):
                    q.append(addr + 4)
                continue

            q.append(addr + 4)

        if q:
            out.truncated = True

        return out


def hdr(title: str) -> None:
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def raw_hex(img: Image, addr: int, before: int = 0x20, after: int = 0x100) -> None:
    lo = max(img.base, addr - before)
    hi = min(img.end, addr + after)
    data = img.read(lo, hi - lo)

    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        print(f"0x{lo + off:08X}: " + " ".join(f"{b:02X}" for b in chunk))


def print_linear(aud: ArmAuditor, start: int, size: int = 0x100) -> None:
    end = start + size
    addr = start
    while addr < end and aud.rom.contains(addr, 4):
        ins = aud.decode_one(addr)
        if ins is None:
            word = aud.rom.read_u32(addr)
            print(f"0x{addr:08X}: .word      0x{word:08X}")
            addr += 4
            continue

        ann = []
        if ins.target is not None:
            ann.append(f"target=0x{ins.target:08X}")
        if ins.literal_addr is not None and ins.literal_value is not None:
            ann.append(
                f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}"
            )
        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"0x{addr:08X}: {ins.text}{suffix}")
        addr += 4


def print_cfg(aud: ArmAuditor, fa: FunctionAudit) -> None:
    print(f"entry              = 0x{fa.entry:08X}")
    print(f"physical dump off  = 0x{fa.entry - ROM_BASE:X}")
    print(f"reachable insns    = {len(fa.visited)}")
    print(f"direct calls       = {len(fa.calls)}")
    print(f"direct branches    = {len(fa.branches)}")
    print(f"memory stores      = {len(fa.stores)}")
    print(f"memory loads       = {len(fa.loads)}")
    print(f"truncated          = {fa.truncated}")
    print()

    for addr in sorted(fa.visited):
        ins = fa.visited[addr]
        ann = []

        if ins.target is not None:
            ann.append(f"target=0x{ins.target:08X}")

        if ins.literal_addr is not None and ins.literal_value is not None:
            ann.append(
                f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}"
            )

        if ArmAuditor.is_store(ins):
            ann.append("STORE")
        if ArmAuditor.is_return(ins):
            ann.append("RETURN")

        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"0x{addr:08X}: {ins.text}{suffix}")


def print_store_context(aud: ArmAuditor, fa: FunctionAudit) -> None:
    if not fa.stores:
        print("<no reachable memory store>")
        return

    for site in fa.stores:
        print()
        print(f"STORE @ 0x{site:08X}")
        for addr in range(max(fa.entry, site - 0x18), site + 0x1C, 4):
            ins = fa.visited.get(addr)
            if ins is None:
                ins = aud.decode_one(addr)
            if ins is None:
                continue
            marker = ">>>" if addr == site else "   "
            print(f"{marker} 0x{addr:08X}: {ins.text}")


def simple_semantic_hints(fa: FunctionAudit) -> None:
    print("Conservative semantic hints:")

    zero_defs = []
    byte_stores = []
    word_stores = []
    multi_stores = []
    backward = []

    for addr, ins in fa.visited.items():
        m = ins.mnemonic.lower()
        o = ins.op_str.lower().replace(" ", "")

        if (
            (m in {"mov", "movs"} and "#0" in o)
            or (m.startswith("eor") and "," in o)
            or (m == "sub" and len(o.split(",")) >= 3 and o.split(",")[1] == o.split(",")[2])
        ):
            zero_defs.append(addr)

        if m.startswith("strb"):
            byte_stores.append(addr)
        elif m.startswith("str") and not m.startswith("strb"):
            word_stores.append(addr)
        elif m.startswith("stm"):
            multi_stores.append(addr)

        if ins.is_jump and ins.target is not None and ins.target < addr:
            backward.append((addr, ins.target))

    print(f"  zero-producing candidates = {len(zero_defs)}")
    if zero_defs:
        print("    " + ", ".join(f"0x{x:08X}" for x in zero_defs))

    print(f"  byte stores               = {len(byte_stores)}")
    print(f"  word stores               = {len(word_stores)}")
    print(f"  multi-register stores     = {len(multi_stores)}")
    print(f"  backward branches         = {len(backward)}")

    if backward:
        for site, target in backward:
            print(f"    0x{site:08X} -> 0x{target:08X}")

    print()
    print("No automatic semantic promotion is made here.")
    print("Exact register/dataflow around the stores must be reviewed from the listing.")


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument(
        "--dump",
        default=r"C:\Users\verto\mtkclient\research\f2\data\dumps\mobiwire_dump_2.bin",
    )
    args = ap.parse_args()

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO")

    path = Path(args.dump)
    if not path.is_file():
        raise SystemExit(f"Missing canonical dump: {path}")

    data = path.read_bytes()
    digest = sha256(data)

    hdr("A. CANONICAL DUMP GUARD")
    print(f"DUMP   = {path}")
    print(f"size   = 0x{len(data):X}")
    print(f"sha256 = {digest}")
    print(f"guard  = {'PASS' if len(data) == DUMP_SIZE and digest == DUMP_SHA256 else 'FAIL'}")

    if len(data) != DUMP_SIZE or digest != DUMP_SHA256:
        raise SystemExit("ABORT: canonical dump guard failed")

    # The project ROM view is the early dump mapped at 0x10000000.
    rom_data = data[: ROM_END - ROM_BASE]
    rom = Image("PHYSICAL_ROM", rom_data, ROM_BASE)
    aud = ArmAuditor(rom)

    hdr("B. MAPPING / TARGET CHECK")
    print(f"ROM runtime base       = 0x{ROM_BASE:08X}")
    print(f"ROM runtime end        = 0x{ROM_END:08X}")
    print(f"TARGET runtime         = 0x{TARGET:08X}")
    print(f"TARGET dump offset     = 0x{TARGET - ROM_BASE:X}")
    print(f"NEIGHBOR runtime       = 0x{NEIGHBOR:08X}")
    print(f"NEIGHBOR dump offset   = 0x{NEIGHBOR - ROM_BASE:X}")
    print(f"TARGET inside ROM      = {'YES' if rom.contains(TARGET, 4) else 'NO'}")
    print(f"NEIGHBOR inside ROM    = {'YES' if rom.contains(NEIGHBOR, 4) else 'NO'}")
    print()
    print(f"Known veneer F0210588  -> 0x{TARGET:08X}")
    print(f"Known veneer F02105B8  -> 0x{NEIGHBOR:08X}")

    if not rom.contains(TARGET, 4):
        raise SystemExit("ABORT: target not in canonical ROM view")

    hdr("C. RAW ROM BYTES AROUND 0x10018998")
    raw_hex(rom, TARGET, before=0x20, after=0x100)

    hdr("D. LINEAR ARM DISASSEMBLY 0x10018998..+0x100")
    print_linear(aud, TARGET, 0x100)

    hdr("E. REACHABLE CFG FROM 0x10018998")
    fa = aud.audit_function(TARGET, max_span=0x300)
    print_cfg(aud, fa)

    hdr("F. STORE-SITE CONTEXTS FOR 0x10018998")
    print_store_context(aud, fa)

    hdr("G. CONSERVATIVE SEMANTIC HINTS FOR 0x10018998")
    simple_semantic_hints(fa)

    hdr("H. NEIGHBOR 0x100189D8")
    print_linear(aud, NEIGHBOR, 0x80)
    nfa = aud.audit_function(NEIGHBOR, max_span=0x200)
    print()
    print_cfg(aud, nfa)

    hdr("I. BITMAP CALL CONTRACT TO REVIEW AGAINST REAL ROM BODY")
    print(f"veneer                = 0x{VENEER:08X}")
    print(f"real ROM target       = 0x{TARGET:08X}")
    print(f"r0 at caller          = 0x{FILTER_BITMAP:08X}")
    print(f"r1 at caller          = (*(u32 *)0x{FILTER_BOUND:08X} >> 3) + 1")
    print()
    print("Required proof for RESET-TO-ALL-CLEAR:")
    print("  The real 0x10018998 body must show that the requested byte range")
    print("  beginning at r0 is overwritten with zero, directly or through a")
    print("  fully resolved callee whose exact effect is equivalent.")

    hdr("J. DECISION GATE")
    print("CANONICAL DUMP GUARD      : PASS")
    print(f"TARGET ARM BODY DECODED   : {'YES' if fa.visited else 'NO'}")
    print(f"TARGET REACHABLE STORES   : {len(fa.stores)}")
    print(f"TARGET DIRECT CALLS       : {len(fa.calls)}")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
