#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.35 - BOOT_ZIMAGE F0210588 EXACT BODY AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no D3 / D5 / D6
- no write / erase
- no phone access

Purpose
-------
A.34 established that the decompressed ZIMAGE cannot be mapped into the
physical dump by raw byte translation. Repository runtime layout proves:

    BOOT_ZIMAGE base = 0xF01F19E4
    BOOT_ZIMAGE size = 0x0004B06C
    BOOT_ZIMAGE end  = 0xF023CA50
    ZIMAGE base      = 0xF023CA50

Therefore F0210588 is inside BOOT_ZIMAGE at offset 0x1EBA4.

This audit reads the canonical BOOT_ZIMAGE directly and prints the exact
reachable Thumb body of:
    F0210588  target used by the filter-bitmap initializer
    F02105B8  nearby helper observed with pointer/length arguments
    F02105C8  known compiler switch helper

It also prints the exact caller context at F02EE338 from canonical ZIMAGE
and a compact incoming-call census across BOOT_ZIMAGE + ZIMAGE.

No patch is generated and no hardware mutation is authorized.
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
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_THUMB,
        CS_GRP_CALL,
        CS_GRP_JUMP,
        CS_OP_IMM,
        CS_OP_MEM,
    )
    from capstone.arm import ARM_REG_PC
except Exception as exc:
    raise SystemExit(
        "capstone is required in the project venv.\n"
        r"Use C:\Users\verto\mtkclient\.venv\Scripts\python.exe" "\n"
        f"Import error: {exc}"
    )

TITLE = "S13.5A.35 - BOOT_ZIMAGE F0210588 EXACT BODY AUDIT"

BOOT_BASE = 0xF01F19E4
BOOT_SIZE = 0x4B06C
BOOT_SHA256 = "aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e"
BOOT_END = BOOT_BASE + BOOT_SIZE

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

TARGET = 0xF0210588
NEIGHBOR = 0xF02105B8
SWITCH_HELPER = 0xF02105C8

FILTER_BITMAP = 0xF00C1624
FILTER_BOUND = 0xF007F04C
BITMAP_INIT = 0xF02EE32C
BITMAP_CALLSITE = 0xF02EE338


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
        off = addr - self.base
        return self.data[off:off+n]

    def read_u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.data, addr - self.base)[0]


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
        return f"{self.mnemonic:<9} {self.op_str}".rstrip()


@dataclass
class Function:
    entry: int
    image: str
    insns: Dict[int, Insn] = field(default_factory=dict)
    calls: List[Tuple[int, int]] = field(default_factory=list)
    stores: List[int] = field(default_factory=list)
    truncated: bool = False


class Auditor:
    def __init__(self, boot: Image, zimage: Image):
        self.boot = boot
        self.zimage = zimage
        self.images = [boot, zimage]
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def image_for(self, addr: int) -> Optional[Image]:
        a = addr & ~1
        for img in self.images:
            if img.contains(a):
                return img
        return None

    def decode_one(self, addr: int) -> Optional[Insn]:
        addr &= ~1
        img = self.image_for(addr)
        if not img or not img.contains(addr, 2):
            return None

        blob = img.read(addr, min(4, img.end - addr))
        ds = list(self.md.disasm(blob, addr, count=1))
        if not ds:
            return None

        ci = ds[0]
        is_call = bool(ci.group(CS_GRP_CALL))
        is_jump = bool(ci.group(CS_GRP_JUMP))
        target = None
        if (is_call or is_jump) and ci.operands:
            if ci.operands[0].type == CS_OP_IMM:
                target = int(ci.operands[0].imm) & 0xFFFFFFFF

        literal_addr = None
        literal_value = None
        if ci.mnemonic.startswith("ldr") and len(ci.operands) >= 2:
            op = ci.operands[1]
            if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                pc = (addr + 4) & ~3
                literal_addr = (pc + int(op.mem.disp)) & 0xFFFFFFFF
                li = self.image_for(literal_addr)
                if li and li.contains(literal_addr, 4):
                    literal_value = li.read_u32(literal_addr)

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
        o = ins.op_str.lower()
        if m == "bx" and "lr" in o:
            return True
        if m == "pop" and "pc" in o:
            return True
        if m.startswith("mov") and "pc" in o and "lr" in o:
            return True
        return False

    @staticmethod
    def is_unconditional_branch(ins: Insn) -> bool:
        return ins.mnemonic.lower() in {"b", "b.w", "bx"}

    def function(self, entry: int, max_span: int = 0x180, max_insns: int = 500) -> Function:
        entry &= ~1
        img = self.image_for(entry)
        out = Function(entry=entry, image=img.name if img else "OUTSIDE")
        if not img:
            return out

        q = deque([entry])
        seen: Set[int] = set()

        while q and len(seen) < max_insns:
            a = q.popleft() & ~1
            if a in seen:
                continue
            if a < entry or a >= entry + max_span:
                out.truncated = True
                continue

            ins = self.decode_one(a)
            if not ins:
                continue

            seen.add(a)
            out.insns[a] = ins

            if ins.mnemonic.lower().startswith(("str", "stm")):
                out.stores.append(a)

            if ins.is_call and ins.target is not None:
                out.calls.append((a, ins.target))
                q.append(a + ins.size)
                continue

            if self.is_return(ins):
                continue

            if ins.is_jump:
                if ins.target is not None:
                    q.append(ins.target & ~1)
                if not self.is_unconditional_branch(ins):
                    q.append(a + ins.size)
                continue

            q.append(a + ins.size)

        if q:
            out.truncated = True
        return out

    def scan_calls_to(self, target: int) -> List[Tuple[str, int]]:
        target &= ~1
        hits: List[Tuple[str, int]] = []

        for img in self.images:
            a = img.base & ~1
            end = img.end - 4
            while a <= end:
                ins = self.decode_one(a)
                if ins and ins.is_call and ins.target is not None:
                    if (ins.target & ~1) == target:
                        hits.append((img.name, a))
                a += 2

        return sorted(set(hits), key=lambda x: (x[0], x[1]))


def hdr(title: str) -> None:
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def raw_hex(img: Image, addr: int, before: int = 0x10, after: int = 0x60) -> None:
    lo = max(img.base, addr - before)
    hi = min(img.end, addr + after)
    data = img.read(lo, hi - lo)

    for off in range(0, len(data), 16):
        chunk = data[off:off+16]
        print(f"  0x{lo+off:08X}: " + " ".join(f"{b:02X}" for b in chunk))


def print_function(aud: Auditor, entry: int, name: str) -> Function:
    fa = aud.function(entry)

    print()
    print(f"{name} 0x{entry:08X} [{fa.image}]")
    print(f"  file offset      = 0x{entry - BOOT_BASE:X}" if fa.image == "BOOT_ZIMAGE" else "")
    print(f"  reachable insns  = {len(fa.insns)}")
    print(f"  direct calls     = {len(fa.calls)}")
    print(f"  store insns      = {len(fa.stores)}")
    print(f"  truncated        = {fa.truncated}")

    for addr in sorted(fa.insns):
        ins = fa.insns[addr]
        ann = []

        if ins.target is not None:
            ann.append(f"target=0x{ins.target:08X}")

        if ins.literal_addr is not None and ins.literal_value is not None:
            ann.append(
                f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}"
            )

        if addr in fa.stores:
            ann.append("STORE")

        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"    0x{addr:08X}: {ins.text}{suffix}")

    return fa


def print_context(aud: Auditor, site: int, before: int = 0x18, after: int = 0x0C) -> None:
    img = aud.image_for(site)
    if not img:
        print("  <outside loaded images>")
        return

    lo = max(img.base, (site - before) & ~1)
    hi = min(img.end, site + after)
    a = lo

    while a < hi:
        ins = aud.decode_one(a)
        if not ins:
            a += 2
            continue

        mark = ">>>" if a == (site & ~1) else "   "
        ann = []
        if ins.target is not None:
            ann.append(f"target=0x{ins.target:08X}")
        if ins.literal_addr is not None and ins.literal_value is not None:
            extra = ""
            if ins.literal_value == FILTER_BITMAP:
                extra = " FILTER_BITMAP"
            if ins.literal_value == FILTER_BOUND:
                extra = " FILTER_BOUND"
            ann.append(
                f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}{extra}"
            )

        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"{mark} 0x{a:08X}: {ins.text}{suffix}")
        a += ins.size


def classify_target(fa: Function) -> None:
    print()
    print("Structural classification hints:")

    mnems = [x.mnemonic.lower() for x in fa.insns.values()]
    texts = [x.op_str.lower().replace(" ", "") for x in fa.insns.values()]

    has_store = bool(fa.stores)
    has_loop_back = any(
        ins.is_jump and ins.target is not None and (ins.target & ~1) < ins.addr
        for ins in fa.insns.values()
    )
    zero_defs = [
        ins.addr
        for ins in fa.insns.values()
        if ins.mnemonic.lower() in {"mov", "movs", "eor", "eors"}
        and (
            "#0" in ins.op_str.lower()
            or (
                ins.mnemonic.lower().startswith("eor")
                and len(ins.op_str.split(",")) >= 2
            )
        )
    ]

    print(f"  contains memory store(s) = {'YES' if has_store else 'NO'}")
    print(f"  contains backward loop   = {'YES' if has_loop_back else 'NO'}")
    print(f"  zero-producing insns     = {len(zero_defs)}")
    if zero_defs:
        print("    " + ", ".join(f"0x{x:08X}" for x in zero_defs))

    # Conservative only: do not auto-promote exact memset semantics.
    if has_store and has_loop_back and zero_defs:
        print("  structural shape         = CONSISTENT WITH zero-fill/memclear loop")
    elif has_store and has_loop_back:
        print("  structural shape         = CONSISTENT WITH memory fill/copy loop")
    elif has_store:
        print("  structural shape         = WRITES MEMORY; exact operation needs instruction review")
    else:
        print("  structural shape         = NO DIRECT STORE in decoded CFG")

    print("  IMPORTANT: final semantic promotion must follow exact instruction/dataflow review.")


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument(
        "--boot",
        default=r".\research\f2\work\extracted\altice_platform\boot_zimage.bin",
    )
    ap.add_argument(
        "--zimage",
        default=r".\research\f2\work\extracted\altice_platform\zimage.bin",
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

    bpath = Path(args.boot)
    zpath = Path(args.zimage)

    if not bpath.is_file():
        raise SystemExit(f"Missing BOOT_ZIMAGE: {bpath}")
    if not zpath.is_file():
        raise SystemExit(f"Missing ZIMAGE: {zpath}")

    bd = bpath.read_bytes()
    zd = zpath.read_bytes()

    hdr("A. CANONICAL IMAGE GUARDS")

    bh = sha256(bd)
    zh = sha256(zd)
    bg = len(bd) == BOOT_SIZE and bh == BOOT_SHA256
    zg = len(zd) == ZIMAGE_SIZE and zh == ZIMAGE_SHA256

    print(f"BOOT_ZIMAGE = {bpath}")
    print(f"  base   = 0x{BOOT_BASE:08X}")
    print(f"  size   = 0x{len(bd):X}")
    print(f"  end    = 0x{BOOT_BASE + len(bd):08X}")
    print(f"  sha256 = {bh}")
    print(f"  guard  = {'PASS' if bg else 'FAIL'}")

    print(f"ZIMAGE      = {zpath}")
    print(f"  base   = 0x{ZIMAGE_BASE:08X}")
    print(f"  size   = 0x{len(zd):X}")
    print(f"  sha256 = {zh}")
    print(f"  guard  = {'PASS' if zg else 'FAIL'}")

    print()
    print(f"BOOT_ZIMAGE expected end == ZIMAGE base : {'PASS' if BOOT_END == ZIMAGE_BASE else 'FAIL'}")
    print(f"actual BOOT end == ZIMAGE base         : {'PASS' if BOOT_BASE + len(bd) == ZIMAGE_BASE else 'FAIL'}")
    print(f"F0210588 BOOT offset                   : 0x{TARGET - BOOT_BASE:X}")

    if not bg:
        raise SystemExit("ABORT: canonical BOOT_ZIMAGE guard failed")
    if not zg:
        raise SystemExit("ABORT: canonical ZIMAGE guard failed")
    if not (BOOT_BASE <= TARGET < BOOT_END):
        raise SystemExit("ABORT: F0210588 is not inside guarded BOOT_ZIMAGE")

    boot = Image("BOOT_ZIMAGE", bd, BOOT_BASE)
    zimage = Image("ZIMAGE", zd, ZIMAGE_BASE)
    aud = Auditor(boot, zimage)

    hdr("B. RAW BYTES AROUND TARGET")
    raw_hex(boot, TARGET, before=0x20, after=0x80)

    hdr("C. EXACT F0210588 REACHABLE BODY")
    target_fa = print_function(aud, TARGET, "TARGET")
    classify_target(target_fa)

    hdr("D. NEARBY F02105B8 REACHABLE BODY")
    print_function(aud, NEIGHBOR, "NEIGHBOR")

    hdr("E. KNOWN SWITCH HELPER F02105C8")
    print_function(aud, SWITCH_HELPER, "SWITCH_HELPER")

    hdr("F. EXACT BITMAP INITIALIZER CALLSITE IN ZIMAGE")
    print(f"initializer = 0x{BITMAP_INIT:08X}")
    print(f"callsite    = 0x{BITMAP_CALLSITE:08X}")
    print(f"target      = 0x{TARGET:08X}")
    print(f"r0 expected = 0x{FILTER_BITMAP:08X}")
    print(f"r1 expected = (*(u32 *)0x{FILTER_BOUND:08X} >> 3) + 1")
    print_context(aud, BITMAP_CALLSITE, before=0x18, after=0x0C)

    hdr("G. INCOMING DIRECT CALLS TO F0210588 ACROSS BOOT_ZIMAGE + ZIMAGE")
    hits = aud.scan_calls_to(TARGET)
    print(f"direct decoded calls = {len(hits)}")
    for img_name, site in hits:
        print(f"  {img_name}: 0x{site:08X}")
        if site == BITMAP_CALLSITE:
            print("    <KNOWN FILTER BITMAP INITIALIZER CALL>")

    hdr("H. DECISION GATE")
    print(f"BOOT_ZIMAGE guard               = {'PASS' if bg else 'FAIL'}")
    print(f"BOOT end == ZIMAGE base         = {'PASS' if BOOT_BASE + len(bd) == ZIMAGE_BASE else 'FAIL'}")
    print(f"F0210588 decoded from real body = {'YES' if len(target_fa.insns) else 'NO'}")
    print(f"F0210588 direct store count     = {len(target_fa.stores)}")
    print()
    print("Promotion rule:")
    print("  Review the exact F0210588 instructions printed above.")
    print("  Promote RESET-TO-ALL-CLEAR only if the real body proves that r1 bytes")
    print("  beginning at r0 are written with zero (or an equivalent exact effect).")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
