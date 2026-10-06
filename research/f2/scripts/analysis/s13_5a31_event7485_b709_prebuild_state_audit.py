#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.31 - EVENT 0x7485 / B709 PRE-REBUILD STATE AUDIT

STRICTLY OFFLINE:
- no USB/COM
- no DA upload
- no D3/D5/D6
- no write / erase
- no phone access

Purpose
-------
A.30 promoted 0x102D1066 -> 0x10313998 to a real CFG-valid caller,
owned by the Thumb function starting near 0x102D100C.  That function
runs a long initialization chain immediately before rebuilding the
filtered B709 selector-8 array.  A.31 audits that chain for:
  * SET_FILTER_BIT / CLEAR_FILTER_BIT activity
  * direct bitmap/global accesses
  * B709 / B700 / B702 / B6FF / 0x8928 / Image Viewer IDs
  * registry child-enumeration helpers
  * the final 0x1031F2E8(0) call immediately before rebuild
  * structural pointer-table evidence around 0x10365A12

The script intentionally refuses to modify any input.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    from capstone import (
        Cs,
        CS_ARCH_ARM,
        CS_MODE_ARM,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_THUMB,
        CS_GRP_CALL,
        CS_GRP_JUMP,
        CS_OP_IMM,
        CS_OP_MEM,
        CS_OP_REG,
    )
    from capstone.arm import ARM_REG_PC, ARM_REG_LR
except Exception as exc:
    raise SystemExit(
        "capstone is required in the project venv. "
        "Install/use the same venv as the previous S13.5A scripts.\n"
        f"Import error: {exc}"
    )

TITLE = "S13.5A.31 - EVENT 0x7485 / B709 PRE-REBUILD STATE AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

EVENT_OWNER = 0x102D100C
EVENT_REBUILD_CALLSITE = 0x102D1066
B709_REBUILD = 0x10313998
B709_PREP = 0x10365A12
REBUILD_WRAPPER = 0x1032F2B8
PRE_REBUILD_NOP = 0x10332B88
FINAL_PRE_REBUILD = 0x1031F2E8

SET_FILTER_VENEER = 0x102FD04C
CLEAR_FILTER_VENEER = 0x102FD054
SET_FILTER_IMPL = 0xF02D4D10
CLEAR_FILTER_IMPL = 0xF02D5828
FILTER_PREDICATE = 0xF02D5458
FILTER_BITMAP = 0xF00C1624
FILTER_BOUND = 0xF007F04C

COUNT_FILTERED_VENEER = 0x102FC51C
ENUM_FILTERED_VENEER = 0x102FC3CC
CHILD_AT_INDEX_VENEER = 0x102FBA3C
ROOT_BRANCH_VENEER = 0x102FA0CC

FOCUS_IDS = {
    0xB709: "B709",
    0xB700: "B700",
    0xB702: "B702",
    0xB6FF: "B6FF",
    0x8928: "AUDIO_8928",
    0x8313: "IMAGE_8313",
    0x8321: "IMAGE_8321",
    0xB74A: "SEL1_8321_B74A",
    0xB747: "SEL5_8321_B747",
    0x7485: "EVENT_7485",
    0x7487: "EVENT_7487",
    0x7489: "EVENT_7489",
}

FOCUS_ADDRS = {
    SET_FILTER_VENEER: "SET_FILTER_VENEER",
    CLEAR_FILTER_VENEER: "CLEAR_FILTER_VENEER",
    SET_FILTER_IMPL: "SET_FILTER_IMPL",
    CLEAR_FILTER_IMPL: "CLEAR_FILTER_IMPL",
    FILTER_PREDICATE: "FILTER_PREDICATE",
    FILTER_BITMAP: "FILTER_BITMAP",
    FILTER_BOUND: "FILTER_BOUND",
    COUNT_FILTERED_VENEER: "COUNT_FILTERED_CHILDREN_VENEER",
    ENUM_FILTERED_VENEER: "ENUM_FILTERED_CHILD_IDS_VENEER",
    CHILD_AT_INDEX_VENEER: "CHILD_ID_AT_INDEX_VENEER",
    ROOT_BRANCH_VENEER: "B709_RAW_BRANCH_INDEX_VENEER",
    B709_REBUILD: "B709_REBUILD",
    B709_PREP: "B709_PREP",
}

NEIGHBOR_CANDIDATES = [
    0x103659DC,
    0x10365A12,
    0x10365A44,
    0x10365A54,
    0x10365A68,
    0x10365AB0,
    0x10365AC4,
    0x10365AD8,
    0x10365AEC,
    0x10365B88,
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(data):
        raise IndexError(off)
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise IndexError(off)
    return struct.unpack_from("<I", data, off)[0]


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

    def off(self, addr: int) -> int:
        if not self.contains(addr):
            raise ValueError(f"{self.name}: address out of range: 0x{addr:08X}")
        return addr - self.base

    def read(self, addr: int, n: int) -> bytes:
        off = self.off(addr)
        return self.data[off:off+n]

    def read_u32(self, addr: int) -> int:
        return u32(self.data, self.off(addr))


@dataclass
class InsnInfo:
    addr: int
    size: int
    text: str
    target: Optional[int] = None
    is_call: bool = False
    is_jump: bool = False
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None


@dataclass
class FunctionAudit:
    entry: int
    image: str
    visited: Dict[int, InsnInfo] = field(default_factory=dict)
    calls: List[Tuple[int, int]] = field(default_factory=list)
    literals: List[Tuple[int, int, int]] = field(default_factory=list)  # insn, litaddr, value
    focus_hits: List[str] = field(default_factory=list)
    truncated: bool = False


class Auditor:
    def __init__(self, alice: Image, zimage: Image):
        self.images = [alice, zimage]
        self.alice = alice
        self.zimage = zimage
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True
        self.arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.arm.detail = True

    def image_for(self, addr: int) -> Optional[Image]:
        for img in self.images:
            if img.contains(addr):
                return img
        return None

    def decode_one(self, addr: int) -> Optional[InsnInfo]:
        img = self.image_for(addr)
        if not img or not img.contains(addr, 2):
            return None
        blob = img.read(addr, min(4, img.end - addr))
        decoded = list(self.thumb.disasm(blob, addr, count=1))
        if not decoded:
            return None
        insn = decoded[0]
        text = f"{insn.mnemonic:<9} {insn.op_str}".rstrip()
        target = None
        is_call = insn.group(CS_GRP_CALL)
        is_jump = insn.group(CS_GRP_JUMP)
        if (is_call or is_jump) and insn.operands:
            op0 = insn.operands[0]
            if op0.type == CS_OP_IMM:
                target = int(op0.imm) & 0xFFFFFFFF

        literal_addr = None
        literal_value = None
        # Thumb PC-relative literal LDR. Capstone exposes [pc, #disp].
        if insn.mnemonic.startswith("ldr") and len(insn.operands) >= 2:
            op = insn.operands[1]
            if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                pc = (addr + 4) & ~3
                literal_addr = (pc + int(op.mem.disp)) & 0xFFFFFFFF
                li = self.image_for(literal_addr)
                if li and li.contains(literal_addr, 4):
                    literal_value = li.read_u32(literal_addr)

        return InsnInfo(
            addr=addr,
            size=insn.size,
            text=text,
            target=target,
            is_call=bool(is_call),
            is_jump=bool(is_jump),
            literal_addr=literal_addr,
            literal_value=literal_value,
        )

    @staticmethod
    def is_conditional_branch(text: str) -> bool:
        m = text.split()[0].lower()
        if m in {"b", "b.w", "bx", "bl", "blx"}:
            return False
        return m.startswith("b") or m in {"cbz", "cbnz"}

    @staticmethod
    def is_return(text: str) -> bool:
        s = text.lower()
        if s.startswith("bx") and "lr" in s:
            return True
        if s.startswith("pop") and "pc" in s:
            return True
        if s.startswith("mov") and "pc, lr" in s:
            return True
        return False

    def audit_function(self, entry: int, max_span: int = 0x1000, max_insns: int = 2500) -> FunctionAudit:
        img = self.image_for(entry)
        out = FunctionAudit(entry=entry, image=img.name if img else "OUTSIDE")
        if not img:
            return out

        q = deque([entry & ~1])
        seen: Set[int] = set()
        while q and len(seen) < max_insns:
            addr = q.popleft()
            if addr in seen:
                continue
            if addr < entry - 4 or addr >= entry + max_span:
                out.truncated = True
                continue
            ins = self.decode_one(addr)
            if ins is None:
                continue
            seen.add(addr)
            out.visited[addr] = ins

            if ins.literal_value is not None and ins.literal_addr is not None:
                out.literals.append((addr, ins.literal_addr, ins.literal_value))

            if ins.is_call and ins.target is not None:
                out.calls.append((addr, ins.target))

            # Calls always return locally for this static walk.
            if ins.is_call:
                q.append(addr + ins.size)
                continue

            if self.is_return(ins.text):
                continue

            if ins.is_jump:
                if ins.target is not None:
                    q.append(ins.target & ~1)
                if self.is_conditional_branch(ins.text):
                    q.append(addr + ins.size)
                continue

            q.append(addr + ins.size)

        if q:
            out.truncated = True

        self.classify_focus(out)
        return out

    def resolve_arm_veneer(self, addr: int) -> Optional[int]:
        # Classic ARM import veneer:
        #   E51FF004  ldr pc, [pc, #-4]
        #   XXXXXXXX  literal target (bit0 = Thumb)
        if not self.alice.contains(addr, 8):
            return None
        w0 = self.alice.read_u32(addr)
        w1 = self.alice.read_u32(addr + 4)
        if w0 in {0xE51FF004, 0xE59FF000}:
            return w1
        # Fallback: disassemble two ARM instructions and accept a PC literal load.
        blob = self.alice.read(addr, min(12, self.alice.end - addr))
        ds = list(self.arm.disasm(blob, addr, count=2))
        if ds and ds[0].mnemonic == "ldr" and ds[0].operands:
            try:
                dst = ds[0].operands[0]
                src = ds[0].operands[1]
                if dst.type == CS_OP_REG and dst.reg == ARM_REG_PC and src.type == CS_OP_MEM and src.mem.base == ARM_REG_PC:
                    pc = addr + 8
                    lit = (pc + int(src.mem.disp)) & 0xFFFFFFFF
                    if self.alice.contains(lit, 4):
                        return self.alice.read_u32(lit)
            except Exception:
                pass
        return None

    def normalize_call_target(self, target: int) -> Tuple[int, Optional[int]]:
        direct = target & ~1
        resolved = self.resolve_arm_veneer(direct)
        if resolved is None:
            return direct, None
        return direct, resolved

    def classify_focus(self, a: FunctionAudit) -> None:
        hits = []
        for site, target in a.calls:
            direct, resolved = self.normalize_call_target(target)
            for candidate in (direct, (resolved & ~1) if resolved is not None else None):
                if candidate is None:
                    continue
                if candidate in FOCUS_ADDRS:
                    hits.append(
                        f"CALL 0x{site:08X} -> 0x{target:08X}"
                        + (f" -> veneer 0x{resolved:08X}" if resolved is not None else "")
                        + f" <{FOCUS_ADDRS[candidate]}>"
                    )
        for site, litaddr, value in a.literals:
            vv = value & ~1
            if value in FOCUS_ADDRS or vv in FOCUS_ADDRS:
                name = FOCUS_ADDRS.get(value, FOCUS_ADDRS.get(vv, "?"))
                hits.append(f"LITERAL 0x{site:08X} @0x{litaddr:08X}=0x{value:08X} <{name}>")
            if value in FOCUS_IDS:
                hits.append(f"LITERAL 0x{site:08X} @0x{litaddr:08X}=0x{value:04X} <{FOCUS_IDS[value]}>")
        out_u16 = []
        if a.visited:
            lo = min(a.visited)
            hi = max(x.addr + x.size for x in a.visited.values())
            img = self.image_for(lo)
            if img and img.contains(lo, hi - lo):
                buf = img.read(lo, hi - lo)
                for ident, name in FOCUS_IDS.items():
                    needle = struct.pack("<H", ident & 0xFFFF)
                    start = 0
                    while True:
                        p = buf.find(needle, start)
                        if p < 0:
                            break
                        out_u16.append(f"RAW_U16 0x{lo+p:08X}=0x{ident:04X} <{name}>")
                        start = p + 1
        hits.extend(out_u16)
        a.focus_hits = sorted(set(hits))

    def pointer_occurrences(self, target: int) -> List[Tuple[str, int, int]]:
        vals = {target & 0xFFFFFFFF, (target | 1) & 0xFFFFFFFF}
        out = []
        for img in self.images:
            for val in vals:
                needle = struct.pack("<I", val)
                pos = 0
                while True:
                    p = img.data.find(needle, pos)
                    if p < 0:
                        break
                    out.append((img.name, img.base + p, val))
                    pos = p + 1
        return out


def print_header(s: str) -> None:
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def fmt_call(aud: Auditor, site: int, target: int) -> str:
    direct, resolved = aud.normalize_call_target(target)
    s = f"0x{site:08X} -> 0x{target:08X}"
    if resolved is not None:
        s += f" -> [ARM veneer] 0x{resolved:08X}"
    key = direct if direct in FOCUS_ADDRS else ((resolved & ~1) if resolved is not None else None)
    if key in FOCUS_ADDRS:
        s += f" <{FOCUS_ADDRS[key]}>"
    return s


def summarize_function(aud: Auditor, a: FunctionAudit, show_instructions: bool = False) -> None:
    print(f"\nFUNCTION 0x{a.entry:08X} [{a.image}]")
    print(f"  reachable insns : {len(a.visited)}")
    print(f"  direct calls    : {len(a.calls)}")
    print(f"  literals        : {len(a.literals)}")
    print(f"  truncated       : {a.truncated}")
    if a.focus_hits:
        print("  FOCUS HITS:")
        for x in a.focus_hits:
            print(f"    {x}")
    if show_instructions:
        print("  REACHABLE CFG:")
        for addr in sorted(a.visited):
            ins = a.visited[addr]
            suffix = ""
            if ins.target is not None:
                suffix += f" ; target=0x{ins.target:08X}"
            if ins.literal_value is not None and ins.literal_addr is not None:
                suffix += f" ; literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}"
            print(f"    0x{addr:08X}: {ins.text}{suffix}")


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument(
        "--alice",
        default=r".\research\f2\work\extracted\altice_alice\alice-py.bin",
        help="Canonical decompressed ALICE",
    )
    ap.add_argument(
        "--zimage",
        default=r".\research\f2\work\extracted\altice_platform\zimage.bin",
        help="Canonical decompressed ZIMAGE",
    )
    ap.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Transitive callee depth from 0x102D100C (default: 2)",
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

    alice_path = Path(args.alice)
    zimage_path = Path(args.zimage)
    if not alice_path.is_file():
        raise SystemExit(f"Missing ALICE: {alice_path}")
    if not zimage_path.is_file():
        raise SystemExit(f"Missing ZIMAGE: {zimage_path}")

    alice_data = alice_path.read_bytes()
    zimage_data = zimage_path.read_bytes()

    print_header("A. CANONICAL INPUTS")
    ah = sha256(alice_data)
    zh = sha256(zimage_data)
    print(f"ALICE  = {alice_path}")
    print(f"  base   = 0x{ALICE_BASE:08X}")
    print(f"  size   = 0x{len(alice_data):X}")
    print(f"  sha256 = {ah}")
    print(f"  guard  = {'PASS' if len(alice_data)==ALICE_SIZE and ah==ALICE_SHA256 else 'FAIL'}")
    print(f"ZIMAGE = {zimage_path}")
    print(f"  base   = 0x{ZIMAGE_BASE:08X}")
    print(f"  size   = 0x{len(zimage_data):X}")
    print(f"  sha256 = {zh}")
    print(f"  guard  = {'PASS' if len(zimage_data)==ZIMAGE_SIZE and zh==ZIMAGE_SHA256 else 'FAIL'}")
    if len(alice_data) != ALICE_SIZE or ah != ALICE_SHA256:
        raise SystemExit("ABORT: ALICE canonical guard failed")
    if len(zimage_data) != ZIMAGE_SIZE or zh != ZIMAGE_SHA256:
        raise SystemExit("ABORT: ZIMAGE canonical guard failed")

    alice = Image("ALICE", alice_data, ALICE_BASE)
    zimage = Image("ZIMAGE", zimage_data, ZIMAGE_BASE)
    aud = Auditor(alice, zimage)

    print_header("B. EVENT 0x7485 OWNER 0x102D100C - EXACT REACHABLE CFG")
    owner = aud.audit_function(EVENT_OWNER, max_span=0x200)
    summarize_function(aud, owner, show_instructions=True)
    if EVENT_REBUILD_CALLSITE not in owner.visited:
        print("[FAIL] expected rebuild callsite 0x102D1066 is not CFG-reachable")
    else:
        ins = owner.visited[EVENT_REBUILD_CALLSITE]
        print(f"\n[PASS] 0x102D1066 reachable: {ins.text}")
        print(f"       target = 0x{(ins.target or 0):08X}")

    print_header("C. PRE-REBUILD DIRECT CALL ORDER")
    ordered_calls = sorted(owner.calls)
    pre_calls = [(s, t) for s, t in ordered_calls if s < EVENT_REBUILD_CALLSITE]
    for site, target in pre_calls:
        print("  " + fmt_call(aud, site, target))
    print(f"\npre-rebuild direct call count = {len(pre_calls)}")
    print("last direct call before rebuild:")
    if pre_calls:
        print("  " + fmt_call(aud, *pre_calls[-1]))
        if (pre_calls[-1][1] & ~1) == FINAL_PRE_REBUILD:
            print("  [PASS] exact last call is 0x1031F2E8 after r0=0 in A.30")
        else:
            print("  [WARN] last call differs from A.30 expectation")

    print_header(f"D. TRANSITIVE PRE-REBUILD CALLEE AUDIT (DEPTH <= {args.depth})")
    q = deque()
    seen: Set[int] = set()
    # Seed only calls occurring before the rebuild.
    for _, t in pre_calls:
        direct, resolved = aud.normalize_call_target(t)
        target = (resolved & ~1) if resolved is not None else direct
        if aud.image_for(target):
            q.append((target, 1))

    interesting: List[FunctionAudit] = []
    all_audits: Dict[int, FunctionAudit] = {}
    while q:
        entry, depth = q.popleft()
        entry &= ~1
        if entry in seen or depth > args.depth:
            continue
        seen.add(entry)
        fa = aud.audit_function(entry, max_span=0x1200)
        all_audits[entry] = fa
        if fa.focus_hits or entry == FINAL_PRE_REBUILD:
            interesting.append(fa)
        if depth < args.depth:
            for _, t in fa.calls:
                direct, resolved = aud.normalize_call_target(t)
                target = (resolved & ~1) if resolved is not None else direct
                if aud.image_for(target) and target not in seen:
                    q.append((target, depth + 1))

    print(f"visited functions = {len(all_audits)}")
    print(f"interesting       = {len(interesting)}")
    for fa in interesting:
        summarize_function(aud, fa, show_instructions=(fa.entry == FINAL_PRE_REBUILD))

    print_header("E. EXPLICIT FILTER / REGISTRY EFFECT CENSUS")
    effect_rows = []
    for entry, fa in sorted(all_audits.items()):
        tags = []
        for site, t in fa.calls:
            direct, resolved = aud.normalize_call_target(t)
            normalized = {(direct & ~1)}
            if resolved is not None:
                normalized.add(resolved & ~1)
            if SET_FILTER_VENEER in normalized or SET_FILTER_IMPL in normalized:
                tags.append(f"SET_FILTER@0x{site:08X}")
            if CLEAR_FILTER_VENEER in normalized or CLEAR_FILTER_IMPL in normalized:
                tags.append(f"CLEAR_FILTER@0x{site:08X}")
            if COUNT_FILTERED_VENEER in normalized:
                tags.append(f"COUNT_FILTERED@0x{site:08X}")
            if ENUM_FILTERED_VENEER in normalized:
                tags.append(f"ENUM_FILTERED@0x{site:08X}")
            if CHILD_AT_INDEX_VENEER in normalized:
                tags.append(f"CHILD_AT_INDEX@0x{site:08X}")
            if ROOT_BRANCH_VENEER in normalized:
                tags.append(f"ROOT_BRANCH_INDEX@0x{site:08X}")
        for site, litaddr, value in fa.literals:
            if value == FILTER_BITMAP:
                tags.append(f"BITMAP_LITERAL@0x{site:08X}")
            if value == FILTER_BOUND:
                tags.append(f"FILTER_BOUND_LITERAL@0x{site:08X}")
            if value in FOCUS_IDS:
                tags.append(f"{FOCUS_IDS[value]}_LITERAL@0x{site:08X}")
        if tags:
            effect_rows.append((entry, sorted(set(tags))))
    if not effect_rows:
        print("<none within audited transitive depth>")
    for entry, tags in effect_rows:
        print(f"0x{entry:08X}:")
        for tag in tags:
            print(f"  - {tag}")

    print_header("F. FINAL PRE-REBUILD 0x1031F2E8")
    final = all_audits.get(FINAL_PRE_REBUILD) or aud.audit_function(FINAL_PRE_REBUILD, max_span=0x1200)
    summarize_function(aud, final, show_instructions=True)

    print_header("G. 0x10365A12 NEIGHBORHOOD STRUCTURAL POINTER TOPOLOGY")
    for c in NEIGHBOR_CANDIDATES:
        occ = aud.pointer_occurrences(c)
        print(f"\n0x{c:08X}: pointer/body occurrences={len(occ)}")
        for img_name, addr, value in occ:
            print(f"  {img_name} 0x{addr:08X} -> 0x{value:08X}")
            img = alice if img_name == "ALICE" else zimage
            lo = max(img.base, addr - 0x20)
            hi = min(img.end, addr + 0x24)
            words = []
            p = lo & ~3
            while p + 4 <= hi:
                try:
                    w = img.read_u32(p)
                except Exception:
                    break
                marker = " <PTR>" if p == addr else ""
                # Annotate function-like pointers into ALICE/ZIMAGE.
                target_img = aud.image_for(w & ~1)
                ann = f" -> {target_img.name}" if target_img else ""
                words.append(f"    0x{p:08X}: 0x{w:08X}{marker}{ann}")
                p += 4
            print("\n".join(words))

    print_header("H. DECISION GATE")
    any_filter_effect = any(
        any("FILTER" in tag or "BITMAP" in tag for tag in tags)
        for _, tags in effect_rows
    )
    final_filter_effect = any(
        "FILTER" in hit or "BITMAP" in hit
        for hit in final.focus_hits
    )
    print("A.30 retained facts:")
    print("  - 0x102D1066 -> 0x10313998 is CFG-valid inside owner 0x102D100C.")
    print("  - 0x10332B88 is a no-op bx lr.")
    print("  - 0x10365A12 CLEARs B700/B702/B6FF then rebuilds B709.")
    print()
    print(f"pre-rebuild transitive filter/bitmap evidence = {'FOUND' if any_filter_effect else 'NOT FOUND'}")
    print(f"final 0x1031F2E8 filter/bitmap evidence        = {'FOUND' if final_filter_effect else 'NOT FOUND'}")
    print()
    print("Promotion rule:")
    print("  Do NOT authorize a menu flash from this audit alone.")
    print("  A physical candidate requires exact logical mutation + exact repack footprint +")
    print("  fresh D6 baseline + rollback + post-write D6 verification.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
