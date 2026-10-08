#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.39 - REGISTRY RECORD MUTATOR / B709 BUILDER AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no D3 / D5 / D6
- no write / erase
- no phone access

Background
----------
A.38 closes the B709 filter-index problem for the proven static model.
The remaining logical blocker is the runtime registry behind:

    F007F044 = registry base pointer
    F007F048 = neighboring registry global
    F007F04C = dense-ID bound

Known readers:
    F02E01B0(id)      -> dense registry index
    F02FBC24(id)      -> GET_PARENT_ID(id)
    F02D8178(parent,i)-> CHILD_ID_AT_INDEX(parent,i)

Known registry-record facts:
    stride = 0x10
    record +0x00 participates in parent lookup
    record +0x0C is the raw child-array pointer

A.39 does NOT guess the runtime registry contents.
Instead it identifies static functions that are plausible registry RECORD
MUTATORS by combining:
  - exact PC-relative xrefs to F007F044/F048/F04C;
  - calls to F02E01B0;
  - reachable memory stores in the same owner function;
  - direct caller census for each mutator candidate;
  - conservative constant-argument recovery at callers;
  - focused ID evidence for B709, B700..B708, 8313, 8321, 8928;
  - comparison with known generic child-registration framework APIs.

Goal:
Find the code that actually constructs/updates children[B709], or reduce the
search to a small set of concrete mutator candidates.

No patch is generated.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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
    from capstone.arm import ARM_REG_PC
except Exception as exc:
    raise SystemExit(
        "capstone is required in the project venv.\n"
        r"Use C:\Users\verto\mtkclient\.venv\Scripts\python.exe" "\n"
        f"Import error: {exc}"
    )

TITLE = "S13.5A.39 - REGISTRY RECORD MUTATOR / B709 BUILDER AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

BOOT_BASE = 0xF01F19E4
BOOT_SIZE = 0x4B06C
BOOT_SHA256 = "aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

DUMP_SIZE = 0x400000
DUMP_SHA256 = "2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922"
ROM_BASE = 0x10000000
ROM_END = 0x1004C20C

REG_BASE_GLOBAL = 0xF007F044
REG_AUX_GLOBAL = 0xF007F048
REG_BOUND_GLOBAL = 0xF007F04C

ID_TO_DENSE = 0xF02E01B0
GET_PARENT_ID = 0xF02FBC24
CHILD_AT_INDEX = 0xF02D8178
INDEX_TO_ID = 0xF02FEFB4

# Generic registration framework APIs from prior work. They may be a different
# registry; included only as comparison / cross-reference, never assumed equal.
GENERIC_ADD_CHILD = 0xF02EE14C
GENERIC_ADD_CHILD_WRAPPER = 0xF02E72F0
GENERIC_NODE_CREATE = 0xF02F1E44
GENERIC_TYPE0_CREATE = 0xF02F0AB8

FOCUS_IDS = {
    0xB709: "B709_ROOT",
    0xB700: "B700",
    0xB701: "B701",
    0xB702: "B702",
    0xB703: "B703",
    0xB704: "B704",
    0xB705: "B705",
    0xB706: "B706",
    0xB707: "B707",
    0xB708: "B708",
    0x8313: "IMAGE_8313",
    0x8321: "IMAGE_8321",
    0x8928: "AUDIO_8928",
}

MODE_THUMB = "THUMB"
MODE_ARM = "ARM"


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
        return struct.unpack_from("<I", self.read(addr, 4))[0]


@dataclass
class Insn:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    mode: str
    target: Optional[int] = None
    target_mode: Optional[str] = None
    is_call: bool = False
    is_jump: bool = False
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None

    @property
    def text(self) -> str:
        return f"{self.mnemonic:<9} {self.op_str}".rstrip()


@dataclass
class FunctionAudit:
    entry: int
    mode: str
    image: str
    visited: Dict[int, Insn] = field(default_factory=dict)
    calls: List[Tuple[int, int, str]] = field(default_factory=list)
    stores: List[int] = field(default_factory=list)
    truncated: bool = False


class Auditor:
    def __init__(self, images: List[Image]):
        self.images = images
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True
        self.arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.arm.detail = True

    def image_for(self, addr: int) -> Optional[Image]:
        a = addr & ~1
        for img in self.images:
            if img.contains(a):
                return img
        return None

    def raw_arm_veneer_target(self, addr: int) -> Optional[int]:
        addr &= ~3
        img = self.image_for(addr)
        if not img or not img.contains(addr, 8):
            return None
        w0 = img.read_u32(addr)
        if w0 == 0xE51FF004:
            return img.read_u32(addr + 4)
        if w0 == 0xE59FF000 and img.contains(addr + 8, 4):
            return img.read_u32(addr + 8)
        return None

    def decode_one(self, addr: int, mode: str) -> Optional[Insn]:
        addr = addr & (~1 if mode == MODE_THUMB else ~3)
        img = self.image_for(addr)
        if not img:
            return None

        width = min(4, img.end - addr)
        if width < 2:
            return None

        md = self.thumb if mode == MODE_THUMB else self.arm
        ds = list(md.disasm(img.read(addr, width), addr, count=1))
        if not ds:
            return None
        ci = ds[0]

        is_call = bool(ci.group(CS_GRP_CALL))
        is_jump = bool(ci.group(CS_GRP_JUMP))
        target = None
        target_mode = None

        if (is_call or is_jump) and ci.operands:
            op0 = ci.operands[0]
            if op0.type == CS_OP_IMM:
                target = int(op0.imm) & 0xFFFFFFFF
                m = ci.mnemonic.lower()
                if mode == MODE_THUMB:
                    target_mode = MODE_ARM if m.startswith("blx") else MODE_THUMB
                else:
                    target_mode = MODE_THUMB if m.startswith("blx") else MODE_ARM

        literal_addr = None
        literal_value = None
        if ci.mnemonic.lower().startswith("ldr") and len(ci.operands) >= 2:
            op = ci.operands[1]
            if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                pc = ((addr + 4) & ~3) if mode == MODE_THUMB else (addr + 8)
                literal_addr = (pc + int(op.mem.disp)) & 0xFFFFFFFF
                li = self.image_for(literal_addr)
                if li and li.contains(literal_addr, 4):
                    literal_value = li.read_u32(literal_addr)

        return Insn(
            addr=addr,
            size=ci.size,
            mnemonic=ci.mnemonic,
            op_str=ci.op_str,
            mode=mode,
            target=target,
            target_mode=target_mode,
            is_call=is_call,
            is_jump=is_jump,
            literal_addr=literal_addr,
            literal_value=literal_value,
        )

    def normalize_target(self, target: int, mode: str) -> Tuple[int, str, Optional[int]]:
        t = target & (~1 if mode == MODE_THUMB else ~3)
        vt = self.raw_arm_veneer_target(t)
        if vt is not None:
            vm = MODE_THUMB if (vt & 1) else MODE_ARM
            return vt & (~1 if vm == MODE_THUMB else ~3), vm, t
        return t, mode, None

    @staticmethod
    def is_return(ins: Insn) -> bool:
        m = ins.mnemonic.lower()
        o = ins.op_str.lower().replace(" ", "")
        if m.startswith("bx") and not m.startswith("blx") and o == "lr":
            return True
        if m == "pop" and "pc" in o:
            return True
        if m.startswith("ldm") and "pc" in o:
            return True
        if m == "mov" and o == "pc,lr":
            return True
        return False

    @staticmethod
    def is_unconditional_branch(ins: Insn) -> bool:
        m = ins.mnemonic.lower()
        if ins.mode == MODE_THUMB:
            return m in {"b", "b.w", "bx"}
        return m in {"b", "bx"}

    @staticmethod
    def is_store(ins: Insn) -> bool:
        m = ins.mnemonic.lower()
        return m.startswith("str") or m.startswith("stm")

    def audit_function(
        self,
        entry: int,
        mode: str,
        max_span: int = 0x1000,
        max_insns: int = 3000,
    ) -> FunctionAudit:
        entry = entry & (~1 if mode == MODE_THUMB else ~3)
        img = self.image_for(entry)
        out = FunctionAudit(entry=entry, mode=mode, image=img.name if img else "OUTSIDE")
        if not img:
            return out

        lo = entry
        hi = min(img.end, entry + max_span)
        q = deque([entry])
        seen: Set[int] = set()

        while q and len(seen) < max_insns:
            addr = q.popleft()
            addr &= (~1 if mode == MODE_THUMB else ~3)

            if addr in seen:
                continue
            if addr < lo or addr >= hi:
                out.truncated = True
                continue

            ins = self.decode_one(addr, mode)
            if ins is None:
                continue

            seen.add(addr)
            out.visited[addr] = ins

            if self.is_store(ins):
                out.stores.append(addr)

            if ins.is_call:
                if ins.target is not None and ins.target_mode is not None:
                    eff, emode, _ = self.normalize_target(ins.target, ins.target_mode)
                    out.calls.append((addr, eff, emode))
                q.append(addr + ins.size)
                continue

            if self.is_return(ins):
                continue

            if ins.is_jump:
                if ins.target is not None and ins.target_mode is not None:
                    eff, emode, _ = self.normalize_target(ins.target, ins.target_mode)
                    if emode == mode and lo <= eff < hi:
                        q.append(eff)
                if not self.is_unconditional_branch(ins):
                    q.append(addr + ins.size)
                continue

            q.append(addr + ins.size)

        if q:
            out.truncated = True
        return out

    def plausible_function_start(self, site: int, mode: str, back: int = 0x180) -> int:
        img = self.image_for(site)
        if not img:
            return site & (~1 if mode == MODE_THUMB else ~3)

        align = 2 if mode == MODE_THUMB else 4
        lo = max(img.base, site - back)
        lo -= lo % align
        best = None

        for a in range(lo, site + 1, align):
            ins = self.decode_one(a, mode)
            if not ins:
                continue
            m = ins.mnemonic.lower()
            o = ins.op_str.lower()
            if mode == MODE_THUMB:
                if m == "push" and "lr" in o:
                    best = a
            else:
                if (m.startswith("stm") or m == "push") and ("lr" in o or "sp" in o):
                    best = a

        return best if best is not None else (site & (~1 if mode == MODE_THUMB else ~3))

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str, int, str, int]]:
        out = []
        for img in self.images:
            # Thumb halfword sweep.
            a = img.base & ~1
            while a + 2 <= img.end:
                ins = self.decode_one(a, MODE_THUMB)
                if ins and ins.literal_value == value:
                    out.append((img.name, a, MODE_THUMB, ins.literal_addr or 0))
                a += 2

            # ARM aligned sweep, useful for ROM / import veneers.
            a = (img.base + 3) & ~3
            while a + 4 <= img.end:
                ins = self.decode_one(a, MODE_ARM)
                if ins and ins.literal_value == value:
                    out.append((img.name, a, MODE_ARM, ins.literal_addr or 0))
                a += 4

        return sorted(set(out), key=lambda x: (x[0], x[1], x[2]))

    def scan_calls_to(self, target: int) -> List[Tuple[str, int, str, int, str, Optional[int]]]:
        """
        Returns image, callsite, caller_mode, effective_target, effective_mode, veneer
        """
        hits = []
        for img in self.images:
            # Thumb calls.
            a = img.base & ~1
            while a + 4 <= img.end:
                ins = self.decode_one(a, MODE_THUMB)
                if ins and ins.is_call and ins.target is not None and ins.target_mode is not None:
                    eff, emode, veneer = self.normalize_target(ins.target, ins.target_mode)
                    if eff == (target & ~1):
                        hits.append((img.name, a, MODE_THUMB, eff, emode, veneer))
                a += 2

            # ARM calls.
            a = (img.base + 3) & ~3
            while a + 4 <= img.end:
                ins = self.decode_one(a, MODE_ARM)
                if ins and ins.is_call and ins.target is not None and ins.target_mode is not None:
                    eff, emode, veneer = self.normalize_target(ins.target, ins.target_mode)
                    if eff == (target & ~1):
                        hits.append((img.name, a, MODE_ARM, eff, emode, veneer))
                a += 4

        return sorted(set(hits), key=lambda x: (x[0], x[1], x[2]))

    def local_constant_for_reg(
        self,
        callsite: int,
        mode: str,
        reg_name: str,
        back: int = 0x40,
    ) -> Optional[Tuple[int, int, str]]:
        """
        Conservative straight-line backward constant recovery for r0..r3.
        Supports:
          ldr Rx, [pc,#] literal
          mov/movs Rx,#imm
          movw + movt pair
          simple add/sub immediate from same register
        Stops at control transfer or unknown write to the requested register.
        """
        img = self.image_for(callsite)
        if not img:
            return None

        reg_name = reg_name.lower()
        align = 2 if mode == MODE_THUMB else 4
        lo = max(img.base, callsite - back)
        lo -= lo % align

        insns = []
        a = lo
        while a < callsite:
            ins = self.decode_one(a, mode)
            if ins:
                insns.append(ins)
                a += ins.size if mode == MODE_THUMB else 4
            else:
                a += align

        pending_hi = None

        for ins in reversed(insns):
            if ins.is_call or ins.is_jump:
                break

            d = ins.op_str.lower().replace(" ", "")
            if not d.startswith(reg_name + ","):
                continue

            m = ins.mnemonic.lower()

            if m.startswith("ldr") and ins.literal_value is not None:
                return ins.literal_value & 0xFFFFFFFF, ins.addr, "PC_LITERAL"

            mm = re.match(re.escape(reg_name) + r",#(0x[0-9a-f]+|\d+)$", d)
            if m in {"mov", "movs", "mov.w", "movw"} and mm:
                val = int(mm.group(1), 0) & 0xFFFFFFFF
                if m == "movw" and pending_hi is not None:
                    val |= pending_hi << 16
                    return val, ins.addr, "MOVW_MOVT"
                return val, ins.addr, m.upper()

            if m == "movt":
                mm2 = re.match(re.escape(reg_name) + r",#(0x[0-9a-f]+|\d+)$", d)
                if mm2:
                    pending_hi = int(mm2.group(1), 0) & 0xFFFF
                    continue

            # Unknown local writer to requested register.
            return None

        return None


def hdr(title: str) -> None:
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def load_guard(path: Path, size: int, expected_sha: str, name: str) -> bytes:
    if not path.is_file():
        raise SystemExit(f"Missing {name}: {path}")
    data = path.read_bytes()
    digest = sha256(data)
    ok = len(data) == size and digest == expected_sha
    print(f"{name} = {path}")
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {digest}")
    print(f"  guard  = {'PASS' if ok else 'FAIL'}")
    if not ok:
        raise SystemExit(f"ABORT: canonical {name} guard failed")
    return data


def print_context(aud: Auditor, site: int, mode: str, before: int = 0x20, after: int = 0x20) -> None:
    img = aud.image_for(site)
    if not img:
        return

    align = 2 if mode == MODE_THUMB else 4
    lo = max(img.base, site - before)
    lo -= lo % align
    hi = min(img.end, site + after)
    a = lo

    while a < hi:
        ins = aud.decode_one(a, mode)
        if not ins:
            a += align
            continue

        mark = ">>>" if a == site else "   "
        ann = []
        if ins.target is not None and ins.target_mode is not None:
            eff, emode, veneer = aud.normalize_target(ins.target, ins.target_mode)
            s = f"effective=0x{eff:08X}[{emode}]"
            if veneer is not None:
                s += f" via_veneer=0x{veneer:08X}"
            ann.append(s)

        if ins.literal_addr is not None and ins.literal_value is not None:
            extra = ""
            if ins.literal_value in FOCUS_IDS:
                extra = " " + FOCUS_IDS[ins.literal_value]
            if ins.literal_value in {REG_BASE_GLOBAL, REG_AUX_GLOBAL, REG_BOUND_GLOBAL}:
                extra = " REGISTRY_GLOBAL"
            ann.append(
                f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}{extra}"
            )

        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"{mark} 0x{a:08X}: {ins.text}{suffix}")
        a += ins.size if mode == MODE_THUMB else 4


def u16_occurrences(images: List[Image], value: int) -> List[Tuple[str, int]]:
    needle = struct.pack("<H", value & 0xFFFF)
    out = []
    for img in images:
        start = 0
        while True:
            off = img.data.find(needle, start)
            if off < 0:
                break
            out.append((img.name, img.base + off))
            start = off + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument(
        "--alice",
        default=r".\research\f2\work\extracted\altice_alice\alice-py.bin",
    )
    ap.add_argument(
        "--boot",
        default=r"C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin",
    )
    ap.add_argument(
        "--zimage",
        default=r".\research\f2\work\extracted\altice_platform\zimage.bin",
    )
    ap.add_argument(
        "--dump",
        default=r"C:\Users\verto\mtkclient\research\f2\data\dumps\mobiwire_dump_2.bin",
    )
    ap.add_argument("--max-candidates", type=int, default=80)
    ap.add_argument("--max-callers", type=int, default=80)
    args = ap.parse_args()

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO")

    hdr("A. CANONICAL INPUT GUARDS")
    ad = load_guard(Path(args.alice), ALICE_SIZE, ALICE_SHA256, "ALICE")
    bd = load_guard(Path(args.boot), BOOT_SIZE, BOOT_SHA256, "BOOT_ZIMAGE")
    zd = load_guard(Path(args.zimage), ZIMAGE_SIZE, ZIMAGE_SHA256, "ZIMAGE")
    dd = load_guard(Path(args.dump), DUMP_SIZE, DUMP_SHA256, "DUMP")

    images = [
        Image("ALICE", ad, ALICE_BASE),
        Image("BOOT_ZIMAGE", bd, BOOT_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
        Image("PHYSICAL_ROM", dd[:ROM_END - ROM_BASE], ROM_BASE),
    ]
    aud = Auditor(images)

    hdr("B. EXACT REGISTRY-GLOBAL PC-LITERAL XREFS")
    global_xrefs = {}
    for value, name in [
        (REG_BASE_GLOBAL, "REG_BASE_GLOBAL"),
        (REG_AUX_GLOBAL, "REG_AUX_GLOBAL"),
        (REG_BOUND_GLOBAL, "REG_BOUND_GLOBAL"),
    ]:
        hits = aud.exact_literal_xrefs(value)
        global_xrefs[value] = hits
        print()
        print(f"{name} 0x{value:08X}: xrefs={len(hits)}")
        for img_name, site, mode, litaddr in hits:
            owner = aud.plausible_function_start(site, mode)
            print(
                f"  {img_name:12s} site=0x{site:08X}[{mode}] "
                f"literal_word=0x{litaddr:08X} owner_approx=0x{owner:08X}"
            )

    hdr("C. DIRECT CALLERS OF KNOWN REGISTRY PRIMITIVES")
    primitive_calls = {}
    for target, name in [
        (ID_TO_DENSE, "ID_TO_DENSE"),
        (GET_PARENT_ID, "GET_PARENT_ID"),
        (CHILD_AT_INDEX, "CHILD_AT_INDEX"),
        (INDEX_TO_ID, "INDEX_TO_ID"),
    ]:
        hits = aud.scan_calls_to(target)
        primitive_calls[target] = hits
        print()
        print(f"{name} 0x{target:08X}: direct calls={len(hits)}")
        for img_name, site, mode, eff, emode, veneer in hits[:120]:
            owner = aud.plausible_function_start(site, mode)
            v = f" via_veneer=0x{veneer:08X}" if veneer is not None else ""
            print(
                f"  {img_name:12s} callsite=0x{site:08X}[{mode}] "
                f"owner_approx=0x{owner:08X}{v}"
            )

    hdr("D. REGISTRY RECORD MUTATOR CANDIDATES")
    candidate_keys: Dict[Tuple[int, str], Dict[str, object]] = {}

    # Candidate owners from exact REG_BASE_GLOBAL xrefs.
    for img_name, site, mode, litaddr in global_xrefs[REG_BASE_GLOBAL]:
        owner = aud.plausible_function_start(site, mode)
        key = (owner, mode)
        candidate_keys.setdefault(key, {"reasons": set(), "xref_sites": [], "dense_calls": []})
        candidate_keys[key]["reasons"].add("REG_BASE_XREF")
        candidate_keys[key]["xref_sites"].append(site)

    # Candidate owners from ID_TO_DENSE callers.
    for img_name, site, mode, eff, emode, veneer in primitive_calls[ID_TO_DENSE]:
        owner = aud.plausible_function_start(site, mode)
        key = (owner, mode)
        candidate_keys.setdefault(key, {"reasons": set(), "xref_sites": [], "dense_calls": []})
        candidate_keys[key]["reasons"].add("CALL_ID_TO_DENSE")
        candidate_keys[key]["dense_calls"].append(site)

    candidates = []

    for (owner, mode), meta in candidate_keys.items():
        fa = aud.audit_function(owner, mode, max_span=0x900)
        literal_values = {
            ins.literal_value
            for ins in fa.visited.values()
            if ins.literal_value is not None
        }
        has_regbase = REG_BASE_GLOBAL in literal_values
        has_dense_call = any(
            target == ID_TO_DENSE
            for _, target, _ in fa.calls
        )
        store_count = len(fa.stores)

        # Registry-record mutator candidate requires a registry anchor plus stores.
        score = 0
        if has_regbase:
            score += 3
        if has_dense_call:
            score += 3
        if store_count:
            score += min(4, store_count)
        if REG_AUX_GLOBAL in literal_values:
            score += 1
        if REG_BOUND_GLOBAL in literal_values:
            score += 1

        focus_literals = sorted(
            v for v in literal_values if v in FOCUS_IDS
        )
        if focus_literals:
            score += 2

        candidates.append(
            (score, owner, mode, fa, has_regbase, has_dense_call, focus_literals, meta)
        )

    candidates.sort(key=lambda x: (-x[0], x[1], x[2]))

    mutators = []
    for row in candidates[: args.max_candidates]:
        score, owner, mode, fa, has_regbase, has_dense_call, focus_literals, meta = row
        if not fa.stores:
            continue
        if not (has_regbase or has_dense_call):
            continue

        mutators.append(row)

        print()
        print(
            f"CANDIDATE owner=0x{owner:08X}[{mode}] image={fa.image} "
            f"score={score} stores={len(fa.stores)} calls={len(fa.calls)} "
            f"regbase={has_regbase} id_to_dense={has_dense_call} truncated={fa.truncated}"
        )
        print("  reasons=" + ",".join(sorted(meta["reasons"])))
        if focus_literals:
            print(
                "  focus literals="
                + ", ".join(f"0x{x:04X}<{FOCUS_IDS[x]}>" for x in focus_literals)
            )

        # Print exact registry xrefs and stores in the owner.
        for addr in sorted(fa.visited):
            ins = fa.visited[addr]
            interesting = False
            tags = []

            if ins.literal_value in {REG_BASE_GLOBAL, REG_AUX_GLOBAL, REG_BOUND_GLOBAL}:
                interesting = True
                tags.append("REGISTRY_GLOBAL")

            if ins.literal_value in FOCUS_IDS:
                interesting = True
                tags.append(FOCUS_IDS[ins.literal_value])

            if addr in fa.stores:
                interesting = True
                tags.append("STORE")

            if any(site == addr for site, target, m in fa.calls if target == ID_TO_DENSE):
                interesting = True
                tags.append("CALL_ID_TO_DENSE")

            if interesting:
                print(
                    f"    0x{addr:08X}: {ins.text}"
                    + (f" ; {'|'.join(tags)}" if tags else "")
                )

    print()
    print(f"mutator candidates emitted = {len(mutators)}")

    hdr("E. CALLERS OF MUTATOR CANDIDATES / CONSTANT ARGUMENTS")
    high_value_callers = []

    # Limit to stronger candidates to keep report manageable.
    for score, owner, owner_mode, fa, has_regbase, has_dense_call, focus_literals, meta in mutators:
        if score < 4:
            continue

        hits = aud.scan_calls_to(owner)
        if not hits:
            continue

        print()
        print(
            f"MUTATOR 0x{owner:08X}[{owner_mode}] score={score} callers={len(hits)}"
        )

        for img_name, site, caller_mode, eff, emode, veneer in hits[: args.max_callers]:
            args_found = {}
            for reg in ["r0", "r1", "r2", "r3"]:
                val = aud.local_constant_for_reg(site, caller_mode, reg)
                if val is not None:
                    args_found[reg] = val

            focus = []
            for reg, (value, src, kind) in args_found.items():
                if (value & 0xFFFF) in FOCUS_IDS:
                    focus.append((reg, value & 0xFFFF, src, kind))

            print(
                f"  {img_name:12s} callsite=0x{site:08X}[{caller_mode}]"
                + (f" via_veneer=0x{veneer:08X}" if veneer is not None else "")
            )

            if args_found:
                print(
                    "    constants: "
                    + ", ".join(
                        f"{reg}=0x{value:08X}@0x{src:08X}({kind})"
                        for reg, (value, src, kind) in sorted(args_found.items())
                    )
                )

            if focus:
                print(
                    "    FOCUS: "
                    + ", ".join(
                        f"{reg}=0x{value:04X}<{FOCUS_IDS[value]}>"
                        for reg, value, src, kind in focus
                    )
                )
                high_value_callers.append((owner, site, caller_mode, focus))
                print_context(aud, site, caller_mode, before=0x30, after=0x14)

    hdr("F. GENERIC CHILD-REGISTRATION API CALLER CENSUS")
    for target, name in [
        (GENERIC_ADD_CHILD, "GENERIC_ADD_CHILD_F02EE14C"),
        (GENERIC_ADD_CHILD_WRAPPER, "GENERIC_ADD_CHILD_WRAPPER_F02E72F0"),
        (GENERIC_NODE_CREATE, "GENERIC_NODE_CREATE_F02F1E44"),
        (GENERIC_TYPE0_CREATE, "GENERIC_TYPE0_CREATE_F02F0AB8"),
    ]:
        hits = aud.scan_calls_to(target)
        print()
        print(f"{name} 0x{target:08X}: calls={len(hits)}")

        focus_count = 0
        for img_name, site, mode, eff, emode, veneer in hits[:200]:
            vals = {}
            for reg in ["r0", "r1", "r2", "r3"]:
                val = aud.local_constant_for_reg(site, mode, reg)
                if val is not None:
                    vals[reg] = val

            focus = []
            for reg, (value, src, kind) in vals.items():
                v16 = value & 0xFFFF
                if v16 in FOCUS_IDS:
                    focus.append((reg, v16, src, kind))

            if focus:
                focus_count += 1
                print(
                    f"  {img_name:12s} callsite=0x{site:08X}[{mode}] "
                    + ", ".join(
                        f"{reg}=0x{v:04X}<{FOCUS_IDS[v]}>"
                        for reg, v, src, kind in focus
                    )
                )
                print_context(aud, site, mode, before=0x30, after=0x14)

        print(f"  focus-ID caller contexts = {focus_count}")

    hdr("G. FOCUS-ID OCCURRENCE SUMMARY")
    for value, name in FOCUS_IDS.items():
        occ = u16_occurrences(images, value)
        print(f"0x{value:04X} {name:14s}: raw_u16_occurrences={len(occ)}")
        # Only print a compact sample. Raw occurrences are supporting evidence only.
        for img_name, addr in occ[:16]:
            print(f"  {img_name:12s} 0x{addr:08X}")

    hdr("H. HIGH-VALUE MUTATOR CALLER SUMMARY")
    print(f"mutator caller contexts with focus constants = {len(high_value_callers)}")
    for owner, site, mode, focus in high_value_callers:
        print(
            f"  mutator=0x{owner:08X} caller=0x{site:08X}[{mode}] "
            + ", ".join(
                f"{reg}=0x{value:04X}<{FOCUS_IDS[value]}>"
                for reg, value, src, kind in focus
            )
        )

    hdr("I. DECISION GATE")
    print(f"registry mutator candidates        = {len(mutators)}")
    print(f"focus-bearing mutator callsites    = {len(high_value_callers)}")
    print()
    print("Interpretation rules:")
    print("  - A function is NOT promoted to registry mutator merely because it has stores.")
    print("  - Highest-confidence candidates combine F007F044 access, ID_TO_DENSE use,")
    print("    and stores in the same reachable owner.")
    print("  - Constant B709/8321/8928 at a caller is supporting evidence until exact")
    print("    argument/dataflow into a registry field is demonstrated.")
    print("  - Generic F02EE14C/F02E72F0 framework evidence must not be conflated with")
    print("    the F007F044 registry unless the same backing dataflow is proven.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
