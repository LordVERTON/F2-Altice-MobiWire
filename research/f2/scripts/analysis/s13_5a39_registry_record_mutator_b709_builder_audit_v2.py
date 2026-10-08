#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.39 v2 - REGISTRY RECORD MUTATOR / B709 BUILDER AUDIT

Optimized replacement for A.39 v1.

The v1 scanner repeatedly disassembled every byte range in Thumb and ARM for
each query. That was unnecessarily expensive and could terminate before
buffered output reached PowerShell.

v2:
- line-buffers stdout so progress is visible immediately;
- guards all canonical inputs first;
- builds ONE compact direct-call index using raw branch prefilters;
- finds exact registry-global literal xrefs by searching literal words first,
  then decoding only their possible PC-relative reference windows;
- reuses the call index for all target queries;
- audits only the small set of registry-mutator candidate functions.

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no D3 / D5 / D6
- no write / erase
- no phone access
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
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

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

TITLE = "S13.5A.39 v2 - REGISTRY RECORD MUTATOR / B709 BUILDER AUDIT"

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


def hdr(title: str) -> None:
    print()
    print("=" * 120)
    print(title)
    print("=" * 120, flush=True)


@dataclass(frozen=True)
class Image:
    name: str
    data: bytes
    base: int
    primary_mode: str

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

    def read_u16(self, addr: int) -> int:
        return struct.unpack_from("<H", self.read(addr, 2))[0]

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
class Call:
    image: str
    site: int
    caller_mode: str
    raw_target: int
    raw_target_mode: str
    effective_target: int
    effective_mode: str
    veneer: Optional[int]


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
        self.calls: List[Call] = []
        self.calls_by_target: Dict[int, List[Call]] = defaultdict(list)

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
        addr &= (~1 if mode == MODE_THUMB else ~3)
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

        if (is_call or is_jump) and ci.operands and ci.operands[0].type == CS_OP_IMM:
            target = int(ci.operands[0].imm) & 0xFFFFFFFF
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

    def build_call_index(self) -> None:
        hdr("B. BUILD ONE-TIME DIRECT-CALL INDEX")
        calls = []

        for img in self.images:
            print(f"Indexing calls: {img.name} ({img.primary_mode}) ...", flush=True)

            if img.primary_mode == MODE_THUMB:
                # Prefilter possible 32-bit Thumb BL/BLX encodings.
                off = 0
                data = img.data
                n = len(data)
                while off + 4 <= n:
                    h1 = struct.unpack_from("<H", data, off)[0]
                    h2 = struct.unpack_from("<H", data, off + 2)[0]
                    if (h1 & 0xF800) == 0xF000 and (h2 & 0xC000) == 0xC000:
                        site = img.base + off
                        ins = self.decode_one(site, MODE_THUMB)
                        if (
                            ins and ins.is_call
                            and ins.target is not None
                            and ins.target_mode is not None
                        ):
                            eff, emode, veneer = self.normalize_target(
                                ins.target, ins.target_mode
                            )
                            calls.append(
                                Call(
                                    image=img.name,
                                    site=site,
                                    caller_mode=MODE_THUMB,
                                    raw_target=ins.target,
                                    raw_target_mode=ins.target_mode,
                                    effective_target=eff,
                                    effective_mode=emode,
                                    veneer=veneer,
                                )
                            )
                    off += 2

            else:
                # ARM BL / BLX immediate prefilter.
                off = 0
                data = img.data
                n = len(data)
                while off + 4 <= n:
                    word = struct.unpack_from("<I", data, off)[0]
                    possible_bl = (word & 0x0F000000) == 0x0B000000
                    possible_blx = (word & 0xFE000000) == 0xFA000000
                    if possible_bl or possible_blx:
                        site = img.base + off
                        ins = self.decode_one(site, MODE_ARM)
                        if (
                            ins and ins.is_call
                            and ins.target is not None
                            and ins.target_mode is not None
                        ):
                            eff, emode, veneer = self.normalize_target(
                                ins.target, ins.target_mode
                            )
                            calls.append(
                                Call(
                                    image=img.name,
                                    site=site,
                                    caller_mode=MODE_ARM,
                                    raw_target=ins.target,
                                    raw_target_mode=ins.target_mode,
                                    effective_target=eff,
                                    effective_mode=emode,
                                    veneer=veneer,
                                )
                            )
                    off += 4

        # De-duplicate exact callsites.
        uniq = {}
        for c in calls:
            uniq[(c.image, c.site, c.caller_mode)] = c

        self.calls = sorted(uniq.values(), key=lambda c: (c.image, c.site, c.caller_mode))
        self.calls_by_target.clear()
        for c in self.calls:
            self.calls_by_target[c.effective_target].append(c)

        print(f"Direct-call index entries = {len(self.calls)}", flush=True)

    def calls_to(self, target: int) -> List[Call]:
        return list(self.calls_by_target.get(target & ~1, []))

    def literal_word_occurrences(self, value: int) -> List[Tuple[Image, int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        out = []
        for img in self.images:
            start = 0
            while True:
                off = img.data.find(needle, start)
                if off < 0:
                    break
                out.append((img, img.base + off))
                start = off + 1
        return out

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str, int, str, int]]:
        """
        Efficient exact PC-literal xref search:
        1) find exact 32-bit literal WORD occurrences;
        2) only decode possible referring instructions within architectural
           PC-relative reach behind each literal.
        """
        out = set()
        occ = self.literal_word_occurrences(value)

        for img, lit_addr in occ:
            # Search both modes only in a bounded window before the literal.
            # Thumb-2 / ARM PC-relative LDR reach is <= ~4 KiB.
            lo = max(img.base, lit_addr - 0x1100)

            # Thumb candidates.
            a = lo & ~1
            while a < lit_addr:
                ins = self.decode_one(a, MODE_THUMB)
                if (
                    ins
                    and ins.literal_addr == lit_addr
                    and ins.literal_value == value
                ):
                    out.add((img.name, a, MODE_THUMB, lit_addr))
                a += 2

            # ARM candidates.
            a = (lo + 3) & ~3
            while a < lit_addr:
                ins = self.decode_one(a, MODE_ARM)
                if (
                    ins
                    and ins.literal_addr == lit_addr
                    and ins.literal_value == value
                ):
                    out.add((img.name, a, MODE_ARM, lit_addr))
                a += 4

        return sorted(out, key=lambda x: (x[0], x[1], x[2]))

    def plausible_function_start(self, site: int, mode: str, back: int = 0x180) -> int:
        img = self.image_for(site)
        if not img:
            return site & (~1 if mode == MODE_THUMB else ~3)

        align = 2 if mode == MODE_THUMB else 4
        lo = max(img.base, site - back)
        lo -= lo % align
        best = None

        a = lo
        while a <= site:
            ins = self.decode_one(a, mode)
            if ins:
                m = ins.mnemonic.lower()
                o = ins.op_str.lower()
                if mode == MODE_THUMB:
                    if m == "push" and "lr" in o:
                        best = a
                    a += ins.size
                else:
                    if (m.startswith("stm") or m == "push") and ("lr" in o or "sp" in o):
                        best = a
                    a += 4
            else:
                a += align

        return best if best is not None else (site & (~1 if mode == MODE_THUMB else ~3))

    def audit_function(
        self,
        entry: int,
        mode: str,
        max_span: int = 0x900,
        max_insns: int = 3000,
    ) -> FunctionAudit:
        entry &= (~1 if mode == MODE_THUMB else ~3)
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
            if not ins:
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

    def _cs_one(self, addr: int, mode: str):
        img = self.image_for(addr)
        if not img:
            return None
        md = self.thumb if mode == MODE_THUMB else self.arm
        width = min(4, img.end - addr)
        ds = list(md.disasm(img.read(addr, width), addr, count=1))
        return ds[0] if ds else None

    def local_constants(
        self,
        callsite: int,
        mode: str,
        regs: Tuple[str, ...] = ("r0", "r1", "r2", "r3"),
        back: int = 0x50,
    ) -> Dict[str, Tuple[int, int, str]]:
        """
        Conservative forward symbolic evaluation inside the last straight-line
        block before a call. Supports the common firmware ID builders:
          mov/movs #imm
          movw + movt
          ldr =literal
          mov register
          add/sub immediate
          lsl/lsls immediate

        Returns only registers that remain exact constants at the callsite.
        """
        img = self.image_for(callsite)
        if not img:
            return {}

        align = 2 if mode == MODE_THUMB else 4
        lo = max(img.base, callsite - back)
        lo -= lo % align

        decoded = []
        a = lo
        while a < callsite:
            ins = self.decode_one(a, mode)
            if ins:
                decoded.append(ins)
                a += ins.size if mode == MODE_THUMB else 4
            else:
                a += align

        # Keep only the straight-line suffix after the last call/jump.
        cut = 0
        for i, ins in enumerate(decoded):
            if ins.is_call or ins.is_jump:
                cut = i + 1
        decoded = decoded[cut:]

        wanted = {r.lower() for r in regs}
        state: Dict[str, Tuple[int, int, str]] = {}

        def reg_name_from_id(md, rid: int) -> str:
            try:
                return md.reg_name(rid).lower()
            except Exception:
                return ""

        for ins in decoded:
            ci = self._cs_one(ins.addr, mode)
            if ci is None or not ci.operands:
                continue

            m = ci.mnemonic.lower()
            op0 = ci.operands[0]
            if op0.type != CS_OP_REG:
                continue

            md = self.thumb if mode == MODE_THUMB else self.arm
            dst = reg_name_from_id(md, int(op0.reg))
            if dst not in wanted:
                continue

            # PC-literal load.
            if m.startswith("ldr") and ins.literal_value is not None:
                state[dst] = (ins.literal_value & 0xFFFFFFFF, ins.addr, "PC_LITERAL")
                continue

            # MOV/MOVS/MOVW.
            if m in {"mov", "movs", "mov.w", "movw"} and len(ci.operands) >= 2:
                src = ci.operands[1]
                if src.type == CS_OP_IMM:
                    state[dst] = (int(src.imm) & 0xFFFFFFFF, ins.addr, m.upper())
                elif src.type == CS_OP_REG:
                    sreg = reg_name_from_id(md, int(src.reg))
                    if sreg in state:
                        val, srcaddr, kind = state[sreg]
                        state[dst] = (val, ins.addr, f"MOV<{kind}>")
                    else:
                        state.pop(dst, None)
                else:
                    state.pop(dst, None)
                continue

            # MOVT combines with existing low half.
            if m == "movt" and len(ci.operands) >= 2 and ci.operands[1].type == CS_OP_IMM:
                hi = int(ci.operands[1].imm) & 0xFFFF
                if dst in state:
                    lo16 = state[dst][0] & 0xFFFF
                    state[dst] = (((hi << 16) | lo16) & 0xFFFFFFFF, ins.addr, "MOVW_MOVT")
                else:
                    state.pop(dst, None)
                continue

            # Shift-left forms, including "lsls r0, r0, #8" and "lsls r0, #8".
            if m.startswith("lsl") and len(ci.operands) >= 2:
                src_reg = dst
                imm = None
                if len(ci.operands) == 2 and ci.operands[1].type == CS_OP_IMM:
                    imm = int(ci.operands[1].imm)
                elif len(ci.operands) >= 3:
                    if ci.operands[1].type == CS_OP_REG:
                        src_reg = reg_name_from_id(md, int(ci.operands[1].reg))
                    if ci.operands[2].type == CS_OP_IMM:
                        imm = int(ci.operands[2].imm)
                if imm is not None and src_reg in state:
                    val = (state[src_reg][0] << imm) & 0xFFFFFFFF
                    state[dst] = (val, ins.addr, "LSL_CONST")
                else:
                    state.pop(dst, None)
                continue

            # ADD/SUB immediate, common for B6FD + N constructions.
            if m.startswith(("add", "sub")) and len(ci.operands) >= 2:
                sign = 1 if m.startswith("add") else -1
                src_reg = dst
                imm = None

                if len(ci.operands) == 2 and ci.operands[1].type == CS_OP_IMM:
                    imm = int(ci.operands[1].imm)
                elif len(ci.operands) >= 3:
                    if ci.operands[1].type == CS_OP_REG:
                        src_reg = reg_name_from_id(md, int(ci.operands[1].reg))
                    if ci.operands[2].type == CS_OP_IMM:
                        imm = int(ci.operands[2].imm)

                if imm is not None and src_reg in state:
                    val = (state[src_reg][0] + sign * imm) & 0xFFFFFFFF
                    state[dst] = (val, ins.addr, "ARITH_CONST")
                else:
                    state.pop(dst, None)
                continue

            # Any other write destroys exactness.
            state.pop(dst, None)

        return {r: state[r] for r in regs if r in state}


def load_guard(path: Path, size: int, expected_sha: str, name: str) -> bytes:
    print(f"Loading {name}: {path}", flush=True)
    if not path.is_file():
        raise SystemExit(f"Missing {name}: {path}")
    data = path.read_bytes()
    digest = sha256(data)
    ok = len(data) == size and digest == expected_sha
    print(f"  size   = 0x{len(data):X}", flush=True)
    print(f"  sha256 = {digest}", flush=True)
    print(f"  guard  = {'PASS' if ok else 'FAIL'}", flush=True)
    if not ok:
        raise SystemExit(f"ABORT: canonical {name} guard failed")
    return data


def print_context(aud: Auditor, site: int, mode: str, before: int = 0x30, after: int = 0x14) -> None:
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
            text = f"effective=0x{eff:08X}[{emode}]"
            if veneer is not None:
                text += f" via_veneer=0x{veneer:08X}"
            ann.append(text)
        if ins.literal_value is not None:
            extra = ""
            v16 = ins.literal_value & 0xFFFF
            if v16 in FOCUS_IDS:
                extra = f" {FOCUS_IDS[v16]}"
            if ins.literal_value in {REG_BASE_GLOBAL, REG_AUX_GLOBAL, REG_BOUND_GLOBAL}:
                extra = " REGISTRY_GLOBAL"
            ann.append(
                f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}{extra}"
            )

        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"{mark} 0x{a:08X}: {ins.text}{suffix}")
        a += ins.size if mode == MODE_THUMB else 4


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument("--boot", default=r"C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin")
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
    ap.add_argument("--dump", default=r"C:\Users\verto\mtkclient\research\f2\data\dumps\mobiwire_dump_2.bin")
    ap.add_argument("--max-candidates", type=int, default=60)
    args = ap.parse_args()

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO", flush=True)

    hdr("A. CANONICAL INPUT GUARDS")
    ad = load_guard(Path(args.alice), ALICE_SIZE, ALICE_SHA256, "ALICE")
    bd = load_guard(Path(args.boot), BOOT_SIZE, BOOT_SHA256, "BOOT_ZIMAGE")
    zd = load_guard(Path(args.zimage), ZIMAGE_SIZE, ZIMAGE_SHA256, "ZIMAGE")
    dd = load_guard(Path(args.dump), DUMP_SIZE, DUMP_SHA256, "DUMP")

    images = [
        Image("ALICE", ad, ALICE_BASE, MODE_THUMB),
        Image("BOOT_ZIMAGE", bd, BOOT_BASE, MODE_THUMB),
        Image("ZIMAGE", zd, ZIMAGE_BASE, MODE_THUMB),
        Image("PHYSICAL_ROM", dd[:ROM_END - ROM_BASE], ROM_BASE, MODE_ARM),
    ]
    aud = Auditor(images)

    aud.build_call_index()

    hdr("C. EXACT REGISTRY-GLOBAL PC-LITERAL XREFS")
    global_xrefs = {}
    for value, name in [
        (REG_BASE_GLOBAL, "REG_BASE_GLOBAL"),
        (REG_AUX_GLOBAL, "REG_AUX_GLOBAL"),
        (REG_BOUND_GLOBAL, "REG_BOUND_GLOBAL"),
    ]:
        print(f"Searching xrefs to {name} 0x{value:08X} ...", flush=True)
        hits = aud.exact_literal_xrefs(value)
        global_xrefs[value] = hits
        print(f"{name}: xrefs={len(hits)}")
        for img_name, site, mode, litaddr in hits:
            owner = aud.plausible_function_start(site, mode)
            print(
                f"  {img_name:12s} site=0x{site:08X}[{mode}] "
                f"literal_word=0x{litaddr:08X} owner_approx=0x{owner:08X}"
            )

    hdr("D. DIRECT CALLERS OF KNOWN REGISTRY PRIMITIVES")
    for target, name in [
        (ID_TO_DENSE, "ID_TO_DENSE"),
        (GET_PARENT_ID, "GET_PARENT_ID"),
        (CHILD_AT_INDEX, "CHILD_AT_INDEX"),
        (INDEX_TO_ID, "INDEX_TO_ID"),
    ]:
        hits = aud.calls_to(target)
        print(f"{name} 0x{target:08X}: direct calls={len(hits)}")
        for c in hits[:120]:
            owner = aud.plausible_function_start(c.site, c.caller_mode)
            v = f" via_veneer=0x{c.veneer:08X}" if c.veneer is not None else ""
            print(
                f"  {c.image:12s} callsite=0x{c.site:08X}[{c.caller_mode}] "
                f"owner_approx=0x{owner:08X}{v}"
            )

    hdr("E. REGISTRY RECORD MUTATOR CANDIDATES")
    candidate_keys: Dict[Tuple[int, str], Set[str]] = defaultdict(set)

    for img_name, site, mode, litaddr in global_xrefs[REG_BASE_GLOBAL]:
        candidate_keys[(aud.plausible_function_start(site, mode), mode)].add("REG_BASE_XREF")

    for c in aud.calls_to(ID_TO_DENSE):
        candidate_keys[(aud.plausible_function_start(c.site, c.caller_mode), c.caller_mode)].add("CALL_ID_TO_DENSE")

    rows = []
    for (owner, mode), reasons in candidate_keys.items():
        fa = aud.audit_function(owner, mode)
        literal_values = {
            ins.literal_value
            for ins in fa.visited.values()
            if ins.literal_value is not None
        }
        has_regbase = REG_BASE_GLOBAL in literal_values
        has_dense = any(t == ID_TO_DENSE for _, t, _ in fa.calls)
        focus_literals = sorted(
            (v & 0xFFFF) for v in literal_values
            if (v & 0xFFFF) in FOCUS_IDS
        )

        score = 0
        score += 4 if has_regbase else 0
        score += 4 if has_dense else 0
        score += min(4, len(fa.stores))
        score += 2 if focus_literals else 0
        score += 1 if REG_AUX_GLOBAL in literal_values else 0
        score += 1 if REG_BOUND_GLOBAL in literal_values else 0

        if fa.stores and (has_regbase or has_dense):
            rows.append((score, owner, mode, fa, has_regbase, has_dense, focus_literals, reasons))

    rows.sort(key=lambda x: (-x[0], x[1], x[2]))
    rows = rows[:args.max_candidates]

    print(f"candidate count = {len(rows)}", flush=True)

    for score, owner, mode, fa, has_regbase, has_dense, focus_literals, reasons in rows:
        print()
        print(
            f"CANDIDATE owner=0x{owner:08X}[{mode}] image={fa.image} "
            f"score={score} stores={len(fa.stores)} calls={len(fa.calls)} "
            f"regbase={has_regbase} id_to_dense={has_dense} truncated={fa.truncated}"
        )
        print("  reasons=" + ",".join(sorted(reasons)))
        if focus_literals:
            print(
                "  focus_literals="
                + ", ".join(f"0x{x:04X}<{FOCUS_IDS[x]}>" for x in focus_literals)
            )

        for addr in sorted(fa.visited):
            ins = fa.visited[addr]
            tags = []
            if ins.literal_value in {REG_BASE_GLOBAL, REG_AUX_GLOBAL, REG_BOUND_GLOBAL}:
                tags.append("REGISTRY_GLOBAL")
            if ins.literal_value is not None and (ins.literal_value & 0xFFFF) in FOCUS_IDS:
                tags.append(FOCUS_IDS[ins.literal_value & 0xFFFF])
            if addr in fa.stores:
                tags.append("STORE")
            if any(addr == site and target == ID_TO_DENSE for site, target, _ in fa.calls):
                tags.append("CALL_ID_TO_DENSE")
            if tags:
                print(f"    0x{addr:08X}: {ins.text} ; {'|'.join(tags)}")

    hdr("F. CALLERS OF HIGH-SCORE MUTATOR CANDIDATES")
    focus_mutator_calls = []

    for score, owner, mode, fa, has_regbase, has_dense, focus_literals, reasons in rows:
        if score < 6:
            continue
        hits = aud.calls_to(owner)
        if not hits:
            continue

        print()
        print(f"MUTATOR 0x{owner:08X}[{mode}] score={score} callers={len(hits)}")

        for c in hits[:120]:
            consts = aud.local_constants(c.site, c.caller_mode)
            focus = []
            for reg, (value, src, kind) in consts.items():
                v16 = value & 0xFFFF
                if v16 in FOCUS_IDS:
                    focus.append((reg, v16, src, kind))

            if consts:
                print(
                    f"  {c.image:12s} callsite=0x{c.site:08X}[{c.caller_mode}] "
                    + ", ".join(
                        f"{reg}=0x{value:08X}@0x{src:08X}({kind})"
                        for reg, (value, src, kind) in sorted(consts.items())
                    )
                )

            if focus:
                print(
                    "    FOCUS: "
                    + ", ".join(
                        f"{reg}=0x{v:04X}<{FOCUS_IDS[v]}>"
                        for reg, v, src, kind in focus
                    )
                )
                focus_mutator_calls.append((owner, c.site, c.caller_mode, focus))
                print_context(aud, c.site, c.caller_mode)

    hdr("G. GENERIC CHILD-REGISTRATION API CROSS-CHECK")
    for target, name in [
        (GENERIC_ADD_CHILD, "F02EE14C"),
        (GENERIC_ADD_CHILD_WRAPPER, "F02E72F0"),
        (GENERIC_NODE_CREATE, "F02F1E44"),
        (GENERIC_TYPE0_CREATE, "F02F0AB8"),
    ]:
        hits = aud.calls_to(target)
        print(f"{name} 0x{target:08X}: calls={len(hits)}")
        matched = 0

        for c in hits:
            consts = aud.local_constants(c.site, c.caller_mode)
            focus = []
            for reg, (value, src, kind) in consts.items():
                v16 = value & 0xFFFF
                if v16 in FOCUS_IDS:
                    focus.append((reg, v16, src, kind))
            if not focus:
                continue

            matched += 1
            print(
                f"  {c.image:12s} callsite=0x{c.site:08X}[{c.caller_mode}] "
                + ", ".join(
                    f"{reg}=0x{v:04X}<{FOCUS_IDS[v]}>"
                    for reg, v, src, kind in focus
                )
            )
            print_context(aud, c.site, c.caller_mode)

        print(f"  focus-ID contexts={matched}")

    hdr("H. RAW FOCUS-ID OCCURRENCE COUNTS")
    for value, name in FOCUS_IDS.items():
        needle = struct.pack("<H", value)
        total = 0
        samples = []
        for img in images:
            start = 0
            while True:
                off = img.data.find(needle, start)
                if off < 0:
                    break
                total += 1
                if len(samples) < 12:
                    samples.append((img.name, img.base + off))
                start = off + 1
        print(f"0x{value:04X} {name:14s}: total={total}")
        for img_name, addr in samples:
            print(f"  {img_name:12s} 0x{addr:08X}")

    hdr("I. DECISION GATE")
    print(f"one-time direct-call index entries = {len(aud.calls)}")
    print(f"registry mutator candidates         = {len(rows)}")
    print(f"focus-bearing mutator callsites     = {len(focus_mutator_calls)}")
    print()
    print("Interpretation:")
    print("  - REG_BASE access + ID_TO_DENSE + stores in one function is the strongest")
    print("    static signature for an F007F044 registry-record mutator.")
    print("  - Focus constants at callers are supporting evidence until exact field")
    print("    dataflow proves parent/child insertion semantics.")
    print("  - Generic F02EE14C/F02E72F0 evidence is kept separate unless backing-store")
    print("    identity with F007F044 is explicitly proven.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
