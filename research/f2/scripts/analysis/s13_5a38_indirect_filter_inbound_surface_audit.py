#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.38 - INDIRECT FILTER INBOUND SURFACE AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no D3 / D5 / D6
- no write / erase
- no phone access

Goal
----
A.36 proved:
    F02EE32C -> F0210588 -> ROM 0x10018998 = MEMZERO(buffer,length)

and therefore the filter bitmap F00C1624 is all-zero immediately after the
initializer in 0x1031FD20.

A.33 found no SET/CLEAR/PREDICATE route after that reset and before the valid
B709 rebuild, but only to callgraph depth <= 4.

A.38 starts from the A.37 finite direct closure and closes the residual indirect-control-flow surface. It adds:
- corrected ARM conditional BX<cond> LR return classification;
- full cross-image finite direct closure as a regression guard;
- residual genuine BLX/BX-register census only;
- backward provenance classification for each residual indirect target register;
- static inbound-surface census for SET/CLEAR/PREDICATE and their ALICE pointer words;
- detection of exact filter-target literals and MOVW/MOVT target construction in reachable code.

This still cannot prove behavior hidden behind an unresolved runtime function
pointer. Such unresolved indirect sites are explicitly reported as a residual
qualification instead of being silently ignored.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import deque, defaultdict
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

TITLE = "S13.5A.38 - INDIRECT FILTER INBOUND SURFACE AUDIT"

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

EVENT_OWNER = 0x102D100C
RESET_OWNER_CALLSITE = 0x102D1040
B709_REBUILD_CALLSITE = 0x102D1066
B709_REBUILD = 0x10313998

RESET_ROOT = 0x1031FD20
MEMZERO_CALLSITE_IN_RESET = 0x1031FD2E
MEMZERO_VENEER = 0xF0210588
MEMZERO_ROM = 0x10018998

SET_VENEER = 0x102FD04C
CLEAR_VENEER = 0x102FD054
SET_IMPL = 0xF02D4D10
CLEAR_IMPL = 0xF02D5828
PRED_IMPL = 0xF02D5458

FILTER_BITMAP = 0xF00C1624
FILTER_BOUND = 0xF007F04C

TARGETS = {
    SET_VENEER: "SET_VENEER",
    CLEAR_VENEER: "CLEAR_VENEER",
    SET_IMPL: "SET_IMPL",
    CLEAR_IMPL: "CLEAR_IMPL",
    PRED_IMPL: "FILTER_PREDICATE",
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
    indirect_reg: Optional[int] = None
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
    direct_calls: List[Tuple[int, int, str]] = field(default_factory=list)
    indirect_calls: List[Tuple[int, int]] = field(default_factory=list)
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
        """
        Recognize project import veneers such as:
          E51FF004 ; LDR PC,[PC,#-4]
          literal target
        """
        addr &= ~3
        img = self.image_for(addr)
        if not img or not img.contains(addr, 8):
            return None
        w0 = img.read_u32(addr)
        if w0 == 0xE51FF004:
            return img.read_u32(addr + 4)
        if w0 == 0xE59FF000:
            return img.read_u32(addr + 8) if img.contains(addr + 8, 4) else None
        return None

    def infer_entry_mode(self, addr: int, requested: Optional[str] = None) -> str:
        if requested is not None:
            return requested
        if self.raw_arm_veneer_target(addr) is not None:
            return MODE_ARM
        img = self.image_for(addr)
        if img and img.name == "PHYSICAL_ROM":
            return MODE_ARM
        return MODE_THUMB

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
        indirect_reg = None

        if (is_call or is_jump) and ci.operands:
            op0 = ci.operands[0]
            if op0.type == CS_OP_IMM:
                target = int(op0.imm) & 0xFFFFFFFF
                m = ci.mnemonic.lower()
                if mode == MODE_THUMB:
                    if m.startswith("blx"):
                        target_mode = MODE_ARM
                    else:
                        target_mode = MODE_THUMB
                else:
                    # ARM BLX immediate toggles to Thumb. Plain B/BL stays ARM.
                    if m.startswith("blx"):
                        target_mode = MODE_THUMB
                    else:
                        target_mode = MODE_ARM
            elif op0.type == CS_OP_REG:
                indirect_reg = int(op0.reg)

        literal_addr = None
        literal_value = None
        if ci.mnemonic.lower().startswith("ldr") and len(ci.operands) >= 2:
            op = ci.operands[1]
            if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                if mode == MODE_THUMB:
                    pc = (addr + 4) & ~3
                else:
                    pc = addr + 8
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
            indirect_reg=indirect_reg,
            literal_addr=literal_addr,
            literal_value=literal_value,
        )

    @staticmethod
    def is_return(ins: Insn) -> bool:
        m = ins.mnemonic.lower()
        o = ins.op_str.lower().replace(" ", "")
        # Capstone keeps ARM condition codes in the mnemonic (bxeq, bxne, ...).
        # Any BX<cond> LR is a return path, not a dynamic callback.
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

    def normalize_direct_target(self, target: int, target_mode: str) -> Tuple[int, str, Optional[int]]:
        """
        Resolve one ARM import veneer layer.
        Returns effective_addr, effective_mode, veneer_addr_or_none.
        """
        t = target & (~1 if target_mode == MODE_THUMB else ~3)

        # If raw bytes prove an ARM import veneer, follow it regardless of the
        # caller's state hint. This is important for ALICE/BOOT import stubs.
        veneer_target = self.raw_arm_veneer_target(t)
        if veneer_target is not None:
            vt = veneer_target & 0xFFFFFFFF
            # LSB controls state for indirect branch through PC.
            if vt & 1:
                return vt & ~1, MODE_THUMB, t
            return vt & ~3, MODE_ARM, t

        return t, target_mode, None

    def audit_function(
        self,
        entry: int,
        mode: str,
        max_span: int = 0x1800,
        max_insns: int = 5000,
    ) -> FunctionAudit:
        entry = entry & (~1 if mode == MODE_THUMB else ~3)
        img = self.image_for(entry)
        out = FunctionAudit(entry=entry, mode=mode, image=img.name if img else "OUTSIDE")
        if not img:
            return out

        q = deque([entry])
        seen: Set[int] = set()
        lo = entry
        hi = min(img.end, entry + max_span)

        while q and len(seen) < max_insns:
            addr = q.popleft()
            addr = addr & (~1 if mode == MODE_THUMB else ~3)

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

            if ins.is_call:
                if ins.target is not None and ins.target_mode is not None:
                    eff, emode, _ = self.normalize_direct_target(ins.target, ins.target_mode)
                    out.direct_calls.append((addr, eff, emode))
                elif ins.indirect_reg is not None:
                    out.indirect_calls.append((addr, ins.indirect_reg))
                q.append(addr + ins.size)
                continue

            if self.is_return(ins):
                continue

            if ins.is_jump:
                if ins.target is not None and ins.target_mode is not None:
                    eff, emode, _ = self.normalize_direct_target(ins.target, ins.target_mode)

                    if emode == mode and lo <= eff < hi:
                        # Normal intra-function control-flow edge.
                        q.append(eff)
                    elif self.image_for(eff):
                        # Conservative closure rule: a direct branch leaving the
                        # local function window is promoted to a global graph edge
                        # (tail-call / far code block). This avoids silently losing
                        # reachable code because of max_span.
                        out.direct_calls.append((addr, eff, emode))
                    else:
                        out.truncated = True

                elif ins.indirect_reg is not None:
                    # BX<cond> LR is a return and has already been handled above.
                    # Other BX-register transfers are possible indirect tail calls.
                    m = ins.mnemonic.lower()
                    o = ins.op_str.lower().replace(" ", "")
                    if not (m.startswith("bx") and not m.startswith("blx") and o == "lr"):
                        out.indirect_calls.append((addr, ins.indirect_reg))

                if not self.is_unconditional_branch(ins):
                    nxt = addr + ins.size
                    if nxt < hi:
                        q.append(nxt)
                    elif self.image_for(nxt):
                        # Conditional fallthrough crossing the local window:
                        # conservatively continue as a global edge.
                        out.direct_calls.append((addr, nxt, mode))
                    else:
                        out.truncated = True
                continue

            q.append(addr + ins.size)

        if q:
            out.truncated = True
        return out

    def local_indirect_target(self, fa: FunctionAudit, site: int, reg: int) -> Optional[Tuple[int, str, int]]:
        """
        Conservative backward recovery for:
            ldr Rx, [pc, #imm] ; ... ; blx/bx Rx
        Stops at call/branch or another write to Rx when detectable.
        Returns (effective_target, mode, source_addr).
        """
        addrs = [a for a in sorted(fa.visited) if a < site and a >= site - 0x30]
        for addr in reversed(addrs):
            ins = fa.visited[addr]

            if ins.is_call or ins.is_jump:
                break

            ci = self.decode_one(addr, fa.mode)
            if ci is None:
                continue

            # Parse destination register via textual form only after Capstone
            # already validated the instruction.
            dest = ci.op_str.split(",", 1)[0].strip().lower()
            md = self.thumb if fa.mode == MODE_THUMB else self.arm
            raw = self.image_for(addr).read(addr, min(4, self.image_for(addr).end - addr))
            decoded = list(md.disasm(raw, addr, count=1))
            if not decoded:
                continue
            d = decoded[0]

            if d.operands and d.operands[0].type == CS_OP_REG and int(d.operands[0].reg) == reg:
                if ci.mnemonic.lower().startswith("ldr") and ci.literal_value is not None:
                    val = ci.literal_value & 0xFFFFFFFF
                    mode = MODE_THUMB if (val & 1) else MODE_ARM
                    eff, emode, _ = self.normalize_direct_target(
                        val & (~1 if mode == MODE_THUMB else ~3),
                        mode
                    )
                    return eff, emode, addr
                # Some other instruction overwrote the call register.
                break

        return None


    def _decoded_capstone(self, addr: int, mode: str):
        img = self.image_for(addr)
        if not img:
            return None
        md = self.thumb if mode == MODE_THUMB else self.arm
        width = min(4, img.end - addr)
        ds = list(md.disasm(img.read(addr, width), addr, count=1))
        return ds[0] if ds else None

    def indirect_provenance(
        self,
        fa: FunctionAudit,
        site: int,
        reg: int,
        max_back: int = 0x60,
        max_copy_depth: int = 5,
    ) -> Tuple[str, Optional[int], Optional[str], Optional[int]]:
        """
        Conservative backward provenance for a BLX/BX register target.

        Returns:
          class, resolved_target, resolved_mode, source_instruction_address

        Classes:
          PC_LITERAL     exact address loaded from a PC-relative literal
          MOVW_MOVT      exact address built by movw/movt
          REG_COPY:*     target copied from another register; recursively traced
          MEMORY_LOAD    target loaded from non-PC memory / vtable / object
          STACK_LOAD     target restored/loaded from stack
          COMPUTED       arithmetic/logical construction
          ARG_OR_LIVEIN  no local definition found before basic-block boundary
          UNKNOWN_WRITE  local writer found but not classified
        """
        visited_regs = set()

        def chase(cur_reg: int, before: int, depth: int):
            if depth > max_copy_depth or (cur_reg, before) in visited_regs:
                return ("ARG_OR_LIVEIN", None, None, None)
            visited_regs.add((cur_reg, before))

            addrs = [
                a for a in sorted(fa.visited)
                if before - max_back <= a < before
            ]

            for addr in reversed(addrs):
                ins = fa.visited[addr]

                # Stop at a prior control-transfer: don't cross basic-block semantics blindly.
                if ins.is_call or ins.is_jump:
                    break

                d = self._decoded_capstone(addr, fa.mode)
                if d is None or not d.operands:
                    continue

                # Does this instruction write cur_reg as operand 0?
                op0 = d.operands[0]
                if op0.type != CS_OP_REG or int(op0.reg) != cur_reg:
                    continue

                m = d.mnemonic.lower()

                # PC-relative literal load.
                if m.startswith("ldr") and ins.literal_value is not None:
                    val = ins.literal_value & 0xFFFFFFFF
                    imode = MODE_THUMB if (val & 1) else MODE_ARM
                    eff, emode, _ = self.normalize_direct_target(
                        val & (~1 if imode == MODE_THUMB else ~3),
                        imode,
                    )
                    return ("PC_LITERAL", eff, emode, addr)

                # Non-PC memory load: callback/vtable/object/global RAM.
                if m.startswith("ldr") and len(d.operands) >= 2 and d.operands[1].type == CS_OP_MEM:
                    return ("MEMORY_LOAD", None, None, addr)

                # MOV register copy.
                if m in {"mov", "movs", "mov.w"} and len(d.operands) >= 2:
                    op1 = d.operands[1]
                    if op1.type == CS_OP_REG:
                        sub = chase(int(op1.reg), addr, depth + 1)
                        return ("REG_COPY:" + sub[0], sub[1], sub[2], sub[3] or addr)
                    if op1.type == CS_OP_IMM:
                        val = int(op1.imm) & 0xFFFFFFFF
                        imode = MODE_THUMB if (val & 1) else MODE_ARM
                        return ("COMPUTED", val & (~1 if imode == MODE_THUMB else ~3), imode, addr)

                # MOVW/MOVT pair construction.
                if m == "movt" and len(d.operands) >= 2 and d.operands[1].type == CS_OP_IMM:
                    hi = int(d.operands[1].imm) & 0xFFFF
                    for a2 in reversed([x for x in addrs if x < addr]):
                        d2 = self._decoded_capstone(a2, fa.mode)
                        if d2 is None or len(d2.operands) < 2:
                            continue
                        if (
                            d2.mnemonic.lower() == "movw"
                            and d2.operands[0].type == CS_OP_REG
                            and int(d2.operands[0].reg) == cur_reg
                            and d2.operands[1].type == CS_OP_IMM
                        ):
                            lo = int(d2.operands[1].imm) & 0xFFFF
                            val = ((hi << 16) | lo) & 0xFFFFFFFF
                            imode = MODE_THUMB if (val & 1) else MODE_ARM
                            eff, emode, _ = self.normalize_direct_target(
                                val & (~1 if imode == MODE_THUMB else ~3),
                                imode,
                            )
                            return ("MOVW_MOVT", eff, emode, addr)
                        # Stop if the same register was overwritten.
                        if d2.operands and d2.operands[0].type == CS_OP_REG and int(d2.operands[0].reg) == cur_reg:
                            break
                    return ("COMPUTED", None, None, addr)

                # Stack-restored / multi-load value.
                if m.startswith("pop") or m.startswith("ldm"):
                    return ("STACK_LOAD", None, None, addr)

                # Arithmetic/logical construction.
                if m.startswith(("add", "sub", "orr", "eor", "and", "adr")):
                    return ("COMPUTED", None, None, addr)

                return ("UNKNOWN_WRITE", None, None, addr)

            return ("ARG_OR_LIVEIN", None, None, None)

        return chase(reg, site, 0)

    def reachable_movw_movt_filter_constructions(
        self,
        cache: Dict[Tuple[int, str], FunctionAudit],
        wanted: Set[int],
    ) -> List[Tuple[Tuple[int, str], int, int]]:
        """Find exact target addresses built with local MOVW/MOVT pairs."""
        hits = []
        wanted_even = {x & ~1 for x in wanted}

        for key, fa in cache.items():
            addrs = sorted(fa.visited)
            for i, addr in enumerate(addrs):
                d = self._decoded_capstone(addr, fa.mode)
                if d is None or d.mnemonic.lower() != "movt" or len(d.operands) < 2:
                    continue
                if d.operands[0].type != CS_OP_REG or d.operands[1].type != CS_OP_IMM:
                    continue
                reg = int(d.operands[0].reg)
                hi = int(d.operands[1].imm) & 0xFFFF

                for a2 in reversed([x for x in addrs if addr - 0x30 <= x < addr]):
                    d2 = self._decoded_capstone(a2, fa.mode)
                    if d2 is None or not d2.operands:
                        continue
                    if d2.operands[0].type == CS_OP_REG and int(d2.operands[0].reg) == reg:
                        if (
                            d2.mnemonic.lower() == "movw"
                            and len(d2.operands) >= 2
                            and d2.operands[1].type == CS_OP_IMM
                        ):
                            lo = int(d2.operands[1].imm) & 0xFFFF
                            val = ((hi << 16) | lo) & 0xFFFFFFFF
                            if (val & ~1) in wanted_even:
                                hits.append((key, addr, val))
                        break
        return hits


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


def event_post_reset_roots(aud: Auditor) -> Tuple[List[Tuple[str, int, int, str]], FunctionAudit]:
    """
    Root set:
      A) direct calls INSIDE RESET_ROOT after MEMZERO_CALLSITE
      B) EVENT_OWNER direct calls after RESET_OWNER_CALLSITE and before rebuild
    """
    roots: List[Tuple[str, int, int, str]] = []

    reset_fa = aud.audit_function(RESET_ROOT, MODE_THUMB, max_span=0x200)
    for site, target, mode in sorted(reset_fa.direct_calls):
        if site > MEMZERO_CALLSITE_IN_RESET:
            roots.append(("RESET_INTERNAL", site, target, mode))

    owner_fa = aud.audit_function(EVENT_OWNER, MODE_THUMB, max_span=0x200)
    for site, target, mode in sorted(owner_fa.direct_calls):
        if RESET_OWNER_CALLSITE < site < B709_REBUILD_CALLSITE:
            roots.append(("EVENT_TAIL", site, target, mode))

    # de-dup while preserving label/site
    seen = set()
    out = []
    for x in roots:
        k = (x[1], x[2], x[3])
        if k not in seen:
            seen.add(k)
            out.append(x)

    return out, owner_fa


def ptr_occurrences(images: List[Image], value: int) -> List[Tuple[str, int, str]]:
    out = []
    for img in images:
        for v, label in [(value & 0xFFFFFFFF, "EVEN"), ((value | 1) & 0xFFFFFFFF, "THUMB_PTR")]:
            needle = struct.pack("<I", v)
            start = 0
            while True:
                off = img.data.find(needle, start)
                if off < 0:
                    break
                out.append((img.name, img.base + off, label))
                start = off + 1
    return sorted(set(out), key=lambda x: (x[0], x[1], x[2]))


def reconstruct_path(
    node: Tuple[int, str],
    parent: Dict[Tuple[int, str], Tuple[Tuple[int, str], int]],
) -> List[Tuple[Tuple[int, str], Optional[int]]]:
    rev = [(node, None)]
    cur = node
    while cur in parent:
        prev, site = parent[cur]
        rev.append((prev, site))
        cur = prev
    rev.reverse()
    return rev


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
    ap.add_argument("--max-functions", type=int, default=6000)
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

    rom_len = ROM_END - ROM_BASE
    images = [
        Image("ALICE", ad, ALICE_BASE),
        Image("BOOT_ZIMAGE", bd, BOOT_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
        Image("PHYSICAL_ROM", dd[:rom_len], ROM_BASE),
    ]
    aud = Auditor(images)

    hdr("B. KNOWN FILTER TARGETS / VENEER RESOLUTION")
    for addr, name in TARGETS.items():
        img = aud.image_for(addr)
        vt = aud.raw_arm_veneer_target(addr)
        s = f"{name:18s} 0x{addr:08X} image={img.name if img else 'OUTSIDE'}"
        if vt is not None:
            s += f" ARM_VENEER->0x{vt:08X}"
        print(s)

    print()
    print(f"MEMZERO_VENEER 0x{MEMZERO_VENEER:08X} -> 0x{aud.raw_arm_veneer_target(MEMZERO_VENEER):08X}")
    print(f"MEMZERO_ROM    expected 0x{MEMZERO_ROM:08X}")

    hdr("C. POST-MEMZERO ROOT SET")
    roots, owner_fa = event_post_reset_roots(aud)
    print(f"root count = {len(roots)}")
    for kind, site, target, mode in roots:
        print(f"  {kind:14s} callsite=0x{site:08X} -> 0x{target:08X} [{mode}]")

    hdr("D. FULL DIRECT CALLGRAPH CLOSURE")
    cache: Dict[Tuple[int, str], FunctionAudit] = {}
    queue = deque()
    parent: Dict[Tuple[int, str], Tuple[Tuple[int, str], int]] = {}
    root_of: Dict[Tuple[int, str], Tuple[str, int, int, str]] = {}

    for root in roots:
        kind, site, target, mode = root
        key = (target, mode)
        if key not in root_of:
            root_of[key] = root
            queue.append(key)

    reached_targets: Dict[int, List[Tuple[int, str]]] = defaultdict(list)
    indirect_sites: List[Tuple[Tuple[int, str], int, int, Optional[Tuple[int, str, int]]]] = []
    truncated_funcs: List[Tuple[int, str]] = []

    processed = 0

    while queue and processed < args.max_functions:
        key = queue.popleft()
        if key in cache:
            continue

        addr, mode = key
        if not aud.image_for(addr):
            continue

        fa = aud.audit_function(addr, mode)
        cache[key] = fa
        processed += 1

        if fa.truncated:
            truncated_funcs.append(key)

        if addr in TARGETS:
            reached_targets[addr].append(key)

        for site, reg in fa.indirect_calls:
            resolved = aud.local_indirect_target(fa, site, reg)
            indirect_sites.append((key, site, reg, resolved))
            if resolved is not None:
                rt, rm, src = resolved
                child = (rt, rm)
                if child not in cache and child not in root_of:
                    root_of[child] = root_of.get(key, ("INDIRECT", site, rt, rm))
                    parent[child] = (key, site)
                    queue.append(child)

        for site, child_addr, child_mode in fa.direct_calls:
            child = (child_addr, child_mode)

            if child_addr in TARGETS:
                reached_targets[child_addr].append(child)

            if not aud.image_for(child_addr):
                continue

            if child not in parent and child not in root_of:
                parent[child] = (key, site)
                root_of[child] = root_of.get(key, ("UNKNOWN", site, child_addr, child_mode))

            if child not in cache:
                queue.append(child)

    print(f"functions processed = {processed}")
    print(f"functions cached    = {len(cache)}")
    print(f"queue residual      = {len(queue)}")
    print(f"truncated functions = {len(truncated_funcs)}")
    print(f"indirect sites      = {len(indirect_sites)}")

    if processed >= args.max_functions and queue:
        print("CALLGRAPH STATUS = ABORTED BY --max-functions")
    else:
        print("CALLGRAPH STATUS = FINITE DIRECT CLOSURE REACHED")

    hdr("E. REACHABILITY TO FILTER MUTATION / PREDICATE TARGETS")
    for addr, name in TARGETS.items():
        # A target may be reached through veneer normalization so inspect cache too.
        keys = [k for k in cache if k[0] == addr]
        print(f"{name:18s} 0x{addr:08X}: {'REACHABLE' if keys else 'NOT REACHED'}")
        for key in keys[:10]:
            path = reconstruct_path(key, parent)
            print("  path:")
            for idx, (node, callsite_from_prev) in enumerate(path):
                a, m = node
                if idx == 0:
                    print(f"    ROOT 0x{a:08X} [{m}]")
                else:
                    print(f"      via callsite 0x{callsite_from_prev:08X} -> 0x{a:08X} [{m}]")

    # Effective target aliases: veneer calls normalize directly to impl.
    for addr, name in [(SET_IMPL, "SET_IMPL"), (CLEAR_IMPL, "CLEAR_IMPL"), (PRED_IMPL, "FILTER_PREDICATE")]:
        keys = [k for k in cache if k[0] == addr]
        if keys:
            print(f"effective {name} functions in closure = {len(keys)}")

    hdr("F. RESIDUAL INDIRECT CONTROL TRANSFERS / PROVENANCE")
    unresolved_indirect = 0
    filter_indirect = 0
    provenance_counts = defaultdict(int)
    provenance_examples = defaultdict(list)
    resolved_indirects = []

    for (owner_key, site, reg, resolved) in sorted(indirect_sites, key=lambda x: (x[0][0], x[1])):
        fa = cache[owner_key]

        if resolved is not None:
            rt, rm, src = resolved
            cls = "PC_LITERAL"
            provenance_counts[cls] += 1
            resolved_indirects.append((owner_key, site, rt, rm, src, cls))
            if rt in TARGETS:
                filter_indirect += 1
            if len(provenance_examples[cls]) < 12:
                provenance_examples[cls].append((owner_key, site, rt, rm, src))
            continue

        cls, rt, rm, src = aud.indirect_provenance(fa, site, reg)
        provenance_counts[cls] += 1

        if rt is not None:
            resolved_indirects.append((owner_key, site, rt, rm, src, cls))
            if rt in TARGETS:
                filter_indirect += 1
        else:
            unresolved_indirect += 1

        if len(provenance_examples[cls]) < 12:
            provenance_examples[cls].append((owner_key, site, rt, rm, src))

    print(f"residual indirect sites = {len(indirect_sites)}")
    print(f"exactly/locally resolved = {len(indirect_sites) - unresolved_indirect}")
    print(f"still unresolved         = {unresolved_indirect}")
    print(f"filter-target resolutions= {filter_indirect}")
    print()
    print("Provenance classes:")
    for cls, count in sorted(provenance_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {count:4d}  {cls}")

    print()
    print("Representative sites by provenance:")
    for cls in sorted(provenance_examples):
        print()
        print(f"[{cls}]")
        for owner_key, site, rt, rm, src in provenance_examples[cls]:
            owner_addr, owner_mode = owner_key
            tail = ""
            if rt is not None:
                tail = f" -> 0x{rt:08X}[{rm}]"
                if rt in TARGETS:
                    tail += f" <{TARGETS[rt]}>"
            if src is not None:
                tail += f" source=0x{src:08X}"
            print(f"  owner=0x{owner_addr:08X}[{owner_mode}] site=0x{site:08X}{tail}")

    hdr("G. RAW POINTER CENSUS TO FILTER TARGETS")
    pointer_hits_total = 0
    for addr, name in TARGETS.items():
        hits = ptr_occurrences(images, addr)
        pointer_hits_total += len(hits)
        print()
        print(f"{name} 0x{addr:08X}: pointer occurrences={len(hits)}")
        for img_name, paddr, kind in hits[:80]:
            reachable_owner = None
            # Mark if pointer is physically inside a reachable function body.
            for key, fa in cache.items():
                if paddr in fa.visited or (fa.entry <= paddr < fa.entry + 0x1800):
                    if aud.image_for(paddr) and aud.image_for(paddr).name == fa.image:
                        # Avoid overclaiming; only exact literal_addr refs are stronger.
                        pass
            print(f"  {img_name:12s} 0x{paddr:08X} {kind}")

    hdr("H. REACHABLE FUNCTIONS CONTAINING EXACT FILTER POINTER LITERALS")
    literal_refs = []
    filter_values = set(TARGETS.keys()) | {x | 1 for x in TARGETS.keys()}

    for key, fa in cache.items():
        for ins in fa.visited.values():
            if ins.literal_value is not None and (ins.literal_value & 0xFFFFFFFF) in filter_values:
                literal_refs.append((key, ins.addr, ins.literal_value))

    if not literal_refs:
        print("<none>")
    else:
        for (owner_addr, owner_mode), site, value in sorted(literal_refs):
            print(
                f"owner=0x{owner_addr:08X}[{owner_mode}] "
                f"site=0x{site:08X} literal=0x{value:08X}"
            )


    hdr("I. FILTER INBOUND-SURFACE / ADDRESS-CONSTRUCTION AUDIT")
    filter_values = set(TARGETS.keys())
    filter_values.update({SET_IMPL | 1, CLEAR_IMPL | 1, PRED_IMPL | 1})
    pointer_word_addrs = {0x102FD050, 0x102FD058, 0x102FC298}

    # References to the ALICE import-literal WORD ADDRESSES, not only their values.
    pointer_word_refs = []
    for key, fa in cache.items():
        for ins in fa.visited.values():
            if ins.literal_value is not None and (ins.literal_value & 0xFFFFFFFF) in pointer_word_addrs:
                pointer_word_refs.append((key, ins.addr, ins.literal_value))

    mov_pair_hits = aud.reachable_movw_movt_filter_constructions(cache, filter_values)

    print(f"reachable refs to pointer-word addresses = {len(pointer_word_refs)}")
    for (owner_addr, owner_mode), site, value in sorted(pointer_word_refs):
        print(
            f"  owner=0x{owner_addr:08X}[{owner_mode}] "
            f"site=0x{site:08X} literal=0x{value:08X}"
        )

    print(f"reachable MOVW/MOVT filter constructions = {len(mov_pair_hits)}")
    for (owner_addr, owner_mode), site, value in sorted(mov_pair_hits):
        print(
            f"  owner=0x{owner_addr:08X}[{owner_mode}] "
            f"movt_site=0x{site:08X} value=0x{value:08X}"
        )

    # Which resolved indirects actually land on filter targets?
    resolved_filter_indirects = [
        x for x in resolved_indirects if x[2] in TARGETS
    ]
    print(f"resolved indirects landing on filter targets = {len(resolved_filter_indirects)}")
    for owner_key, site, rt, rm, src, cls in resolved_filter_indirects:
        print(
            f"  owner=0x{owner_key[0]:08X}[{owner_key[1]}] "
            f"site=0x{site:08X} -> 0x{rt:08X}[{rm}] "
            f"class={cls} source={('0x%08X' % src) if src is not None else 'UNKNOWN'}"
        )

    hdr("J. CLOSURE DECISION")
    mutation_reached = any(k[0] in {SET_IMPL, CLEAR_IMPL, SET_VENEER, CLEAR_VENEER} for k in cache)
    predicate_reached = any(k[0] == PRED_IMPL for k in cache)

    print(f"direct closure complete               = {'YES' if not queue else 'NO'}")
    print(f"SET/CLEAR direct reachability         = {'FOUND' if mutation_reached else 'NOT FOUND'}")
    print(f"predicate direct reachability         = {'FOUND' if predicate_reached else 'NOT FOUND'}")
    print(f"residual genuine indirect sites       = {len(indirect_sites)}")
    print(f"still-unresolved indirect sites        = {unresolved_indirect}")
    print(f"filter-target indirect resolutions     = {filter_indirect}")
    print(f"reachable exact filter pointer literals= {len(literal_refs)}")
    print(f"reachable pointer-word address refs    = {len(pointer_word_refs)}")
    print(f"reachable MOVW/MOVT filter constructors= {len(mov_pair_hits)}")
    print()
    print("Interpretation rule:")
    print("  - Conditional BX<cond> LR returns are excluded from the indirect count.")
    print("  - If direct closure is complete; SET/CLEAR is not reached; no indirect")
    print("    resolves to a filter target; no reachable exact filter pointer, pointer-word")
    print("    address, or MOVW/MOVT constructor exists; then all STATIC address-supply")
    print("    routes identified by this model are closed.")
    print("  - Residual MEMORY_LOAD / ARG_OR_LIVEIN callbacks remain dynamic qualification")
    print("    unless their source tables/registration paths are independently bounded.")
    print("  - Do not infer raw B709 membership here; this script only closes filter state.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
