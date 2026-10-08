#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.40 - REGISTRY CANDIDATE STORE DESTINATION AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no write / erase
- no phone access

Purpose
-------
A.39 v2 found six store-containing functions associated with F007F044 /
ID_TO_DENSE. Two are already classified:

    F02AE864 = filtered child-ID enumeration provider
               (store goes to caller output buffer)
    F02D4D10 = filter SET primitive
               (store goes to filter bitmap)

The four unresolved candidates are:

    F02AE4E4
    F02F5230
    F02F5270
    F03002A0

A.40 prints their exact reachable bodies, all direct callers, local argument
setup, and conservative backward provenance for every store's source/base/index
registers. The two known functions above are included as controls.

No function is promoted to registry mutator automatically.
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

TITLE = "S13.5A.40 - REGISTRY CANDIDATE STORE DESTINATION AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

REG_BASE_GLOBAL = 0xF007F044
REG_AUX_GLOBAL = 0xF007F048
REG_BOUND_GLOBAL = 0xF007F04C
FILTER_BITMAP = 0xF00C1624

ID_TO_DENSE = 0xF02E01B0
FILTER_PREDICATE = 0xF02D5458

TARGETS = [
    (0xF02AE4E4, "UNKNOWN_A"),
    (0xF02F5230, "UNKNOWN_B"),
    (0xF02F5270, "UNKNOWN_C"),
    (0xF03002A0, "UNKNOWN_D"),
]

CONTROLS = [
    (0xF02AE864, "CONTROL_FILTERED_CHILD_ENUM"),
    (0xF02D4D10, "CONTROL_FILTER_SET"),
]

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
    mode: str

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


@dataclass
class Call:
    image: str
    site: int
    mode: str
    effective_target: int
    effective_mode: str
    veneer: Optional[int]


class Auditor:
    def __init__(self, images: List[Image]):
        self.images = images
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True
        self.arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.arm.detail = True
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

    def cs_one(self, addr: int, mode: str):
        img = self.image_for(addr)
        if not img:
            return None
        md = self.thumb if mode == MODE_THUMB else self.arm
        width = min(4, img.end - addr)
        ds = list(md.disasm(img.read(addr, width), addr, count=1))
        return ds[0] if ds else None

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

    def audit_function(self, entry: int, mode: str = MODE_THUMB, max_span: int = 0x180) -> FunctionAudit:
        img = self.image_for(entry)
        fa = FunctionAudit(entry=entry, mode=mode, image=img.name if img else "OUTSIDE")
        if not img:
            return fa

        lo = entry
        hi = min(img.end, entry + max_span)
        q = deque([entry])
        seen: Set[int] = set()

        while q and len(seen) < 800:
            a = q.popleft()
            a &= (~1 if mode == MODE_THUMB else ~3)
            if a in seen:
                continue
            if a < lo or a >= hi:
                fa.truncated = True
                continue

            ins = self.decode_one(a, mode)
            if not ins:
                continue

            seen.add(a)
            fa.visited[a] = ins

            if self.is_store(ins):
                fa.stores.append(a)

            if ins.is_call:
                if ins.target is not None and ins.target_mode is not None:
                    eff, emode, _ = self.normalize_target(ins.target, ins.target_mode)
                    fa.calls.append((a, eff, emode))
                q.append(a + ins.size)
                continue

            if self.is_return(ins):
                continue

            if ins.is_jump:
                if ins.target is not None and ins.target_mode is not None:
                    eff, emode, _ = self.normalize_target(ins.target, ins.target_mode)
                    if emode == mode and lo <= eff < hi:
                        q.append(eff)
                if not self.is_unconditional_branch(ins):
                    q.append(a + ins.size)
                continue

            q.append(a + ins.size)

        if q:
            fa.truncated = True
        return fa

    def build_call_index(self) -> None:
        hdr("B. ONE-TIME DIRECT CALL INDEX")
        for img in self.images:
            print(f"Indexing {img.name} ({img.mode}) ...", flush=True)
            if img.mode == MODE_THUMB:
                for off in range(0, len(img.data) - 3, 2):
                    h1 = struct.unpack_from("<H", img.data, off)[0]
                    h2 = struct.unpack_from("<H", img.data, off + 2)[0]
                    if (h1 & 0xF800) != 0xF000 or (h2 & 0xC000) != 0xC000:
                        continue
                    site = img.base + off
                    ins = self.decode_one(site, MODE_THUMB)
                    if not ins or not ins.is_call or ins.target is None or ins.target_mode is None:
                        continue
                    eff, emode, veneer = self.normalize_target(ins.target, ins.target_mode)
                    self.calls_by_target[eff].append(
                        Call(img.name, site, MODE_THUMB, eff, emode, veneer)
                    )
            else:
                for off in range(0, len(img.data) - 3, 4):
                    word = struct.unpack_from("<I", img.data, off)[0]
                    if (word & 0x0F000000) != 0x0B000000 and (word & 0xFE000000) != 0xFA000000:
                        continue
                    site = img.base + off
                    ins = self.decode_one(site, MODE_ARM)
                    if not ins or not ins.is_call or ins.target is None or ins.target_mode is None:
                        continue
                    eff, emode, veneer = self.normalize_target(ins.target, ins.target_mode)
                    self.calls_by_target[eff].append(
                        Call(img.name, site, MODE_ARM, eff, emode, veneer)
                    )

        for k in list(self.calls_by_target):
            uniq = {}
            for c in self.calls_by_target[k]:
                uniq[(c.image, c.site, c.mode)] = c
            self.calls_by_target[k] = sorted(uniq.values(), key=lambda x: (x.image, x.site))

        print(
            "Indexed target buckets = "
            + str(len(self.calls_by_target)),
            flush=True,
        )

    def local_block_before(self, site: int, mode: str, back: int = 0x50) -> List[Insn]:
        img = self.image_for(site)
        if not img:
            return []
        align = 2 if mode == MODE_THUMB else 4
        lo = max(img.base, site - back)
        lo -= lo % align
        insns = []
        a = lo
        while a < site:
            ins = self.decode_one(a, mode)
            if ins:
                insns.append(ins)
                a += ins.size if mode == MODE_THUMB else 4
            else:
                a += align

        cut = 0
        for i, ins in enumerate(insns):
            if ins.is_call or ins.is_jump:
                cut = i + 1
        return insns[cut:]

    def trace_reg_origin(
        self,
        fa: FunctionAudit,
        before_site: int,
        reg_id: int,
        depth: int = 0,
        seen: Optional[Set[Tuple[int, int]]] = None,
    ) -> str:
        """
        Conservative backward trace inside reachable instructions.
        Designed for store address/value diagnosis, not full emulation.
        """
        if seen is None:
            seen = set()
        key = (before_site, reg_id)
        if key in seen or depth > 6:
            return "UNKNOWN"
        seen.add(key)

        md = self.thumb if fa.mode == MODE_THUMB else self.arm
        rname = md.reg_name(reg_id)

        # If never locally written, r0-r3 are function args.
        addrs = [a for a in sorted(fa.visited) if a < before_site and a >= before_site - 0x80]
        for addr in reversed(addrs):
            ins = fa.visited[addr]
            if ins.is_call or ins.is_jump:
                # Do not cross a control-flow edge blindly.
                break

            ci = self.cs_one(addr, fa.mode)
            if ci is None or not ci.operands:
                continue
            op0 = ci.operands[0]
            if op0.type != CS_OP_REG or int(op0.reg) != reg_id:
                continue

            m = ci.mnemonic.lower()

            if m.startswith("ldr") and ins.literal_value is not None:
                tag = ""
                if ins.literal_value == REG_BASE_GLOBAL:
                    tag = "<REG_BASE_GLOBAL>"
                elif ins.literal_value == REG_AUX_GLOBAL:
                    tag = "<REG_AUX_GLOBAL>"
                elif ins.literal_value == REG_BOUND_GLOBAL:
                    tag = "<REG_BOUND_GLOBAL>"
                elif ins.literal_value == FILTER_BITMAP:
                    tag = "<FILTER_BITMAP>"
                return f"PC_LITERAL(0x{ins.literal_value:08X}{tag})@0x{addr:08X}"

            if m.startswith("ldr") and len(ci.operands) >= 2 and ci.operands[1].type == CS_OP_MEM:
                mem = ci.operands[1].mem
                b = md.reg_name(mem.base) if mem.base else "none"
                idx = md.reg_name(mem.index) if mem.index else ""
                disp = int(mem.disp)
                return f"LOAD_MEM(base={b},index={idx},disp={disp:+#x})@0x{addr:08X}"

            if m in {"mov", "movs", "mov.w"} and len(ci.operands) >= 2:
                src = ci.operands[1]
                if src.type == CS_OP_REG:
                    sub = self.trace_reg_origin(fa, addr, int(src.reg), depth + 1, seen)
                    return f"MOV({md.reg_name(src.reg)}<-{sub})@0x{addr:08X}"
                if src.type == CS_OP_IMM:
                    return f"IMM(0x{int(src.imm)&0xFFFFFFFF:X})@0x{addr:08X}"

            if m in {"movw", "movt"} and len(ci.operands) >= 2:
                return f"{m.upper()}_CONSTRUCTION@0x{addr:08X}"

            if m.startswith(("add", "sub")):
                parts = []
                for op in ci.operands[1:]:
                    if op.type == CS_OP_REG:
                        parts.append(md.reg_name(op.reg))
                    elif op.type == CS_OP_IMM:
                        parts.append(f"#{int(op.imm):#x}")
                return f"{m.upper()}({','.join(parts)})@0x{addr:08X}"

            if m.startswith(("lsl", "lsr", "and", "orr", "eor", "bic")):
                return f"{m.upper()}_DERIVED@0x{addr:08X}"

            return f"WRITE_BY_{m.upper()}@0x{addr:08X}"

        if rname in {"r0", "r1", "r2", "r3"}:
            return f"ARG({rname})"
        if rname == "sp":
            return "STACK_POINTER"
        return f"LIVEIN({rname})"

    def caller_constants(self, site: int, mode: str) -> Dict[str, str]:
        """
        Human-readable local caller setup, preserving stack-address args.
        """
        block = self.local_block_before(site, mode, 0x60)
        state: Dict[str, str] = {}
        md = self.thumb if mode == MODE_THUMB else self.arm

        for ins in block:
            ci = self.cs_one(ins.addr, mode)
            if ci is None or not ci.operands or ci.operands[0].type != CS_OP_REG:
                continue
            dst = md.reg_name(ci.operands[0].reg).lower()
            if dst not in {"r0", "r1", "r2", "r3"}:
                continue
            m = ci.mnemonic.lower()

            if m.startswith("ldr") and ins.literal_value is not None:
                v = ins.literal_value & 0xFFFFFFFF
                label = ""
                if (v & 0xFFFF) in FOCUS_IDS:
                    label = f"<{FOCUS_IDS[v & 0xFFFF]}>"
                state[dst] = f"0x{v:08X}{label}"
                continue

            if m in {"mov", "movs", "mov.w", "movw"} and len(ci.operands) >= 2:
                op = ci.operands[1]
                if op.type == CS_OP_IMM:
                    state[dst] = f"0x{int(op.imm)&0xFFFFFFFF:X}"
                elif op.type == CS_OP_REG:
                    src = md.reg_name(op.reg).lower()
                    state[dst] = state.get(src, src)
                else:
                    state.pop(dst, None)
                continue

            if m.startswith("add") and len(ci.operands) >= 2:
                # add r1, sp, #4 / add r0, sp, #...
                regs = [op for op in ci.operands[1:] if op.type == CS_OP_REG]
                imms = [op for op in ci.operands[1:] if op.type == CS_OP_IMM]
                if regs:
                    src = md.reg_name(regs[0].reg).lower()
                    imm = int(imms[0].imm) if imms else 0
                    if src == "sp":
                        state[dst] = f"SP{imm:+#x}"
                    elif src in state:
                        state[dst] = f"({state[src]}+{imm:#x})"
                    else:
                        state.pop(dst, None)
                continue

            state.pop(dst, None)

        return state


def load_guard(path: Path, size: int, digest: str, name: str) -> bytes:
    print(f"Loading {name}: {path}", flush=True)
    if not path.is_file():
        raise SystemExit(f"Missing {name}: {path}")
    data = path.read_bytes()
    got = sha256(data)
    ok = len(data) == size and got == digest
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {got}")
    print(f"  guard  = {'PASS' if ok else 'FAIL'}", flush=True)
    if not ok:
        raise SystemExit(f"ABORT: {name} guard failed")
    return data


def print_body(aud: Auditor, entry: int, label: str) -> FunctionAudit:
    fa = aud.audit_function(entry)
    print()
    print(f"{label}: 0x{entry:08X} image={fa.image}")
    print(
        f"  reachable={len(fa.visited)} calls={len(fa.calls)} "
        f"stores={len(fa.stores)} truncated={fa.truncated}"
    )

    for addr in sorted(fa.visited):
        ins = fa.visited[addr]
        ann = []
        if ins.target is not None and ins.target_mode is not None:
            eff, emode, veneer = aud.normalize_target(ins.target, ins.target_mode)
            text = f"target=0x{eff:08X}[{emode}]"
            if veneer is not None:
                text += f" via=0x{veneer:08X}"
            ann.append(text)
        if ins.literal_value is not None:
            extra = ""
            if ins.literal_value == REG_BASE_GLOBAL:
                extra = " REG_BASE_GLOBAL"
            elif ins.literal_value == REG_AUX_GLOBAL:
                extra = " REG_AUX_GLOBAL"
            elif ins.literal_value == REG_BOUND_GLOBAL:
                extra = " REG_BOUND_GLOBAL"
            elif ins.literal_value == FILTER_BITMAP:
                extra = " FILTER_BITMAP"
            elif (ins.literal_value & 0xFFFF) in FOCUS_IDS:
                extra = " " + FOCUS_IDS[ins.literal_value & 0xFFFF]
            ann.append(
                f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}{extra}"
            )
        if addr in fa.stores:
            ann.append("STORE")
        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"    0x{addr:08X}: {ins.text}{suffix}")

    return fa


def print_store_slices(aud: Auditor, fa: FunctionAudit) -> None:
    md = aud.thumb if fa.mode == MODE_THUMB else aud.arm
    if not fa.stores:
        print("  <no stores>")
        return

    for site in fa.stores:
        ci = aud.cs_one(site, fa.mode)
        print()
        print(f"  STORE @ 0x{site:08X}: {fa.visited[site].text}")
        if ci is None:
            continue

        # Store operand 0 is value; memory operand is usually operand 1.
        if ci.operands and ci.operands[0].type == CS_OP_REG:
            reg = int(ci.operands[0].reg)
            print(
                f"    value {md.reg_name(reg)} <- "
                + aud.trace_reg_origin(fa, site, reg)
            )

        memops = [op for op in ci.operands if op.type == CS_OP_MEM]
        if memops:
            mem = memops[0].mem
            if mem.base:
                b = int(mem.base)
                print(
                    f"    base  {md.reg_name(b)} <- "
                    + aud.trace_reg_origin(fa, site, b)
                )
            if mem.index:
                ix = int(mem.index)
                print(
                    f"    index {md.reg_name(ix)} <- "
                    + aud.trace_reg_origin(fa, site, ix)
                )
            if mem.disp:
                print(f"    displacement = {int(mem.disp):+#x}")

        # Nearby exact context.
        lo = max(fa.entry, site - 0x18)
        hi = site + 0x12
        for addr in sorted(a for a in fa.visited if lo <= a < hi):
            mark = ">>>" if addr == site else "   "
            print(f"    {mark} 0x{addr:08X}: {fa.visited[addr].text}")


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
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
    zd = load_guard(Path(args.zimage), ZIMAGE_SIZE, ZIMAGE_SHA256, "ZIMAGE")

    aud = Auditor([
        Image("ALICE", ad, ALICE_BASE, MODE_THUMB),
        Image("ZIMAGE", zd, ZIMAGE_BASE, MODE_THUMB),
    ])

    aud.build_call_index()

    hdr("C. KNOWN CONTROL FUNCTIONS")
    control_fas = {}
    for addr, label in CONTROLS:
        fa = print_body(aud, addr, label)
        control_fas[addr] = fa
        print_store_slices(aud, fa)

    hdr("D. UNRESOLVED CANDIDATE EXACT BODIES")
    target_fas = {}
    for addr, label in TARGETS:
        fa = print_body(aud, addr, label)
        target_fas[addr] = fa
        print_store_slices(aud, fa)

    hdr("E. DIRECT CALLERS / ABI CLUES")
    for addr, label in TARGETS + CONTROLS:
        hits = aud.calls_by_target.get(addr, [])
        print()
        print(f"{label} 0x{addr:08X}: direct callers={len(hits)}")
        for c in hits[:120]:
            setup = aud.caller_constants(c.site, c.mode)
            setup_text = ", ".join(f"{k}={v}" for k, v in sorted(setup.items()))
            via = f" via=0x{c.veneer:08X}" if c.veneer is not None else ""
            print(
                f"  {c.image:8s} 0x{c.site:08X}[{c.mode}]{via}"
                + (f" ; {setup_text}" if setup_text else "")
            )

            # Print focused context only for useful B709/Image/Audio/stack-buffer setups.
            focused = any(
                any(tag in v for tag in ("B709_ROOT", "IMAGE_", "AUDIO_", "SP+"))
                for v in setup.values()
            )
            if focused:
                block = aud.local_block_before(c.site, c.mode, 0x40)
                for ins in block:
                    print(f"      0x{ins.addr:08X}: {ins.text}")
                print(f"    >>> 0x{c.site:08X}: CALL")

    hdr("F. PAIRWISE STRUCTURAL COMPARISON")
    pairs = [
        (0xF02AE4E4, 0xF03002A0),
        (0xF02F5230, 0xF02F5270),
        (0xF02AE4E4, 0xF02AE864),
    ]
    for a, b in pairs:
        fa = target_fas.get(a) or control_fas.get(a)
        fb = target_fas.get(b) or control_fas.get(b)
        if not fa or not fb:
            continue
        seq_a = [(i.mnemonic, re.sub(r"0x[0-9a-fA-F]+", "IMM", i.op_str)) for _, i in sorted(fa.visited.items())]
        seq_b = [(i.mnemonic, re.sub(r"0x[0-9a-fA-F]+", "IMM", i.op_str)) for _, i in sorted(fb.visited.items())]
        same_prefix = 0
        for x, y in zip(seq_a, seq_b):
            if x == y:
                same_prefix += 1
            else:
                break
        print(
            f"0x{a:08X} vs 0x{b:08X}: "
            f"insns={len(seq_a)}/{len(seq_b)} identical_normalized_prefix={same_prefix}"
        )

    hdr("G. DECISION GATE")
    print("Required promotion rule:")
    print("  A candidate becomes a TRUE F007F044 registry mutator only if the store")
    print("  destination base/index is proven to derive from the registry record or")
    print("  child-array backing memory, not from a caller output buffer or unrelated table.")
    print()
    print("Known controls:")
    print("  F02AE864 must remain FILTERED_CHILD_ENUM / output-buffer writer.")
    print("  F02D4D10 must remain FILTER_SET / bitmap writer.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
