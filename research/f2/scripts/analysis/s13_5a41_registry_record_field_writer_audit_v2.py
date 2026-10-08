#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.41 v2 - REGISTRY RECORD FIELD WRITER / ADD-CHILD AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no write / erase
- no phone access

Background
----------
A.40 proved that all A.39 "mutator candidates" were actually readers /
materializers writing into caller-provided output buffers.

Known F007F044 registry read layout:
    record stride      = 0x10
    record +0x00       participates in parent lookup
    record +0x02       raw child count
    record +0x0C       raw child-array pointer

A.41 pivots from registry READERS to registry WRITERS.

It searches for:
  1. direct writes to globals F007F044/F048/F04C;
  2. functions writing record fields +0x00 / +0x02 / +0x0C;
  3. "add-child" shapes:
       load child-array pointer from record+0x0C
       load/update child count at record+0x02
       store a child u16 into the child array
       store updated count back to record+0x02
  4. record constructors that initialize +0x02 and +0x0C together;
  5. callers / constant arguments for proven writer candidates.

No function is promoted automatically.
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

TITLE = "S13.5A.41 v2 - REGISTRY RECORD FIELD WRITER / ADD-CHILD AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

REG_BASE_GLOBAL = 0xF007F044
REG_AUX_GLOBAL = 0xF007F048
REG_BOUND_GLOBAL = 0xF007F04C

ID_TO_DENSE = 0xF02E01B0
CHILD_AT_INDEX = 0xF02D8178
CHILD_COUNT = 0xF02D8870
GET_PARENT_ID = 0xF02FBC24
INDEX_TO_ID = 0xF02FEFB4

KNOWN_READERS = [
    (ID_TO_DENSE, "ID_TO_DENSE"),
    (CHILD_AT_INDEX, "CHILD_AT_INDEX"),
    (CHILD_COUNT, "CHILD_COUNT"),
    (GET_PARENT_ID, "GET_PARENT_ID"),
    (INDEX_TO_ID, "INDEX_TO_ID"),
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
    target: Optional[int] = None
    is_call: bool = False
    is_jump: bool = False
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None

    @property
    def text(self) -> str:
        return f"{self.mnemonic:<9} {self.op_str}".rstrip()


@dataclass
class MemAccess:
    addr: int
    mnemonic: str
    is_store: bool
    is_load: bool
    width: str
    value_reg: Optional[int]
    base_reg: Optional[int]
    index_reg: Optional[int]
    disp: int
    text: str


@dataclass
class FunctionAudit:
    entry: int
    image: str
    visited: Dict[int, Insn] = field(default_factory=dict)
    calls: List[Tuple[int, int]] = field(default_factory=list)
    accesses: List[MemAccess] = field(default_factory=list)
    truncated: bool = False


@dataclass
class Call:
    image: str
    site: int
    target: int
    veneer: Optional[int]


class Auditor:
    def __init__(self, images: List[Image]):
        self.images = images
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True
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

    def normalize_target(self, target: int) -> Tuple[int, Optional[int]]:
        t = target & ~1
        vt = self.raw_arm_veneer_target(t)
        if vt is not None:
            return vt & ~1, t
        return t, None

    def decode_one(self, addr: int) -> Optional[Insn]:
        addr &= ~1
        img = self.image_for(addr)
        if not img or not img.contains(addr, 2):
            return None
        width = min(4, img.end - addr)
        ds = list(self.thumb.disasm(img.read(addr, width), addr, count=1))
        if not ds:
            return None
        ci = ds[0]

        is_call = bool(ci.group(CS_GRP_CALL))
        is_jump = bool(ci.group(CS_GRP_JUMP))
        target = None
        if (is_call or is_jump) and ci.operands and ci.operands[0].type == CS_OP_IMM:
            target = int(ci.operands[0].imm) & 0xFFFFFFFF

        literal_addr = None
        literal_value = None
        if ci.mnemonic.lower().startswith("ldr") and len(ci.operands) >= 2:
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

    def cs_one(self, addr: int):
        img = self.image_for(addr)
        if not img:
            return None
        width = min(4, img.end - addr)
        ds = list(self.thumb.disasm(img.read(addr, width), addr, count=1))
        return ds[0] if ds else None

    @staticmethod
    def is_return(ins: Insn) -> bool:
        m = ins.mnemonic.lower()
        o = ins.op_str.lower().replace(" ", "")
        if m.startswith("bx") and not m.startswith("blx") and o == "lr":
            return True
        if m == "pop" and "pc" in o:
            return True
        return False

    @staticmethod
    def is_unconditional_branch(ins: Insn) -> bool:
        return ins.mnemonic.lower() in {"b", "b.w", "bx"}

    def mem_access(self, addr: int) -> Optional[MemAccess]:
        ins = self.decode_one(addr)
        ci = self.cs_one(addr)
        if ins is None or ci is None:
            return None

        m = ci.mnemonic.lower()
        is_store = m.startswith("str")
        is_load = m.startswith("ldr")
        if not (is_store or is_load):
            return None

        memops = [op for op in ci.operands if op.type == CS_OP_MEM]
        if not memops:
            return None
        mem = memops[0].mem

        value_reg = None
        if ci.operands and ci.operands[0].type == CS_OP_REG:
            value_reg = int(ci.operands[0].reg)

        if m.startswith(("strb", "ldrb")):
            width = "u8"
        elif m.startswith(("strh", "ldrh")):
            width = "u16"
        else:
            width = "u32"

        return MemAccess(
            addr=addr,
            mnemonic=m,
            is_store=is_store,
            is_load=is_load,
            width=width,
            value_reg=value_reg,
            base_reg=int(mem.base) if mem.base else None,
            index_reg=int(mem.index) if mem.index else None,
            disp=int(mem.disp),
            text=ins.text,
        )

    def audit_function(self, entry: int, max_span: int = 0x240) -> FunctionAudit:
        entry &= ~1
        img = self.image_for(entry)
        fa = FunctionAudit(entry=entry, image=img.name if img else "OUTSIDE")
        if not img:
            return fa

        lo = entry
        hi = min(img.end, entry + max_span)
        q = deque([entry])
        seen: Set[int] = set()

        while q and len(seen) < 1200:
            a = q.popleft() & ~1
            if a in seen:
                continue
            if a < lo or a >= hi:
                fa.truncated = True
                continue

            ins = self.decode_one(a)
            if not ins:
                continue
            seen.add(a)
            fa.visited[a] = ins

            ma = self.mem_access(a)
            if ma:
                fa.accesses.append(ma)

            if ins.is_call:
                if ins.target is not None:
                    eff, _ = self.normalize_target(ins.target)
                    fa.calls.append((a, eff))
                q.append(a + ins.size)
                continue

            if self.is_return(ins):
                continue

            if ins.is_jump:
                if ins.target is not None:
                    t = ins.target & ~1
                    if lo <= t < hi:
                        q.append(t)
                if not self.is_unconditional_branch(ins):
                    q.append(a + ins.size)
                continue

            q.append(a + ins.size)

        if q:
            fa.truncated = True
        return fa

    def plausible_function_start(self, site: int, back: int = 0x180) -> int:
        img = self.image_for(site)
        if not img:
            return site & ~1
        lo = max(img.base, site - back) & ~1
        best = None
        a = lo
        while a <= site:
            ins = self.decode_one(a)
            if ins:
                if ins.mnemonic.lower() == "push" and "lr" in ins.op_str.lower():
                    best = a
                a += ins.size
            else:
                a += 2
        return best if best is not None else (site & ~1)

    def build_call_index(self) -> None:
        hdr("B. ONE-TIME DIRECT CALL INDEX")
        for img in self.images:
            print(f"Indexing {img.name} ...", flush=True)
            data = img.data
            for off in range(0, len(data) - 3, 2):
                h1 = struct.unpack_from("<H", data, off)[0]
                h2 = struct.unpack_from("<H", data, off + 2)[0]
                if (h1 & 0xF800) != 0xF000 or (h2 & 0xC000) != 0xC000:
                    continue
                site = img.base + off
                ins = self.decode_one(site)
                if not ins or not ins.is_call or ins.target is None:
                    continue
                eff, veneer = self.normalize_target(ins.target)
                self.calls_by_target[eff].append(
                    Call(img.name, site, eff, veneer)
                )

        for target in list(self.calls_by_target):
            uniq = {}
            for c in self.calls_by_target[target]:
                uniq[(c.image, c.site)] = c
            self.calls_by_target[target] = sorted(
                uniq.values(), key=lambda x: (x.image, x.site)
            )

        print(f"Indexed target buckets = {len(self.calls_by_target)}", flush=True)

    def literal_occurrences(self, value: int) -> List[Tuple[Image, int]]:
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

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str, int, int]]:
        out = set()
        for img, lit_addr in self.literal_occurrences(value):
            lo = max(img.base, lit_addr - 0x1100) & ~1
            for a in range(lo, lit_addr, 2):
                ins = self.decode_one(a)
                if ins and ins.literal_addr == lit_addr and ins.literal_value == value:
                    out.add((img.name, a, lit_addr))
        return sorted(out)

    def scan_store_candidates(self) -> List[int]:
        """
        Raw prefilter + Capstone validation. Returns store sites with record-like
        displacement 0 / 2 / 0xC or indexed halfword stores (possible child append).
        """
        sites = set()
        for img in self.images:
            print(f"Scanning record-like stores: {img.name} ...", flush=True)
            data = img.data
            for off in range(0, len(data) - 3, 2):
                h = struct.unpack_from("<H", data, off)[0]

                # Common Thumb16 load/store families + Thumb32 F8xx.
                possible = (
                    (h & 0xF000) in {0x5000, 0x6000, 0x7000, 0x8000, 0x9000}
                    or (h & 0xF800) == 0xF800
                )
                if not possible:
                    continue

                site = img.base + off
                ma = self.mem_access(site)
                if not ma or not ma.is_store:
                    continue

                if ma.disp in {0, 2, 0xC} or (
                    ma.width == "u16" and ma.index_reg is not None
                ):
                    sites.add(site)

        return sorted(sites)

    def trace_reg_origin(self, fa: FunctionAudit, before: int, reg: int, depth: int = 0, seen=None) -> str:
        if seen is None:
            seen = set()
        key = (before, reg)
        if key in seen or depth > 6:
            return "UNKNOWN"
        seen.add(key)

        rname = self.thumb.reg_name(reg)
        addrs = [a for a in sorted(fa.visited) if before - 0x90 <= a < before]
        for a in reversed(addrs):
            ins = fa.visited[a]
            if ins.is_call or ins.is_jump:
                break
            ci = self.cs_one(a)
            if ci is None or not ci.operands:
                continue
            op0 = ci.operands[0]
            if op0.type != CS_OP_REG or int(op0.reg) != reg:
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
                return f"PC_LITERAL(0x{ins.literal_value:08X}{tag})@0x{a:08X}"

            if m.startswith("ldr") and len(ci.operands) >= 2 and ci.operands[1].type == CS_OP_MEM:
                mem = ci.operands[1].mem
                b = self.thumb.reg_name(mem.base) if mem.base else "none"
                ix = self.thumb.reg_name(mem.index) if mem.index else ""
                return f"LOAD_MEM(base={b},index={ix},disp={int(mem.disp):+#x})@0x{a:08X}"

            if m in {"mov", "movs", "mov.w"} and len(ci.operands) >= 2:
                src = ci.operands[1]
                if src.type == CS_OP_REG:
                    sub = self.trace_reg_origin(fa, a, int(src.reg), depth + 1, seen)
                    return f"MOV({self.thumb.reg_name(src.reg)}<-{sub})@0x{a:08X}"
                if src.type == CS_OP_IMM:
                    return f"IMM(0x{int(src.imm)&0xFFFFFFFF:X})@0x{a:08X}"

            if m.startswith(("add", "sub")):
                parts = []
                for op in ci.operands[1:]:
                    if op.type == CS_OP_REG:
                        parts.append(self.thumb.reg_name(op.reg))
                    elif op.type == CS_OP_IMM:
                        parts.append(f"#{int(op.imm):#x}")
                return f"{m.upper()}({','.join(parts)})@0x{a:08X}"

            if m.startswith(("lsl", "lsr", "and", "orr", "eor", "bic")):
                return f"{m.upper()}_DERIVED@0x{a:08X}"

            return f"WRITE_BY_{m.upper()}@0x{a:08X}"

        if rname in {"r0", "r1", "r2", "r3"}:
            return f"ARG({rname})"
        if rname == "sp":
            return "STACK_POINTER"
        return f"LIVEIN({rname})"

    def caller_constants(self, site: int, back: int = 0x60) -> Dict[str, str]:
        img = self.image_for(site)
        if not img:
            return {}
        lo = max(img.base, site - back) & ~1
        decoded = []
        a = lo
        while a < site:
            ins = self.decode_one(a)
            if ins:
                decoded.append(ins)
                a += ins.size
            else:
                a += 2

        cut = 0
        for i, ins in enumerate(decoded):
            if ins.is_call or ins.is_jump:
                cut = i + 1
        decoded = decoded[cut:]

        state: Dict[str, str] = {}
        for ins in decoded:
            ci = self.cs_one(ins.addr)
            if ci is None or not ci.operands or ci.operands[0].type != CS_OP_REG:
                continue
            dst = self.thumb.reg_name(ci.operands[0].reg).lower()
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
                    src = self.thumb.reg_name(op.reg).lower()
                    state[dst] = state.get(src, src)
                else:
                    state.pop(dst, None)
                continue

            if m.startswith("add") and len(ci.operands) >= 2:
                regs = [op for op in ci.operands[1:] if op.type == CS_OP_REG]
                imms = [op for op in ci.operands[1:] if op.type == CS_OP_IMM]
                if regs:
                    src = self.thumb.reg_name(regs[0].reg).lower()
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


def print_function(aud: Auditor, fa: FunctionAudit, max_lines: int = 180) -> None:
    print(
        f"owner=0x{fa.entry:08X} image={fa.image} reachable={len(fa.visited)} "
        f"calls={len(fa.calls)} mem_accesses={len(fa.accesses)} truncated={fa.truncated}"
    )
    n = 0
    for addr in sorted(fa.visited):
        if n >= max_lines:
            print("  ... truncated listing ...")
            break
        ins = fa.visited[addr]
        tags = []

        ma = next((x for x in fa.accesses if x.addr == addr), None)
        if ma:
            kind = "STORE" if ma.is_store else "LOAD"
            tags.append(
                f"{kind}:{ma.width}:disp={ma.disp:+#x}"
                + (":indexed" if ma.index_reg is not None else "")
            )

        if ins.literal_value in {REG_BASE_GLOBAL, REG_AUX_GLOBAL, REG_BOUND_GLOBAL}:
            tags.append(f"GLOBAL_LITERAL=0x{ins.literal_value:08X}")

        if ins.target is not None and ins.is_call:
            eff, veneer = aud.normalize_target(ins.target)
            text = f"CALL=0x{eff:08X}"
            if veneer is not None:
                text += f" via=0x{veneer:08X}"
            tags.append(text)

        suffix = " ; " + " | ".join(tags) if tags else ""
        print(f"  0x{addr:08X}: {ins.text}{suffix}")
        n += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
    ap.add_argument("--max-candidates", type=int, default=80)
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
        Image("ALICE", ad, ALICE_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
    ])

    aud.build_call_index()

    hdr("C. KNOWN REGISTRY READER LAYOUT ANCHORS")
    for entry, name in KNOWN_READERS:
        fa = aud.audit_function(entry, max_span=0x180)
        print()
        print(f"[{name}]")
        print_function(aud, fa, max_lines=100)

    hdr("D. DIRECT WRITES TO REGISTRY GLOBAL VARIABLES")
    global_write_hits = []
    for gaddr, gname in [
        (REG_BASE_GLOBAL, "REG_BASE_GLOBAL"),
        (REG_AUX_GLOBAL, "REG_AUX_GLOBAL"),
        (REG_BOUND_GLOBAL, "REG_BOUND_GLOBAL"),
    ]:
        xrefs = aud.exact_literal_xrefs(gaddr)
        print()
        print(f"{gname} 0x{gaddr:08X}: exact literal xrefs={len(xrefs)}")

        for img_name, site, lit_addr in xrefs:
            owner = aud.plausible_function_start(site)
            fa = aud.audit_function(owner, max_span=0x240)
            ci = aud.cs_one(site)
            if ci is None or not ci.operands or ci.operands[0].type != CS_OP_REG:
                continue
            loaded_reg = int(ci.operands[0].reg)
            loaded_name = aud.thumb.reg_name(loaded_reg)

            # Look forward for a STORE using the register loaded with the global address as base.
            writes = []
            for ma in fa.accesses:
                if ma.addr <= site or ma.addr > site + 0x80:
                    continue
                if ma.is_store and ma.base_reg == loaded_reg and ma.disp == 0:
                    writes.append(ma)

            status = "WRITE" if writes else "READ/ADDRESS_USE"
            print(
                f"  {img_name:8s} site=0x{site:08X} owner=0x{owner:08X} "
                f"loaded_reg={loaded_name} => {status}"
            )
            for ma in writes:
                global_write_hits.append((gaddr, owner, ma.addr))
                print(f"    STORE 0x{ma.addr:08X}: {ma.text}")

    hdr("E. RECORD-LIKE STORE SCAN / OWNER RANKING")
    store_sites = aud.scan_store_candidates()
    owners: Dict[int, Set[int]] = defaultdict(set)
    for site in store_sites:
        owners[aud.plausible_function_start(site)].add(site)

    ranked = []
    for owner, sites in owners.items():
        fa = aud.audit_function(owner, max_span=0x300)

        stores = [x for x in fa.accesses if x.is_store]
        loads = [x for x in fa.accesses if x.is_load]

        s0 = [x for x in stores if x.disp == 0]
        s2 = [x for x in stores if x.disp == 2]
        sc = [x for x in stores if x.disp == 0xC]
        l2 = [x for x in loads if x.disp == 2]
        lc = [x for x in loads if x.disp == 0xC]
        indexed_half_stores = [
            x for x in stores if x.width == "u16" and x.index_reg is not None
        ]

        literal_vals = {
            ins.literal_value for ins in fa.visited.values()
            if ins.literal_value is not None
        }
        calls_dense = any(t == ID_TO_DENSE for _, t in fa.calls)
        calls_known_reader = any(
            t in {ID_TO_DENSE, CHILD_AT_INDEX, CHILD_COUNT, GET_PARENT_ID, INDEX_TO_ID}
            for _, t in fa.calls
        )

        # Strong signatures.
        constructor_like = bool(s2 and sc)
        add_child_like = bool(lc and l2 and s2 and indexed_half_stores)
        count_mutator_like = bool(lc and s2 and indexed_half_stores)
        reg_global = REG_BASE_GLOBAL in literal_vals

        score = 0
        score += 10 if constructor_like else 0
        score += 12 if add_child_like else 0
        score += 6 if count_mutator_like else 0
        score += 4 if reg_global else 0
        score += 3 if calls_dense else 0
        score += 1 if calls_known_reader else 0
        score += min(3, len(sc))
        score += min(3, len(s2))

        if score <= 0:
            continue

        ranked.append(
            (
                score,
                owner,
                fa,
                constructor_like,
                add_child_like,
                count_mutator_like,
                reg_global,
                s0,
                s2,
                sc,
                l2,
                lc,
                indexed_half_stores,
            )
        )

    ranked.sort(key=lambda x: (-x[0], x[1]))
    ranked = ranked[:args.max_candidates]

    print(f"raw store sites considered = {len(store_sites)}")
    print(f"ranked owner candidates    = {len(ranked)}")

    for row in ranked:
        (
            score, owner, fa, constructor_like, add_child_like,
            count_mutator_like, reg_global, s0, s2, sc, l2, lc,
            indexed_half_stores
        ) = row

        print()
        priority = " <TOP_A41_V1_CANDIDATE>" if owner == 0xF02E36AE else ""
        print(
            f"CANDIDATE 0x{owner:08X} image={fa.image} score={score} "
            f"constructor_like={constructor_like} add_child_like={add_child_like} "
            f"count_mutator_like={count_mutator_like} reg_global={reg_global}"
            + priority
        )
        print(
            f"  stores: +0={len(s0)} +2={len(s2)} +C={len(sc)} "
            f"loads: +2={len(l2)} +C={len(lc)} indexed_u16_stores={len(indexed_half_stores)}"
        )

        interesting_accesses = {}
        for ma in (s0 + s2 + sc + l2 + lc + indexed_half_stores):
            # MemAccess is intentionally mutable/unhashable; de-duplicate by
            # instruction address instead of set(MemAccess).
            interesting_accesses[ma.addr] = ma

        for ma in sorted(
            interesting_accesses.values(),
            key=lambda x: x.addr
        ):
            kind = "STORE" if ma.is_store else "LOAD"
            print(
                f"  {kind} 0x{ma.addr:08X}: {ma.text} "
                f"width={ma.width} disp={ma.disp:+#x}"
            )
            if ma.base_reg is not None:
                print(
                    f"    base {aud.thumb.reg_name(ma.base_reg)} <- "
                    + aud.trace_reg_origin(fa, ma.addr, ma.base_reg)
                )
            if ma.index_reg is not None:
                print(
                    f"    index {aud.thumb.reg_name(ma.index_reg)} <- "
                    + aud.trace_reg_origin(fa, ma.addr, ma.index_reg)
                )
            if ma.value_reg is not None:
                print(
                    f"    value {aud.thumb.reg_name(ma.value_reg)} <- "
                    + aud.trace_reg_origin(fa, ma.addr, ma.value_reg)
                )

        print("  body:")
        print_function(aud, fa, max_lines=140)

    hdr("E2. PRIORITY CANDIDATE SUMMARY")
    priority_rows = [row for row in ranked if row[1] == 0xF02E36AE]
    if not priority_rows:
        print("0xF02E36AE was not retained in the ranked candidate set.")
    else:
        row = priority_rows[0]
        score, owner, fa, constructor_like, add_child_like, count_mutator_like, reg_global, s0, s2, sc, l2, lc, indexed_half_stores = row
        print(f"owner=0x{owner:08X} score={score}")
        print(f"constructor_like={constructor_like}")
        print(f"add_child_like={add_child_like}")
        print(f"count_mutator_like={count_mutator_like}")
        print(f"reg_global={reg_global}")
        print(f"stores +0={len(s0)} +2={len(s2)} +C={len(sc)}")
        print(f"loads  +2={len(l2)} +C={len(lc)}")
        print(f"indexed_u16_stores={len(indexed_half_stores)}")

    hdr("F. DIRECT CALLERS OF TOP WRITER CANDIDATES")
    top_owners = [row[1] for row in ranked if row[0] >= 8][:30]

    for owner in top_owners:
        hits = aud.calls_by_target.get(owner, [])
        print()
        print(f"TARGET 0x{owner:08X}: callers={len(hits)}")
        for c in hits[:120]:
            setup = aud.caller_constants(c.site)
            text = ", ".join(f"{k}={v}" for k, v in sorted(setup.items()))
            via = f" via=0x{c.veneer:08X}" if c.veneer is not None else ""
            print(
                f"  {c.image:8s} 0x{c.site:08X}{via}"
                + (f" ; {text}" if text else "")
            )

    hdr("G. FOCUS-ID PROXIMITY TO TOP WRITER CALLS")
    for owner in top_owners:
        hits = aud.calls_by_target.get(owner, [])
        focus_hits = []
        for c in hits:
            img = aud.image_for(c.site)
            if not img:
                continue
            lo = max(img.base, c.site - 0x60)
            hi = min(img.end, c.site + 0x20)
            blob = img.read(lo, hi - lo)
            for value, name in FOCUS_IDS.items():
                needle = struct.pack("<H", value)
                off = blob.find(needle)
                if off >= 0:
                    focus_hits.append((c.site, value, name, lo + off))
        if focus_hits:
            print(f"writer 0x{owner:08X}:")
            for site, value, name, at in focus_hits:
                print(
                    f"  caller=0x{site:08X} nearby_u16=0x{value:04X}<{name}> at 0x{at:08X}"
                )

    hdr("H. DECISION GATE")
    print(f"direct registry-global writes found = {len(global_write_hits)}")
    print(f"ranked record-writer candidates     = {len(ranked)}")
    print()
    print("Promotion rules:")
    print("  - +0x02/+0x0C layout alone is supporting evidence, not proof.")
    print("  - Highest confidence ADD_CHILD requires the same owner to load child-array")
    print("    pointer (+0x0C), read/update count (+0x02), store child u16 into that")
    print("    array, then write the new count back.")
    print("  - Highest confidence CONSTRUCTOR requires coherent initialization of")
    print("    record+0x02 and record+0x0C with compatible record-base provenance.")
    print("  - Only after writer semantics are proven should B709/8321/8928 caller")
    print("    constants be used to reconstruct hierarchy membership.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
