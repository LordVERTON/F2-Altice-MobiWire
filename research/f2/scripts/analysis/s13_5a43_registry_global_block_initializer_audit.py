#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.43 - REGISTRY GLOBAL BLOCK INITIALIZER AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no write / erase
- no phone access

Validated input from A.42 v2
----------------------------
The complete ALICE/ZIMAGE code surface rooted at exact F007F044 references is
read-only under the validated provenance model. Therefore the registry's
construction must use another addressing route.

A.43 audits the global block around:
    F007F040 .. F007F060

It detects:
  - PC-relative literal references to the block and nearby aliases;
  - stores through base+offset, e.g. literal F007F040 + STR [rX,#4];
  - MOVW/MOVT construction of addresses in/near the block;
  - interprocedural propagation when a block pointer is passed to a helper;
  - calls (memzero/memcpy/allocator-like or unknown) receiving block pointers;
  - raw U32 occurrences of block addresses that are NOT consumed by code
    literals, as possible init/relocation table evidence.

Images:
  - ALICE
  - BOOT_ZIMAGE
  - ZIMAGE

No patch is generated.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

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

TITLE = "S13.5A.43 - REGISTRY GLOBAL BLOCK INITIALIZER AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

BOOT_BASE = 0xF01F19E4
BOOT_SIZE = 0x4B06C
BOOT_SHA256 = "aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

BLOCK_START = 0xF007F040
BLOCK_END = 0xF007F064       # exclusive; includes word at F007F060
NEAR_START = 0xF007F000
NEAR_END = 0xF007F084        # exclusive

REG_ROOT = 0xF007F040
REG_BASE_GLOBAL = 0xF007F044
REG_AUX_GLOBAL = 0xF007F048
REG_BOUND_GLOBAL = 0xF007F04C

KNOWN_MEMZERO_VENEER = 0xF0210588
KNOWN_MEMZERO_REAL = 0x10018998

KNOWN_OWNER_REGRESSION = {
    0xF02AE868: 0xF02AE864,
    0xF02D8180: 0xF02D8178,
    0xF02D8876: 0xF02D8870,
    0xF02F9D5C: 0xF02F9D34,
    0xF02FBC3A: 0xF02FBC24,
}

FOCUS_WORDS = {
    0xF007F040: "REG_ROOT",
    0xF007F044: "REG_BASE_GLOBAL",
    0xF007F048: "REG_AUX_GLOBAL",
    0xF007F04C: "REG_BOUND_GLOBAL",
    0xF007F050: "BLOCK_+10",
    0xF007F054: "BLOCK_+14",
    0xF007F058: "BLOCK_+18",
    0xF007F05C: "BLOCK_+1C",
    0xF007F060: "BLOCK_+20",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hdr(title: str) -> None:
    print()
    print("=" * 120)
    print(title)
    print("=" * 120, flush=True)


def in_block(addr: int) -> bool:
    return BLOCK_START <= (addr & 0xFFFFFFFF) < BLOCK_END


def near_block(addr: int) -> bool:
    return NEAR_START <= (addr & 0xFFFFFFFF) < NEAR_END


def block_label(addr: int) -> str:
    a = addr & 0xFFFFFFFF
    if a in FOCUS_WORDS:
        return FOCUS_WORDS[a]
    if in_block(a):
        return f"BLOCK+0x{a-BLOCK_START:X}"
    if near_block(a):
        delta = a - BLOCK_START
        return f"NEAR{delta:+#x}"
    return ""


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


@dataclass(frozen=True)
class Call:
    image: str
    site: int
    raw_target: int
    effective_target: int
    veneer: Optional[int]


@dataclass(frozen=True)
class Seed:
    image: str
    site: int
    owner: int
    owner_reason: str
    value: int
    source_kind: str
    source_addr: Optional[int]


@dataclass(frozen=True)
class Event:
    kind: str
    function: int
    site: int
    detail: str
    path: Tuple[int, ...]


# Each slot contains a finite set of exact absolute addresses.
AbsState = Tuple[FrozenSet[int], ...]  # logical r0..r12


class Auditor:
    def __init__(self, images: List[Image]):
        self.images = images
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True
        self.calls: List[Call] = []
        self.calls_by_target: Dict[int, List[Call]] = defaultdict(list)
        self.call_targets: Set[int] = set()
        self.prologues: Set[int] = set()
        self.mov_pair_value: Dict[int, Tuple[int, int]] = {}  # movt_site -> (logical_reg, full_value)

    def image_for(self, addr: int) -> Optional[Image]:
        a = addr & 0xFFFFFFFF
        a &= ~1
        for img in self.images:
            if img.contains(a):
                return img
        return None

    def cs_one(self, addr: int):
        addr = (addr & 0xFFFFFFFF) & ~1
        img = self.image_for(addr)
        if not img or not img.contains(addr, 2):
            return None
        width = min(4, img.end - addr)
        ds = list(self.thumb.disasm(img.read(addr, width), addr, count=1))
        return ds[0] if ds else None

    def reg_slot(self, reg_id: int) -> Optional[int]:
        try:
            n = self.thumb.reg_name(reg_id).lower()
        except Exception:
            return None
        aliases = {"sb": 9, "sl": 10, "fp": 11, "ip": 12}
        if n in aliases:
            return aliases[n]
        if n.startswith("r") and n[1:].isdigit():
            v = int(n[1:])
            if 0 <= v <= 12:
                return v
        return None

    def raw_arm_veneer_target(self, addr: int) -> Optional[int]:
        addr &= 0xFFFFFFFF
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
        t = (target & 0xFFFFFFFF) & ~1
        vt = self.raw_arm_veneer_target(t)
        if vt is not None:
            return (vt & 0xFFFFFFFF) & ~1, t
        return t, None

    def literal_value(self, ci) -> Optional[Tuple[int, int]]:
        if not ci.mnemonic.lower().startswith("ldr") or len(ci.operands) < 2:
            return None
        op = ci.operands[1]
        if op.type != CS_OP_MEM or op.mem.base != ARM_REG_PC:
            return None
        pc = (ci.address + 4) & ~3
        lit_addr = (pc + int(op.mem.disp)) & 0xFFFFFFFF
        img = self.image_for(lit_addr)
        if not img or not img.contains(lit_addr, 4):
            return None
        return lit_addr, img.read_u32(lit_addr)

    @staticmethod
    def is_return(ci) -> bool:
        m = ci.mnemonic.lower()
        o = ci.op_str.lower().replace(" ", "")
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
    def is_unconditional_jump(ci) -> bool:
        return ci.mnemonic.lower() in {"b", "b.w", "bx"}

    def build_call_index(self) -> None:
        hdr("B. DIRECT CALL INDEX")
        tmp = {}
        for img in self.images:
            print(f"Indexing calls in {img.name} ...", flush=True)
            data = img.data
            for off in range(0, len(data) - 3, 2):
                h1 = struct.unpack_from("<H", data, off)[0]
                h2 = struct.unpack_from("<H", data, off + 2)[0]
                if (h1 & 0xF800) != 0xF000 or (h2 & 0xC000) != 0xC000:
                    continue
                site = img.base + off
                ci = self.cs_one(site)
                if ci is None or not ci.group(CS_GRP_CALL):
                    continue
                if not ci.operands or ci.operands[0].type != CS_OP_IMM:
                    continue
                raw = int(ci.operands[0].imm) & 0xFFFFFFFF
                eff, veneer = self.normalize_target(raw)
                tmp[(img.name, site)] = Call(img.name, site, raw, eff, veneer)

        self.calls = sorted(tmp.values(), key=lambda c: (c.image, c.site))
        for c in self.calls:
            self.calls_by_target[c.effective_target].append(c)
            self.call_targets.add(c.effective_target)

        print(f"direct calls indexed = {len(self.calls)}")
        print(f"unique effective targets = {len(self.calls_by_target)}", flush=True)

    def build_prologue_index(self) -> None:
        hdr("C. THUMB FUNCTION-ENTRY / PROLOGUE INDEX")
        pro = set()
        for img in self.images:
            print(f"Scanning prologues in {img.name} ...", flush=True)
            data = img.data
            for off in range(0, len(data) - 1, 2):
                h = struct.unpack_from("<H", data, off)[0]

                if (h & 0xFF00) == 0xB500:
                    addr = img.base + off
                    ci = self.cs_one(addr)
                    if ci and ci.mnemonic.lower() == "push" and "lr" in ci.op_str.lower():
                        pro.add(addr)

                if off + 4 <= len(data) and h == 0xE92D:
                    addr = img.base + off
                    ci = self.cs_one(addr)
                    if ci and (
                        ci.mnemonic.lower().startswith("push")
                        or (
                            ci.mnemonic.lower().startswith("stm")
                            and "sp" in ci.op_str.lower()
                            and "lr" in ci.op_str.lower()
                        )
                    ):
                        pro.add(addr)

        self.prologues = pro
        print(f"prologue candidates = {len(self.prologues)}", flush=True)

    def build_movw_movt_index(self) -> List[Tuple[str, int, int, int]]:
        """
        Conservative MOVW/MOVT pair census.
        Returns image, movt_site, logical_reg, full_value for near-block values.
        """
        hdr("D. MOVW/MOVT ADDRESS-CONSTRUCTION INDEX")
        hits = []

        for img in self.images:
            print(f"Scanning MOVW/MOVT pairs in {img.name} ...", flush=True)
            recent_movw: Dict[int, Tuple[int, int]] = {}  # slot -> (site, low16)

            for off in range(0, len(img.data) - 3, 2):
                h1 = struct.unpack_from("<H", img.data, off)[0]

                # Thumb-2 MOVW / MOVT family prefilter.
                if (h1 & 0xFBF0) not in {0xF240, 0xF2C0}:
                    continue

                addr = img.base + off
                ci = self.cs_one(addr)
                if ci is None or len(ci.operands) < 2:
                    continue
                if ci.operands[0].type != CS_OP_REG or ci.operands[1].type != CS_OP_IMM:
                    continue

                slot = self.reg_slot(int(ci.operands[0].reg))
                if slot is None:
                    continue
                imm = int(ci.operands[1].imm) & 0xFFFF
                m = ci.mnemonic.lower()

                if m == "movw":
                    recent_movw[slot] = (addr, imm)
                    continue

                if m == "movt":
                    prev = recent_movw.get(slot)
                    if prev is None or addr - prev[0] > 0x30:
                        continue
                    value = ((imm << 16) | prev[1]) & 0xFFFFFFFF
                    self.mov_pair_value[addr] = (slot, value)
                    if near_block(value):
                        hits.append((img.name, addr, slot, value))
                        print(
                            f"  {img.name:12s} movt=0x{addr:08X} r{slot} "
                            f"=> 0x{value:08X} <{block_label(value)}>"
                        )

        print(f"near-block MOVW/MOVT constructions = {len(hits)}", flush=True)
        return hits

    def raw_u32_occurrences(self, value: int) -> List[Tuple[Image, int]]:
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
        for img, lit_addr in self.raw_u32_occurrences(value):
            lo = max(img.base, lit_addr - 0x1100) & ~1
            for a in range(lo, lit_addr, 2):
                ci = self.cs_one(a)
                if ci is None:
                    continue
                lv = self.literal_value(ci)
                if lv and lv[0] == lit_addr and lv[1] == value:
                    out.add((img.name, a, lit_addr))
        return sorted(out)

    def resolve_owner(self, site: int, max_back: int = 0x1200) -> Tuple[int, str]:
        img = self.image_for(site)
        if not img:
            return site & ~1, "OUTSIDE"
        lo = max(img.base, site - max_back)

        call_pro = [
            a for a in self.prologues
            if lo <= a <= site and a in self.call_targets and self.image_for(a) == img
        ]
        if call_pro:
            return max(call_pro), "CALL_TARGET+PROLOGUE"

        pros = [a for a in self.prologues if lo <= a <= site and self.image_for(a) == img]
        if pros:
            return max(pros), "PROLOGUE_ONLY"

        cts = [a for a in self.call_targets if lo <= a <= site and self.image_for(a) == img]
        if cts:
            return max(cts), "CALL_TARGET_ONLY"

        return site & ~1, "UNRESOLVED"

    @staticmethod
    def empty_state() -> AbsState:
        return tuple(frozenset() for _ in range(13))

    @staticmethod
    def with_slot(state: AbsState, slot: int, values: Iterable[int]) -> AbsState:
        if not (0 <= slot <= 12):
            return state
        lst = list(state)
        lst[slot] = frozenset(v & 0xFFFFFFFF for v in values)
        return tuple(lst)

    @staticmethod
    def vals(state: AbsState, slot: Optional[int]) -> FrozenSet[int]:
        if slot is None or not (0 <= slot <= 12):
            return frozenset()
        return state[slot]

    @staticmethod
    def merge_state(a: AbsState, b: AbsState) -> AbsState:
        # Bound state growth: exact absolute-address analysis should stay tiny.
        merged = []
        for x, y in zip(a, b):
            z = set(x) | set(y)
            merged.append(frozenset(sorted(z)[:8]))
        return tuple(merged)

    @staticmethod
    def state_key(state: AbsState):
        return tuple(tuple(sorted(x)) for x in state)

    def transfer(
        self,
        ci,
        state: AbsState,
        function: int,
        path: Tuple[int, ...],
        depth: int,
        max_depth: int,
        call_seeds,
        events: List[Event],
    ) -> AbsState:
        m = ci.mnemonic.lower()
        ops = ci.operands
        out = state

        # Memory access based on exact absolute-address state.
        memops = [op for op in ops if op.type == CS_OP_MEM]
        if memops:
            mem = memops[0].mem
            base_slot = self.reg_slot(int(mem.base)) if mem.base else None
            base_vals = self.vals(state, base_slot)
            disp = int(mem.disp)

            if m.startswith("str"):
                for base in base_vals:
                    target = (base + disp) & 0xFFFFFFFF
                    if in_block(target):
                        src = ""
                        if ops and ops[0].type == CS_OP_REG:
                            ss = self.reg_slot(int(ops[0].reg))
                            src_vals = sorted(self.vals(state, ss))
                            if src_vals:
                                src = " src_abs=" + ",".join(f"0x{x:08X}" for x in src_vals)
                        events.append(Event(
                            "BLOCK_WRITE",
                            function,
                            ci.address,
                            f"target=0x{target:08X}<{block_label(target)}> "
                            f"{ci.mnemonic} {ci.op_str}{src}",
                            path,
                        ))

            elif m.startswith("ldr"):
                # Report reads of the block too; destination handling occurs below.
                for base in base_vals:
                    target = (base + disp) & 0xFFFFFFFF
                    if in_block(target):
                        events.append(Event(
                            "BLOCK_READ",
                            function,
                            ci.address,
                            f"target=0x{target:08X}<{block_label(target)}> "
                            f"{ci.mnemonic} {ci.op_str}",
                            path,
                        ))

        # Direct calls with near/block pointers.
        if ci.group(CS_GRP_CALL):
            target = None
            veneer = None
            if ops and ops[0].type == CS_OP_IMM:
                target, veneer = self.normalize_target(int(ops[0].imm))

            ptr_args = {}
            seed = self.empty_state()
            for r in range(4):
                vv = self.vals(state, r)
                interesting = sorted(v for v in vv if near_block(v))
                if interesting:
                    ptr_args[f"r{r}"] = [f"0x{v:08X}<{block_label(v)}>" for v in interesting]
                    seed = self.with_slot(seed, r, interesting)

            if target is not None and ptr_args:
                label = ""
                if target == KNOWN_MEMZERO_REAL or (veneer == KNOWN_MEMZERO_VENEER):
                    label = " <KNOWN_MEMZERO>"
                events.append(Event(
                    "BLOCK_POINTER_CALL",
                    function,
                    ci.address,
                    f"target=0x{target:08X}{label} args={ptr_args}",
                    path,
                ))

                if depth < max_depth and self.image_for(target):
                    call_seeds.append((target, seed, path + (target,), depth + 1, ci.address))

            # Caller-saved registers become unknown after call.
            for r in range(4):
                out = self.with_slot(out, r, [])
            return out

        # Destination register transfer.
        if not ops or ops[0].type != CS_OP_REG:
            return out
        dst = self.reg_slot(int(ops[0].reg))
        if dst is None:
            return out

        # Literal absolute address.
        lv = self.literal_value(ci)
        if m.startswith("ldr") and lv is not None:
            _, value = lv
            if near_block(value):
                events.append(Event(
                    "ABS_ADDR_DERIVED",
                    function,
                    ci.address,
                    f"r{dst}=0x{value:08X}<{block_label(value)}> via PC_LITERAL",
                    path,
                ))
                return self.with_slot(out, dst, [value])
            return self.with_slot(out, dst, [])

        # MOVT paired with earlier MOVW.
        pair = self.mov_pair_value.get(ci.address)
        if pair is not None and pair[0] == dst:
            value = pair[1]
            if near_block(value):
                events.append(Event(
                    "ABS_ADDR_DERIVED",
                    function,
                    ci.address,
                    f"r{dst}=0x{value:08X}<{block_label(value)}> via MOVW_MOVT",
                    path,
                ))
                return self.with_slot(out, dst, [value])
            return self.with_slot(out, dst, [])

        # Generic memory load destroys exact-address value unless PC literal handled above.
        if m.startswith("ldr"):
            return self.with_slot(out, dst, [])

        # MOV register copy.
        if m in {"mov", "movs", "mov.w"} and len(ops) >= 2:
            src = ops[1]
            if src.type == CS_OP_REG:
                ss = self.reg_slot(int(src.reg))
                return self.with_slot(out, dst, self.vals(state, ss))
            if src.type == CS_OP_IMM:
                value = int(src.imm) & 0xFFFFFFFF
                if near_block(value):
                    return self.with_slot(out, dst, [value])
            return self.with_slot(out, dst, [])

        # ADD/SUB immediate or two-register addition.
        if m.startswith(("add", "sub")):
            sign = 1 if m.startswith("add") else -1
            reg_ops = [self.reg_slot(int(op.reg)) for op in ops[1:] if op.type == CS_OP_REG]
            imm_ops = [int(op.imm) for op in ops[1:] if op.type == CS_OP_IMM]

            values = set()
            if len(reg_ops) == 1 and reg_ops[0] is not None:
                for base in self.vals(state, reg_ops[0]):
                    delta = imm_ops[0] if imm_ops else 0
                    value = (base + sign * delta) & 0xFFFFFFFF
                    if near_block(value):
                        values.add(value)

            elif len(reg_ops) >= 2 and reg_ops[0] is not None and reg_ops[1] is not None:
                for a in self.vals(state, reg_ops[0]):
                    for b in self.vals(state, reg_ops[1]):
                        value = (a + sign * b) & 0xFFFFFFFF
                        if near_block(value):
                            values.add(value)

            if values:
                events.append(Event(
                    "ABS_ADDR_DERIVED",
                    function,
                    ci.address,
                    f"r{dst}=" + ",".join(
                        f"0x{v:08X}<{block_label(v)}>" for v in sorted(values)
                    ) + f" via {m.upper()}",
                    path,
                ))
            return self.with_slot(out, dst, values)

        # ADR if Capstone provides absolute immediate.
        if m.startswith("adr") and len(ops) >= 2 and ops[1].type == CS_OP_IMM:
            value = int(ops[1].imm) & 0xFFFFFFFF
            if near_block(value):
                return self.with_slot(out, dst, [value])
            return self.with_slot(out, dst, [])

        # Unknown writer destroys exact-address state.
        return self.with_slot(out, dst, [])

    def analyze_function(
        self,
        entry: int,
        initial: AbsState,
        path: Tuple[int, ...],
        depth: int,
        max_depth: int,
        max_span: int,
    ):
        entry &= 0xFFFFFFFF
        entry &= ~1
        img = self.image_for(entry)
        if not img:
            return [], [], 0, False

        lo = entry
        hi = min(img.end, entry + max_span)
        q = deque([(entry, initial)])
        seen: Dict[int, AbsState] = {}
        events: List[Event] = []
        call_seeds = []
        insn_count = 0
        truncated = False

        while q and insn_count < 6000:
            addr, state = q.popleft()
            addr = (addr & 0xFFFFFFFF) & ~1
            if addr < lo or addr >= hi:
                truncated = True
                continue

            old = seen.get(addr)
            if old is not None:
                merged = self.merge_state(old, state)
                if merged == old:
                    continue
                seen[addr] = merged
                state = merged
            else:
                seen[addr] = state

            ci = self.cs_one(addr)
            if ci is None:
                continue
            insn_count += 1

            next_state = self.transfer(
                ci, state, entry, path, depth, max_depth, call_seeds, events
            )

            if self.is_return(ci):
                continue

            if ci.group(CS_GRP_JUMP):
                direct = None
                if ci.operands and ci.operands[0].type == CS_OP_IMM:
                    direct = (int(ci.operands[0].imm) & 0xFFFFFFFF) & ~1

                if direct is not None:
                    if lo <= direct < hi:
                        q.append((direct, next_state))
                    else:
                        truncated = True

                if not self.is_unconditional_jump(ci):
                    q.append(((addr + ci.size) & 0xFFFFFFFF, next_state))
                continue

            q.append(((addr + ci.size) & 0xFFFFFFFF, next_state))

        if q:
            truncated = True
        return events, call_seeds, insn_count, truncated


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


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument(
        "--boot",
        default=r"C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin",
    )
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
    ap.add_argument("--max-depth", type=int, default=4)
    ap.add_argument("--max-span", type=lambda x: int(x, 0), default=0x2000)
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

    aud = Auditor([
        Image("ALICE", ad, ALICE_BASE),
        Image("BOOT_ZIMAGE", bd, BOOT_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
    ])

    aud.build_call_index()
    aud.build_prologue_index()
    mov_hits = aud.build_movw_movt_index()

    hdr("E. FUNCTION-BOUNDARY REGRESSION")
    regression_pass = True
    for site, expected in KNOWN_OWNER_REGRESSION.items():
        got, reason = aud.resolve_owner(site)
        ok = got == expected
        regression_pass &= ok
        print(
            f"xref=0x{site:08X} expected=0x{expected:08X} "
            f"got=0x{got:08X} reason={reason} => {'PASS' if ok else 'FAIL'}"
        )
    print(f"FUNCTION OWNER REGRESSION = {'PASS' if regression_pass else 'FAIL'}")
    if not regression_pass:
        print("ABORT ANALYTICAL PROMOTION: owner regression failed.")
        return 2

    hdr("F. NEAR-BLOCK PC-LITERAL XREFS / ROOT OWNERS")
    seeds: List[Seed] = []
    used_literal_words: Set[Tuple[str, int]] = set()

    for value in range(NEAR_START, NEAR_END, 4):
        hits = aud.exact_literal_xrefs(value)
        if not hits:
            continue
        print(f"VALUE 0x{value:08X} <{block_label(value)}> xrefs={len(hits)}")
        for img_name, site, lit_addr in hits:
            owner, reason = aud.resolve_owner(site)
            seeds.append(Seed(img_name, site, owner, reason, value, "PC_LITERAL", lit_addr))
            used_literal_words.add((img_name, lit_addr))
            print(
                f"  {img_name:12s} site=0x{site:08X} literal=0x{lit_addr:08X} "
                f"owner=0x{owner:08X} reason={reason}"
            )

    for img_name, movt_site, slot, value in mov_hits:
        owner, reason = aud.resolve_owner(movt_site)
        seeds.append(Seed(img_name, movt_site, owner, reason, value, "MOVW_MOVT", None))

    roots = sorted({s.owner for s in seeds})
    print()
    print(f"total address seeds = {len(seeds)}")
    print(f"unique root owners  = {len(roots)}")

    hdr("G. RAW U32 BLOCK-ADDRESS OCCURRENCES / ORPHAN TABLE CENSUS")
    orphan_occ = []
    for value in FOCUS_WORDS:
        occ = aud.raw_u32_occurrences(value)
        print(f"0x{value:08X} <{block_label(value)}> raw_u32_occurrences={len(occ)}")
        for img, addr in occ:
            used = (img.name, addr) in used_literal_words
            status = "CODE_LITERAL" if used else "ORPHAN_U32"
            print(f"  {img.name:12s} 0x{addr:08X} {status}")
            if not used:
                orphan_occ.append((img, addr, value))

                lo = max(img.base, addr - 0x10)
                hi = min(img.end, addr + 0x14)
                # Print aligned nearby words when possible.
                start = (lo + 3) & ~3
                words = []
                a = start
                while a + 4 <= hi:
                    words.append(f"0x{a:08X}:0x{img.read_u32(a):08X}")
                    a += 4
                print("    words: " + " ".join(words))

    hdr("H. INTERPROCEDURAL ABSOLUTE-BLOCK POINTER TRACE")
    queue = deque()
    for root in roots:
        queue.append((root, aud.empty_state(), (root,), 0))

    seen_seeds = set()
    all_events: List[Event] = []
    runs = []

    while queue:
        entry, initial, path, depth = queue.popleft()
        key = (entry, aud.state_key(initial), depth)
        if key in seen_seeds:
            continue
        seen_seeds.add(key)

        evs, calls, count, truncated = aud.analyze_function(
            entry, initial, path, depth, args.max_depth, args.max_span
        )
        runs.append((entry, depth, count, truncated, path))
        all_events.extend(evs)

        for callee, seed, cpath, cdepth, callsite in calls:
            queue.append((callee, seed, cpath, cdepth))

    print(f"root owners                = {len(roots)}")
    print(f"function analyses executed = {len(runs)}")
    print(f"semantic events            = {len(all_events)}")
    print()
    for entry, depth, count, truncated, path in sorted(runs, key=lambda x: (x[1], x[0], x[4])):
        print(
            f"RUN depth={depth} entry=0x{entry:08X} insns={count} "
            f"truncated={truncated} path="
            + " -> ".join(f"0x{x:08X}" for x in path)
        )

    hdr("I. BLOCK READS / WRITES")
    writes = [e for e in all_events if e.kind == "BLOCK_WRITE"]
    reads = [e for e in all_events if e.kind == "BLOCK_READ"]

    print(f"BLOCK_READ  = {len(reads)}")
    for e in reads:
        print(
            f"  fn=0x{e.function:08X} site=0x{e.site:08X} {e.detail} path="
            + " -> ".join(f"0x{x:08X}" for x in e.path)
        )

    print()
    print(f"BLOCK_WRITE = {len(writes)}")
    for e in writes:
        print(
            f"  fn=0x{e.function:08X} site=0x{e.site:08X} {e.detail} path="
            + " -> ".join(f"0x{x:08X}" for x in e.path)
        )

    hdr("J. CALLS RECEIVING BLOCK POINTERS")
    ptr_calls = [e for e in all_events if e.kind == "BLOCK_POINTER_CALL"]
    print(f"BLOCK_POINTER_CALL = {len(ptr_calls)}")
    for e in ptr_calls:
        print(
            f"  fn=0x{e.function:08X} site=0x{e.site:08X} {e.detail} path="
            + " -> ".join(f"0x{x:08X}" for x in e.path)
        )

    hdr("K. ADDRESS-DERIVATION EVENTS")
    deriv = [e for e in all_events if e.kind == "ABS_ADDR_DERIVED"]
    print(f"ABS_ADDR_DERIVED = {len(deriv)}")
    for e in deriv[:250]:
        print(
            f"  fn=0x{e.function:08X} site=0x{e.site:08X} {e.detail} path="
            + " -> ".join(f"0x{x:08X}" for x in e.path)
        )
    if len(deriv) > 250:
        print(f"  ... {len(deriv)-250} additional derivation events omitted ...")

    hdr("L. DECISION GATE")
    writes_by_target = defaultdict(int)
    for e in writes:
        # detail begins with target=0x...
        try:
            tok = e.detail.split()[0].split("=")[1]
            writes_by_target[int(tok, 16)] += 1
        except Exception:
            pass

    print(f"near-block PC/MOV seeds     = {len(seeds)}")
    print(f"root owners                 = {len(roots)}")
    print(f"orphan U32 block refs       = {len(orphan_occ)}")
    print(f"BLOCK_POINTER_CALL          = {len(ptr_calls)}")
    print(f"BLOCK_WRITE                 = {len(writes)}")
    for target in sorted(writes_by_target):
        print(
            f"  writes to 0x{target:08X} <{block_label(target)}> = "
            f"{writes_by_target[target]}"
        )
    print()
    print("Interpretation:")
    print("  - Any BLOCK_WRITE is stronger than the old exact-F007F044-xref model because")
    print("    it includes base+offset aliases and helper propagation.")
    print("  - A write to F007F044 is the primary registry-root initializer anchor.")
    print("  - BLOCK_POINTER_CALL without a direct store may reveal a bulk initializer/helper.")
    print("  - ORPHAN_U32 occurrences are table evidence only until code consumption is proven.")
    print("  - If no write/call exists in ALICE/BOOT/ZIMAGE, the next gate should inspect")
    print("    ROM/data-init relocation tables and/or acquire runtime RAM if feasible.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
