#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.42 v2 - REGISTRY PROVENANCE WRITER TRACE

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no write / erase
- no phone access

Why A.42 exists
---------------
A.41 v2 showed that broad "+2/+0x0C + indexed STRH" matching is too noisy.
Its top candidate 0xF02E36AE was not a validated function entry.

A.42 replaces offset similarity with semantic provenance rooted at F007F044.

Known registry semantics:
    F007F044 -> global containing registry base pointer
    record stride = 0x10
    record +0x02 = raw child count
    record +0x0C = raw child-array pointer
    F02E01B0(id) -> dense index

Tracked provenance tags:
    GLOBAL_ADDR       address F007F044 itself
    REGISTRY_BASE     *(u32*)F007F044
    DENSE_INDEX       return from F02E01B0
    RECORD_OFFSET     DENSE_INDEX << 4
    RECORD_PTR        REGISTRY_BASE + RECORD_OFFSET
    CHILD_COUNT       *(u16*)(RECORD_PTR+2)
    CHILD_ARRAY_PTR   *(u32*)(RECORD_PTR+0x0C)

Interesting writes:
    *GLOBAL_ADDR
    *(RECORD_PTR+2)
    *(RECORD_PTR+0x0C)
    CHILD_ARRAY_PTR[index]

Registry-derived arguments are propagated through direct calls for a bounded
depth so helper writers can be found even if they do not reference F007F044.

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
    from capstone.arm import ARM_REG_PC, ARM_REG_SP, ARM_REG_LR
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

TITLE = "S13.5A.42 v2 - REGISTRY PROVENANCE WRITER TRACE"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

REG_BASE_GLOBAL = 0xF007F044
ID_TO_DENSE = 0xF02E01B0

MODE_THUMB = "THUMB"

# Regression anchors: xref site -> expected function entry.
KNOWN_OWNER_REGRESSION = {
    0xF02AE868: 0xF02AE864,
    0xF02D8180: 0xF02D8178,
    0xF02D8876: 0xF02D8870,
    0xF02F9D5C: 0xF02F9D34,
    0xF02FBC3A: 0xF02FBC24,
}

FOCUS_IDS = {
    0xB709: "B709_ROOT",
    0x8313: "IMAGE_8313",
    0x8321: "IMAGE_8321",
    0x8928: "AUDIO_8928",
}

TAG_GLOBAL_ADDR = "GLOBAL_ADDR"
TAG_REGISTRY_BASE = "REGISTRY_BASE"
TAG_DENSE_INDEX = "DENSE_INDEX"
TAG_RECORD_OFFSET = "RECORD_OFFSET"
TAG_RECORD_PTR = "RECORD_PTR"
TAG_CHILD_COUNT = "CHILD_COUNT"
TAG_CHILD_ARRAY = "CHILD_ARRAY_PTR"

REGISTRY_TAGS = {
    TAG_GLOBAL_ADDR,
    TAG_REGISTRY_BASE,
    TAG_DENSE_INDEX,
    TAG_RECORD_OFFSET,
    TAG_RECORD_PTR,
    TAG_CHILD_COUNT,
    TAG_CHILD_ARRAY,
}


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


@dataclass(frozen=True)
class Call:
    image: str
    site: int
    raw_target: int
    effective_target: int
    veneer: Optional[int]


@dataclass(frozen=True)
class Event:
    kind: str
    function: int
    site: int
    detail: str
    path: Tuple[int, ...]


RegTags = Tuple[FrozenSet[str], ...]  # r0..r12 + sp/lr ignored in state tuple


class Auditor:
    def __init__(self, images: List[Image]):
        self.images = images
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True
        self.calls: List[Call] = []
        self.calls_by_target: Dict[int, List[Call]] = defaultdict(list)
        self.call_targets: Set[int] = set()
        self.prologues: Set[int] = set()

    def image_for(self, addr: int) -> Optional[Image]:
        a = addr & ~1
        for img in self.images:
            if img.contains(a):
                return img
        return None

    def cs_one(self, addr: int):
        addr &= ~1
        img = self.image_for(addr)
        if not img or not img.contains(addr, 2):
            return None
        width = min(4, img.end - addr)
        ds = list(self.thumb.disasm(img.read(addr, width), addr, count=1))
        return ds[0] if ds else None

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
        m = ci.mnemonic.lower()
        return m in {"b", "b.w", "bx"}

    def build_call_index(self) -> None:
        hdr("B. DIRECT CALL INDEX")
        tmp = {}
        for img in self.images:
            print(f"Indexing calls in {img.name} ...", flush=True)
            data = img.data
            for off in range(0, len(data) - 3, 2):
                h1 = struct.unpack_from("<H", data, off)[0]
                h2 = struct.unpack_from("<H", data, off + 2)[0]

                # Thumb-2 BL / BLX immediate family prefilter.
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
                c = Call(img.name, site, raw, eff, veneer)
                tmp[(img.name, site)] = c

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

                # Thumb16 PUSH with M=1 => LR included: 1011 0101 xxxx xxxx
                if (h & 0xFF00) == 0xB500:
                    addr = img.base + off
                    ci = self.cs_one(addr)
                    if ci and ci.mnemonic.lower() == "push" and "lr" in ci.op_str.lower():
                        pro.add(addr)

                # Thumb-2 PUSH.W / STMDB sp!, {...,lr} common prefix E92D.
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

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str, int, int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        out = set()

        for img in self.images:
            start = 0
            occurrences = []
            while True:
                off = img.data.find(needle, start)
                if off < 0:
                    break
                occurrences.append(img.base + off)
                start = off + 1

            for lit_addr in occurrences:
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
        """
        Resolve the enclosing function conservatively.

        Priority:
          1) nearest preceding prologue that is also a direct-call target;
          2) nearest preceding prologue;
          3) nearest preceding direct-call target;
          4) site itself (unresolved).
        """
        img = self.image_for(site)
        if not img:
            return site & ~1, "OUTSIDE"

        lo = max(img.base, site - max_back)

        call_pro = [
            a for a in self.prologues
            if lo <= a <= site and a in self.call_targets
        ]
        if call_pro:
            return max(call_pro), "CALL_TARGET+PROLOGUE"

        pros = [a for a in self.prologues if lo <= a <= site]
        if pros:
            return max(pros), "PROLOGUE_ONLY"

        cts = [a for a in self.call_targets if lo <= a <= site and self.image_for(a) == img]
        if cts:
            return max(cts), "CALL_TARGET_ONLY"

        return site & ~1, "UNRESOLVED"

    @staticmethod
    def empty_state() -> RegTags:
        return tuple(frozenset() for _ in range(13))

    def reg_slot(self, reg_id: int) -> Optional[int]:
        """Map a Capstone ARM register id to our logical r0..r12 slot.

        Capstone register IDs are enum values, not 0..12.  Some versions also
        render r9-r12 using ABI aliases (sb/sl/fp/ip), so handle both forms.
        """
        try:
            name = self.thumb.reg_name(int(reg_id)).lower()
        except Exception:
            return None

        aliases = {"sb": 9, "sl": 10, "fp": 11, "ip": 12}
        if name in aliases:
            return aliases[name]
        if name.startswith("r") and name[1:].isdigit():
            n = int(name[1:])
            if 0 <= n <= 12:
                return n
        return None

    @staticmethod
    def with_reg(state: RegTags, reg_num: int, tags: Iterable[str]) -> RegTags:
        """Set tags by logical register slot (r0==0 .. r12==12)."""
        if not (0 <= reg_num <= 12):
            return state
        lst = list(state)
        lst[reg_num] = frozenset(tags)
        return tuple(lst)

    @staticmethod
    def tags_of(state: RegTags, reg_num: int) -> FrozenSet[str]:
        """Read tags by logical register slot (r0==0 .. r12==12)."""
        if 0 <= reg_num <= 12:
            return state[reg_num]
        return frozenset()

    def tags_of_regid(self, state: RegTags, reg_id: int) -> FrozenSet[str]:
        slot = self.reg_slot(reg_id)
        return self.tags_of(state, slot) if slot is not None else frozenset()

    @staticmethod
    def merge_state(a: RegTags, b: RegTags) -> RegTags:
        return tuple(x | y for x, y in zip(a, b))

    @staticmethod
    def state_key(state: RegTags) -> Tuple[Tuple[str, ...], ...]:
        return tuple(tuple(sorted(x)) for x in state)

    def transfer_instruction(
        self,
        ci,
        state: RegTags,
        function: int,
        path: Tuple[int, ...],
        depth: int,
        max_depth: int,
        call_seeds: List[Tuple[int, RegTags, Tuple[int, ...], int, int]],
        events: List[Event],
    ) -> RegTags:
        m = ci.mnemonic.lower()
        ops = ci.operands
        out = state

        # Record stores before clobbering any destination/value register.
        if m.startswith("str"):
            memops = [op for op in ops if op.type == CS_OP_MEM]
            if memops:
                mem = memops[0].mem
                base_tags = self.tags_of_regid(state, int(mem.base)) if mem.base else frozenset()
                index_tags = self.tags_of_regid(state, int(mem.index)) if mem.index else frozenset()
                disp = int(mem.disp)

                if TAG_GLOBAL_ADDR in base_tags and disp == 0:
                    events.append(Event(
                        "GLOBAL_WRITE", function, ci.address,
                        f"{ci.mnemonic} {ci.op_str} base={sorted(base_tags)}",
                        path,
                    ))

                if TAG_RECORD_PTR in base_tags and disp == 2:
                    events.append(Event(
                        "RECORD_COUNT_WRITE", function, ci.address,
                        f"{ci.mnemonic} {ci.op_str} base={sorted(base_tags)}",
                        path,
                    ))

                if TAG_RECORD_PTR in base_tags and disp == 0x0C:
                    events.append(Event(
                        "RECORD_CHILD_PTR_WRITE", function, ci.address,
                        f"{ci.mnemonic} {ci.op_str} base={sorted(base_tags)}",
                        path,
                    ))

                if TAG_CHILD_ARRAY in base_tags:
                    events.append(Event(
                        "CHILD_ARRAY_WRITE", function, ci.address,
                        f"{ci.mnemonic} {ci.op_str} base={sorted(base_tags)} index={sorted(index_tags)}",
                        path,
                    ))

        # Calls: capture interprocedural registry-derived arguments.
        if ci.group(CS_GRP_CALL):
            target = None
            if ops and ops[0].type == CS_OP_IMM:
                target, _ = self.normalize_target(int(ops[0].imm) & 0xFFFFFFFF)

            arg_tags = tuple(self.tags_of(state, r) for r in range(4))
            registry_args = {
                f"r{r}": sorted(arg_tags[r] & REGISTRY_TAGS)
                for r in range(4)
                if arg_tags[r] & REGISTRY_TAGS
            }

            if target is not None and registry_args:
                events.append(Event(
                    "REGISTRY_DERIVED_CALL", function, ci.address,
                    f"target=0x{target:08X} args={registry_args}",
                    path,
                ))

                if depth < max_depth and self.image_for(target):
                    seed = self.empty_state()
                    for r in range(4):
                        if arg_tags[r]:
                            seed = self.with_reg(seed, r, arg_tags[r])
                    call_seeds.append((target, seed, path + (target,), depth + 1, ci.address))

            # ABI clobber. Known ID_TO_DENSE returns semantic dense index in r0.
            for r in range(4):
                out = self.with_reg(out, r, [])
            if target == ID_TO_DENSE:
                out = self.with_reg(out, 0, [TAG_DENSE_INDEX])
            return out

        # No destination register => nothing else to model.
        if not ops or ops[0].type != CS_OP_REG:
            return out

        dst = self.reg_slot(int(ops[0].reg))
        if dst is None:
            return out

        # PC literal load.
        lv = self.literal_value(ci)
        if m.startswith("ldr") and lv is not None:
            _, value = lv
            if value == REG_BASE_GLOBAL:
                return self.with_reg(out, dst, [TAG_GLOBAL_ADDR])
            return self.with_reg(out, dst, [])

        # General memory loads.
        if m.startswith("ldr") and len(ops) >= 2 and ops[1].type == CS_OP_MEM:
            mem = ops[1].mem
            base_tags = self.tags_of_regid(state, int(mem.base)) if mem.base else frozenset()
            disp = int(mem.disp)

            tags = set()
            if TAG_GLOBAL_ADDR in base_tags and disp == 0:
                tags.add(TAG_REGISTRY_BASE)
                events.append(Event(
                    "REGISTRY_BASE_DERIVED", function, ci.address,
                    f"{ci.mnemonic} {ci.op_str}", path,
                ))
            if TAG_RECORD_PTR in base_tags and disp == 0x0C and m.startswith("ldr") and not m.startswith(("ldrb", "ldrh")):
                tags.add(TAG_CHILD_ARRAY)
                events.append(Event(
                    "CHILD_ARRAY_PTR_DERIVED", function, ci.address,
                    f"{ci.mnemonic} {ci.op_str}", path,
                ))
            if TAG_RECORD_PTR in base_tags and disp == 2 and m.startswith("ldrh"):
                tags.add(TAG_CHILD_COUNT)
                events.append(Event(
                    "CHILD_COUNT_READ", function, ci.address,
                    f"{ci.mnemonic} {ci.op_str}", path,
                ))

            return self.with_reg(out, dst, tags)

        # MOV register / immediate.
        if m in {"mov", "movs", "mov.w"} and len(ops) >= 2:
            src = ops[1]
            if src.type == CS_OP_REG:
                return self.with_reg(out, dst, self.tags_of_regid(state, int(src.reg)))
            return self.with_reg(out, dst, [])

        # LSL dense index by four -> record offset.
        if m.startswith("lsl"):
            src_reg = dst
            imm = None
            if len(ops) == 2 and ops[1].type == CS_OP_IMM:
                imm = int(ops[1].imm)
            elif len(ops) >= 3:
                if ops[1].type == CS_OP_REG:
                    slot = self.reg_slot(int(ops[1].reg))
                    src_reg = slot if slot is not None else -1
                if ops[2].type == CS_OP_IMM:
                    imm = int(ops[2].imm)

            src_tags = self.tags_of(state, src_reg)
            tags = set()
            if TAG_DENSE_INDEX in src_tags and imm == 4:
                tags.add(TAG_RECORD_OFFSET)
            return self.with_reg(out, dst, tags)

        # ADD registry base + record offset -> record pointer.
        if m.startswith("add"):
            reg_sources = []
            for op in ops[1:]:
                if op.type == CS_OP_REG:
                    slot = self.reg_slot(int(op.reg))
                    if slot is not None:
                        reg_sources.append(slot)
            source_tags = [self.tags_of(state, r) for r in reg_sources]
            flat = set().union(*source_tags) if source_tags else set()
            tags = set()

            if TAG_REGISTRY_BASE in flat and TAG_RECORD_OFFSET in flat:
                tags.add(TAG_RECORD_PTR)
                events.append(Event(
                    "RECORD_PTR_DERIVED", function, ci.address,
                    f"{ci.mnemonic} {ci.op_str}", path,
                ))

            # Preserve pointer provenance through add #0 or harmless copies only.
            imms = [int(op.imm) for op in ops[1:] if op.type == CS_OP_IMM]
            if len(reg_sources) == 1 and (not imms or all(i == 0 for i in imms)):
                tags |= set(source_tags[0])

            return self.with_reg(out, dst, tags)

        # SUB / arithmetic destroys semantic pointer tags unless no-op.
        if m.startswith(("sub", "mul", "and", "orr", "eor", "bic", "asr", "lsr")):
            return self.with_reg(out, dst, [])

        # Unknown writer to destination => drop tags conservatively.
        return self.with_reg(out, dst, [])

    def analyze_function(
        self,
        entry: int,
        initial: RegTags,
        path: Tuple[int, ...],
        depth: int,
        max_depth: int,
        max_span: int,
    ) -> Tuple[List[Event], List[Tuple[int, RegTags, Tuple[int, ...], int, int]], int, bool]:
        entry &= ~1
        img = self.image_for(entry)
        if not img:
            return [], [], 0, False

        lo = entry
        hi = min(img.end, entry + max_span)

        # Address -> merged state already seen.
        seen_state: Dict[int, RegTags] = {}
        q = deque([(entry, initial)])
        events: List[Event] = []
        call_seeds: List[Tuple[int, RegTags, Tuple[int, ...], int, int]] = []
        insn_count = 0
        truncated = False

        while q and insn_count < 5000:
            addr, state = q.popleft()
            addr &= ~1
            if addr < lo or addr >= hi:
                truncated = True
                continue

            old = seen_state.get(addr)
            if old is not None:
                merged = self.merge_state(old, state)
                if merged == old:
                    continue
                seen_state[addr] = merged
                state = merged
            else:
                seen_state[addr] = state

            ci = self.cs_one(addr)
            if ci is None:
                continue
            insn_count += 1

            next_state = self.transfer_instruction(
                ci, state, entry, path, depth, max_depth, call_seeds, events
            )

            if self.is_return(ci):
                continue

            # Calls return to the next instruction in the current CFG.  Their
            # callee provenance is handled separately by call_seeds.
            if ci.group(CS_GRP_CALL):
                q.append((addr + ci.size, next_state))
                continue

            if ci.group(CS_GRP_JUMP):
                direct = None
                if ci.operands and ci.operands[0].type == CS_OP_IMM:
                    # Capstone may expose high Thumb addresses as signed ints.
                    direct = (int(ci.operands[0].imm) & 0xFFFFFFFF) & ~1

                if direct is not None:
                    if lo <= direct < hi:
                        q.append((direct, next_state))
                    else:
                        truncated = True

                if not self.is_unconditional_jump(ci):
                    q.append((addr + ci.size, next_state))
                continue

            q.append((addr + ci.size, next_state))

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
    ap.add_argument(
        "--alice",
        default=r".\research\f2\work\extracted\altice_alice\alice-py.bin",
    )
    ap.add_argument(
        "--zimage",
        default=r".\research\f2\work\extracted\altice_platform\zimage.bin",
    )
    ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--max-span", type=lambda x: int(x, 0), default=0x1800)
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
    aud.build_prologue_index()

    hdr("D. EXACT F007F044 XREFS / FUNCTION OWNER RESOLUTION")
    xrefs = aud.exact_literal_xrefs(REG_BASE_GLOBAL)
    owners = {}
    for img_name, site, lit_addr in xrefs:
        owner, reason = aud.resolve_owner(site)
        owners.setdefault(owner, []).append((img_name, site, lit_addr, reason))
        print(
            f"{img_name:8s} xref=0x{site:08X} literal=0x{lit_addr:08X} "
            f"owner=0x{owner:08X} reason={reason}"
        )

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
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        return 2

    hdr("E2. CFG + TAINT ENGINE REGRESSION")
    cfg_checks = [
        (0xF02AE864, 40, "FILTERED_CHILD_ENUM"),
        (0xF02D8178, 10, "CHILD_AT_INDEX"),
        (0xF02D8870, 8, "CHILD_COUNT"),
    ]
    cfg_regression_pass = True
    diagnostic_events = []
    for entry, min_insns, label in cfg_checks:
        evs, calls, count, truncated = aud.analyze_function(
            entry, aud.empty_state(), (entry,), 0, 0, args.max_span
        )
        diagnostic_events.extend(evs)
        ok = count >= min_insns and not truncated
        cfg_regression_pass &= ok
        print(
            f"{label:22s} entry=0x{entry:08X} insns={count} "
            f"truncated={truncated} min={min_insns} => {'PASS' if ok else 'FAIL'}"
        )

    diag_kinds = defaultdict(int)
    for e in diagnostic_events:
        diag_kinds[e.kind] += 1
    taint_regression_pass = (
        diag_kinds.get("REGISTRY_BASE_DERIVED", 0) > 0
        and diag_kinds.get("RECORD_PTR_DERIVED", 0) > 0
        and diag_kinds.get("CHILD_ARRAY_PTR_DERIVED", 0) > 0
    )
    print(f"REGISTRY_BASE_DERIVED    = {diag_kinds.get('REGISTRY_BASE_DERIVED', 0)}")
    print(f"RECORD_PTR_DERIVED       = {diag_kinds.get('RECORD_PTR_DERIVED', 0)}")
    print(f"CHILD_ARRAY_PTR_DERIVED  = {diag_kinds.get('CHILD_ARRAY_PTR_DERIVED', 0)}")
    print(f"CFG REGRESSION           = {'PASS' if cfg_regression_pass else 'FAIL'}")
    print(f"TAINT REGRESSION         = {'PASS' if taint_regression_pass else 'FAIL'}")

    if not (cfg_regression_pass and taint_regression_pass):
        print("ABORT ANALYTICAL PROMOTION: CFG/taint self-test failed.")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        return 3

    hdr("F. INTERPROCEDURAL REGISTRY-PROVENANCE TRACE")

    # Each root owner starts untainted. The exact xref inside the function will
    # introduce GLOBAL_ADDR naturally.
    queue = deque()
    for owner in sorted(owners):
        queue.append((owner, aud.empty_state(), (owner,), 0, None))

    # Deduplicate by function + initial semantic arg state + depth.
    seen_seeds = set()
    all_events: List[Event] = []
    function_runs = []

    while queue:
        entry, initial, path, depth, from_site = queue.popleft()
        seed_key = (
            entry,
            aud.state_key(initial),
            depth,
        )
        if seed_key in seen_seeds:
            continue
        seen_seeds.add(seed_key)

        evs, calls, count, truncated = aud.analyze_function(
            entry,
            initial,
            path,
            depth,
            args.max_depth,
            args.max_span,
        )
        function_runs.append((entry, depth, count, truncated, path))
        all_events.extend(evs)

        for callee, seed, cpath, cdepth, callsite in calls:
            queue.append((callee, seed, cpath, cdepth, callsite))

    print(f"root owners                = {len(owners)}")
    print(f"function analyses executed = {len(function_runs)}")
    print(f"semantic events            = {len(all_events)}")
    trace_diag = defaultdict(int)
    for e in all_events:
        trace_diag[e.kind] += 1
    print(f"REGISTRY_BASE_DERIVED      = {trace_diag.get('REGISTRY_BASE_DERIVED', 0)}")
    print(f"RECORD_PTR_DERIVED         = {trace_diag.get('RECORD_PTR_DERIVED', 0)}")
    print(f"CHILD_ARRAY_PTR_DERIVED    = {trace_diag.get('CHILD_ARRAY_PTR_DERIVED', 0)}")
    print(f"CHILD_COUNT_READ           = {trace_diag.get('CHILD_COUNT_READ', 0)}")
    print()

    for entry, depth, count, truncated, path in sorted(function_runs, key=lambda x: (x[1], x[0], x[4])):
        print(
            f"RUN depth={depth} entry=0x{entry:08X} insns={count} "
            f"truncated={truncated} path="
            + " -> ".join(f"0x{x:08X}" for x in path)
        )

    hdr("G. REGISTRY-DERIVED CALL EDGES")
    call_events = [e for e in all_events if e.kind == "REGISTRY_DERIVED_CALL"]
    print(f"registry-derived direct calls = {len(call_events)}")
    for e in call_events:
        print(
            f"  fn=0x{e.function:08X} site=0x{e.site:08X} "
            f"{e.detail} path="
            + " -> ".join(f"0x{x:08X}" for x in e.path)
        )

    hdr("H. EXACT WRITER EVENTS")
    writer_kinds = {
        "GLOBAL_WRITE",
        "RECORD_COUNT_WRITE",
        "RECORD_CHILD_PTR_WRITE",
        "CHILD_ARRAY_WRITE",
    }
    writer_events = [e for e in all_events if e.kind in writer_kinds]

    by_kind = defaultdict(list)
    for e in writer_events:
        by_kind[e.kind].append(e)

    for kind in sorted(writer_kinds):
        hits = by_kind.get(kind, [])
        print(f"{kind}: {len(hits)}")
        for e in hits:
            print(
                f"  fn=0x{e.function:08X} site=0x{e.site:08X} "
                f"{e.detail} path="
                + " -> ".join(f"0x{x:08X}" for x in e.path)
            )

    hdr("I. FOCUS-ID PROXIMITY FOR PROVEN WRITER PATHS")
    focus_hits = []
    writer_functions = {e.function for e in writer_events}

    for fn in sorted(writer_functions):
        calls = aud.calls_by_target.get(fn, [])
        for c in calls:
            img = aud.image_for(c.site)
            if not img:
                continue
            lo = max(img.base, c.site - 0x80)
            hi = min(img.end, c.site + 0x30)
            blob = img.read(lo, hi - lo)
            for value, name in FOCUS_IDS.items():
                needle = struct.pack("<H", value)
                pos = blob.find(needle)
                if pos >= 0:
                    focus_hits.append((fn, c.site, value, name, lo + pos))

    print(f"focus proximity hits = {len(focus_hits)}")
    for fn, callsite, value, name, at in focus_hits:
        print(
            f"  writer=0x{fn:08X} caller=0x{callsite:08X} "
            f"nearby=0x{value:04X}<{name}> at 0x{at:08X}"
        )

    hdr("J. DECISION GATE")
    print(f"exact F007F044 xrefs        = {len(xrefs)}")
    print(f"resolved root owners        = {len(owners)}")
    print(f"owner regression            = {'PASS' if regression_pass else 'FAIL'}")
    print(f"CFG regression              = {'PASS' if cfg_regression_pass else 'FAIL'}")
    print(f"taint regression            = {'PASS' if taint_regression_pass else 'FAIL'}")
    print(f"interprocedural runs        = {len(function_runs)}")
    print(f"registry-derived call edges = {len(call_events)}")
    print(f"GLOBAL_WRITE                = {len(by_kind.get('GLOBAL_WRITE', []))}")
    print(f"RECORD_COUNT_WRITE          = {len(by_kind.get('RECORD_COUNT_WRITE', []))}")
    print(f"RECORD_CHILD_PTR_WRITE      = {len(by_kind.get('RECORD_CHILD_PTR_WRITE', []))}")
    print(f"CHILD_ARRAY_WRITE           = {len(by_kind.get('CHILD_ARRAY_WRITE', []))}")
    print()
    print("Interpretation:")
    print("  - Only writer events whose destination provenance derives from F007F044")
    print("    are meaningful for registry mutation.")
    print("  - If all four writer classes are zero, the statically reachable")
    print("    F007F044-rooted ALICE/ZIMAGE surface is read-only under this model.")
    print("  - If a writer is found, its exact call path is the next reconstruction anchor.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
