#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.51 - B702 LAUNCHER / DISPATCH INIT TRACE

STRICTLY OFFLINE.
No USB/COM/BROM/DA/device access. No flash write/erase. No repack. No patch.

Purpose
-------
A.50 established:
  8569 -> registration callback 1033E025 -> AUDIO_REG_A
  86C0 -> registration callback 1033E26D -> AUDIO_REG_A + AUDIO_REG_B
  8928 -> registration callback 1033D841 -> AUDIO_REG_A + AUDIO_REG_B + AUDIO_REG_C
and 87ED is Image-family.

S13.4I separately established the dispatcher pattern:
  resolve ID -> call registration callback -> read slot(channel=0,index=1)
  -> invoke the newly captured init when nonzero/different.

A.51 joins those two facts and asks the narrow next question:
  which init does each of 8569 / 86C0 / 8928 actually install into the
  dispatcher-observed slot, and does the 8569 init statically converge on the
  confirmed Audio Player chain (8928 / 1033E815 / 1033F83C)?

This audit does NOT choose or generate a patch.
"""

from __future__ import annotations

import hashlib
import os
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
        CS_MODE_THUMB,
        CS_GRP_CALL,
        CS_GRP_JUMP,
        CS_OP_IMM,
        CS_OP_MEM,
    )
    from capstone.arm import ARM_REG_PC
except Exception as exc:
    raise SystemExit(f"capstone unavailable in canonical venv: {exc}")

try:
    from unicorn import (
        Uc,
        UcError,
        UC_ARCH_ARM,
        UC_MODE_THUMB,
        UC_HOOK_MEM_WRITE,
    )
    from unicorn.arm_const import (
        UC_ARM_REG_SP,
        UC_ARM_REG_LR,
        UC_ARM_REG_PC,
        UC_ARM_REG_R0,
        UC_ARM_REG_R1,
        UC_ARM_REG_R2,
        UC_ARM_REG_R3,
    )
except Exception as exc:
    raise SystemExit(f"unicorn unavailable in canonical venv: {exc}")


TITLE = "S13.5A.51 - B702 LAUNCHER / DISPATCH INIT TRACE"

# Canonical decompressed images.
ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

# Registration callbacks recovered by A.50.
CB_8569 = 0x1033E024
CB_86C0 = 0x1033E26C
CB_8928 = 0x1033D840

# Registered pointers recovered statically by A.50.
INITPTR_8569 = 0x10348D05
INITPTR_86C0 = 0x1033EF29
INITPTR_8928 = 0x1033E815
AUXPTR_8928 = 0xF02E18BD

INIT_8569 = INITPTR_8569 & ~1
INIT_86C0 = INITPTR_86C0 & ~1
INIT_8928 = INITPTR_8928 & ~1
AUDIO_PLAYER = 0x1033F83C

# Registration helpers from S13.4I.
REG_A = 0x1031F71A
REG_B = 0x1031E120
REG_C = 0x1031F81C

# Dispatcher / slot getter facts from S13.4I.
DISPATCHER = 0x10336788
DISPATCHER_END = 0x103367F8
SLOT_GETTER = 0x103097E8
SLOT_GETTER_END = 0x103097FC

# Known branch mapper, used only for contextual owner dumps.
ROOT_MAPPER = 0x10319094
MAPPER_CONTEXTS = [
    ("8569", 0x1035439A, 0x103543A8, 0x103543AA),
    ("86C0_A", 0x102EBC58, 0x102EBCBC, 0x102EBCBE),
    ("86C0_B", 0x1037CA64, 0x1037CA8A, 0x1037CA8C),
    ("86C0_C", 0x10382B94, 0x10382BAA, 0x10382BAC),
    ("8928", 0x103660C8, 0x10366100, 0x10366102),
]

FOCUS_ADDRS = {
    CB_8569: "CB_8569",
    CB_86C0: "CB_86C0",
    CB_8928: "CB_8928",
    INIT_8569: "INIT_8569_10348D04",
    INIT_86C0: "INIT_86C0_1033EF28",
    INIT_8928: "AUDIO_INIT_1033E814",
    AUDIO_PLAYER: "AUDIO_PLAYER_1033F83C",
    REG_A: "AUDIO_REG_A",
    REG_B: "AUDIO_REG_B",
    REG_C: "AUDIO_REG_C",
    ROOT_MAPPER: "ROOT_MAPPER_10319094",
    SLOT_GETTER: "SLOT_GETTER_103097E8",
    DISPATCHER: "DISPATCHER_10336788",
}

FOCUS_IDS = {
    0x8569: "ID_8569",
    0x86C0: "ID_86C0",
    0x8928: "ID_8928",
    0x87ED: "ID_87ED_IMAGE_FAMILY",
    0xB702: "B702",
    0xB709: "B709",
}

# Emulator memory. This is RAM only inside Unicorn, never a device.
RAM = 0xF0000000
RAM_SIZE = 0x00100000
STACK = 0x20000000
STACK_SIZE = 0x00010000
STOP = STACK + 0x100

SCENARIOS = {
    "8569": [
        ("REG_A", REG_A, INITPTR_8569),
    ],
    "86C0": [
        ("REG_A", REG_A, INITPTR_86C0),
        ("REG_B", REG_B, INITPTR_86C0),
    ],
    "8928": [
        ("REG_A", REG_A, INITPTR_8928),
        ("REG_B", REG_B, INITPTR_8928),
        ("REG_C", REG_C, AUXPTR_8928),
    ],
}


def hline(title: str) -> None:
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u32(data: bytes, off: int) -> int:
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
            raise ValueError(f"{self.name}: address out of range 0x{addr:08X}")
        return addr - self.base

    def read(self, addr: int, n: int) -> bytes:
        return self.data[self.off(addr):self.off(addr) + n]

    def read_u32(self, addr: int) -> int:
        return u32(self.data, self.off(addr))


@dataclass
class Insn:
    addr: int
    size: int
    text: str
    target: Optional[int] = None
    is_call: bool = False
    is_jump: bool = False
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None


@dataclass
class FuncAudit:
    entry: int
    image: str
    insns: Dict[int, Insn] = field(default_factory=dict)
    calls: List[Tuple[int, int]] = field(default_factory=list)
    literals: List[Tuple[int, int, int]] = field(default_factory=list)
    truncated: bool = False


class StaticAudit:
    def __init__(self, alice: Image, zimage: Image):
        self.alice = alice
        self.zimage = zimage
        self.images = [alice, zimage]
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True
        self.arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.arm.detail = True

    def image_for(self, addr: int) -> Optional[Image]:
        for img in self.images:
            if img.contains(addr):
                return img
        return None

    def decode_one(self, addr: int) -> Optional[Insn]:
        img = self.image_for(addr)
        if img is None or not img.contains(addr, 2):
            return None
        blob = img.read(addr, min(4, img.end - addr))
        ds = list(self.thumb.disasm(blob, addr, count=1))
        if not ds:
            return None
        i = ds[0]
        target = None
        is_call = bool(i.group(CS_GRP_CALL))
        is_jump = bool(i.group(CS_GRP_JUMP))
        if (is_call or is_jump) and i.operands and i.operands[0].type == CS_OP_IMM:
            target = int(i.operands[0].imm) & 0xFFFFFFFF

        lit_addr = None
        lit_val = None
        if i.mnemonic.startswith("ldr") and len(i.operands) >= 2:
            op = i.operands[1]
            if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                pc = (addr + 4) & ~3
                lit_addr = (pc + int(op.mem.disp)) & 0xFFFFFFFF
                li = self.image_for(lit_addr)
                if li and li.contains(lit_addr, 4):
                    lit_val = li.read_u32(lit_addr)

        return Insn(
            addr=addr,
            size=i.size,
            text=f"{i.mnemonic:<9} {i.op_str}".rstrip(),
            target=target,
            is_call=is_call,
            is_jump=is_jump,
            literal_addr=lit_addr,
            literal_value=lit_val,
        )

    @staticmethod
    def is_return(text: str) -> bool:
        s = text.lower()
        return (
            (s.startswith("pop") and "pc" in s)
            or (s.startswith("bx") and "lr" in s)
            or ("pc, lr" in s and s.startswith("mov"))
        )

    @staticmethod
    def is_conditional_branch(text: str) -> bool:
        m = text.split()[0].lower()
        if m in {"b", "b.w", "bx", "bl", "blx"}:
            return False
        return m.startswith("b") or m in {"cbz", "cbnz"}

    def audit_func(self, entry: int, max_span: int = 0x900, max_insns: int = 900) -> FuncAudit:
        entry &= ~1
        img = self.image_for(entry)
        out = FuncAudit(entry, img.name if img else "OUTSIDE")
        if img is None:
            return out

        q = deque([entry])
        seen: Set[int] = set()
        while q and len(seen) < max_insns:
            addr = q.popleft()
            if addr in seen:
                continue
            if addr < entry or addr >= entry + max_span:
                out.truncated = True
                continue
            ins = self.decode_one(addr)
            if ins is None:
                continue
            seen.add(addr)
            out.insns[addr] = ins
            if ins.literal_value is not None and ins.literal_addr is not None:
                out.literals.append((addr, ins.literal_addr, ins.literal_value))
            if ins.is_call and ins.target is not None:
                out.calls.append((addr, ins.target))
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
        return out

    def resolve_arm_veneer(self, addr: int) -> Optional[int]:
        addr &= ~1
        if not self.alice.contains(addr, 8):
            return None
        w0 = self.alice.read_u32(addr)
        if w0 in (0xE51FF004, 0xE59FF000):
            return self.alice.read_u32(addr + 4)
        return None

    def normalized_target(self, target: int) -> Tuple[int, Optional[str]]:
        direct = target & ~1
        veneer = self.resolve_arm_veneer(direct)
        if veneer is not None:
            mode = "THUMB" if (veneer & 1) else "ARM"
            return veneer & ~1, f"ARM_VENEER->{mode}"
        return direct, None

    def can_follow_thumb(self, raw_target: int) -> Optional[int]:
        direct = raw_target & ~1
        veneer = self.resolve_arm_veneer(direct)
        if veneer is not None:
            if veneer & 1:
                return veneer & ~1
            return None
        # Direct ALICE targets in this family are Thumb. Avoid guessing ZIMAGE mode.
        if self.alice.contains(direct):
            return direct
        return None

    def linear(self, start: int, end: int) -> List[Insn]:
        out = []
        pc = start & ~1
        while pc < end:
            x = self.decode_one(pc)
            if x is None:
                break
            out.append(x)
            pc += x.size
        return out

    def pointer_occurrences(self, value: int) -> List[Tuple[str, int, int]]:
        vals = {value & 0xFFFFFFFF, (value | 1) & 0xFFFFFFFF, (value & ~1) & 0xFFFFFFFF}
        found = []
        for img in self.images:
            for v in vals:
                needle = struct.pack("<I", v)
                p = 0
                while True:
                    p = img.data.find(needle, p)
                    if p < 0:
                        break
                    found.append((img.name, img.base + p, v))
                    p += 1
        return sorted(set(found))

    def string_at(self, ptr: int) -> Optional[str]:
        img = self.image_for(ptr)
        if img is None:
            return None
        off = img.off(ptr)
        buf = img.data[off:off + 160]

        # ASCII first.
        raw = bytearray()
        for b in buf:
            if b == 0:
                break
            if 0x20 <= b <= 0x7E or b in (9,):
                raw.append(b)
            else:
                raw = bytearray()
                break
        if len(raw) >= 4:
            return raw.decode("ascii", errors="replace")

        # UTF-16LE second.
        chars = []
        for i in range(0, min(len(buf) - 1, 158), 2):
            w = buf[i] | (buf[i + 1] << 8)
            if w == 0:
                break
            if 0x20 <= w <= 0x7E:
                chars.append(chr(w))
            else:
                chars = []
                break
        if len(chars) >= 4:
            return "".join(chars)
        return None


def load_images() -> Tuple[Image, Image]:
    root = Path.cwd()
    alice_path = root / "research/f2/work/extracted/altice_alice/alice-py.bin"
    zimage_path = root / "research/f2/work/extracted/altice_platform/zimage.bin"

    if not alice_path.is_file():
        raise SystemExit(f"Missing canonical ALICE: {alice_path}")
    if not zimage_path.is_file():
        raise SystemExit(f"Missing canonical ZIMAGE: {zimage_path}")

    alice = alice_path.read_bytes()
    zimage = zimage_path.read_bytes()

    print(f"ALICE  size=0x{len(alice):X} sha256={sha256(alice)}")
    print(f"ZIMAGE size=0x{len(zimage):X} sha256={sha256(zimage)}")

    if len(alice) != ALICE_SIZE or sha256(alice) != ALICE_SHA256:
        raise SystemExit("ALICE canonical guard FAIL")
    if len(zimage) != ZIMAGE_SIZE or sha256(zimage) != ZIMAGE_SHA256:
        raise SystemExit("ZIMAGE canonical guard FAIL")

    print("ALICE guard  = PASS")
    print("ZIMAGE guard = PASS")
    return Image("ALICE", alice, ALICE_BASE), Image("ZIMAGE", zimage, ZIMAGE_BASE)


def map_image(u: Uc, img: Image) -> None:
    page = 0x1000
    start = img.base & ~(page - 1)
    end = (img.end + page - 1) & ~(page - 1)
    u.mem_map(start, end - start)
    u.mem_write(img.base, img.data)


def make_uc(alice: Image, zimage: Image):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    map_image(u, alice)
    map_image(u, zimage)
    u.mem_map(RAM, RAM_SIZE)
    u.mem_map(STACK, STACK_SIZE)
    writes = []

    def on_write(uc, access, addr, size, value, user):
        if not (STACK <= addr < STACK + STACK_SIZE):
            writes.append((addr, size, value & ((1 << (8 * size)) - 1)))

    u.hook_add(UC_HOOK_MEM_WRITE, on_write)
    return u, writes


def uc_call(u: Uc, entry: int, r0: int = 0, r1: int = 0, r2: int = 0, r3: int = 0,
            count: int = 30000) -> int:
    u.reg_write(UC_ARM_REG_SP, STACK + STACK_SIZE - 0x1000)
    u.reg_write(UC_ARM_REG_LR, STOP | 1)
    u.reg_write(UC_ARM_REG_R0, r0)
    u.reg_write(UC_ARM_REG_R1, r1)
    u.reg_write(UC_ARM_REG_R2, r2)
    u.reg_write(UC_ARM_REG_R3, r3)
    u.emu_start(entry | 1, STOP, count=count)
    pc = u.reg_read(UC_ARM_REG_PC)
    if pc != STOP:
        raise RuntimeError(f"call 0x{entry:08X} did not return to STOP; PC=0x{pc:08X}")
    return u.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF


def probe_scenario(alice: Image, zimage: Image, name: str, seq) -> Dict[str, object]:
    u, writes = make_uc(alice, zimage)

    baseline = uc_call(u, SLOT_GETTER, 0, 1)
    steps = []
    for reg_name, reg_addr, ptr in seq:
        before_n = len(writes)
        uc_call(u, reg_addr, ptr, 1)
        slot = uc_call(u, SLOT_GETTER, 0, 1)
        step_writes = writes[before_n:]
        steps.append({
            "registrar": reg_name,
            "registrar_addr": reg_addr,
            "ptr": ptr,
            "slot01_after": slot,
            "writes": step_writes,
        })

    final_slot = uc_call(u, SLOT_GETTER, 0, 1)
    return {
        "name": name,
        "baseline_slot01": baseline,
        "steps": steps,
        "final_slot01": final_slot,
        "all_writes": writes,
    }


def print_callback(aud: StaticAudit, name: str, start: int, end: int) -> None:
    print(f"\n{name} callback 0x{start:08X}..0x{end - 1:08X}")
    for x in aud.linear(start, end):
        suffix = ""
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            suffix += f" ; target=0x{x.target:08X} norm=0x{norm:08X}"
            if via:
                suffix += f" {via}"
        if x.literal_value is not None:
            suffix += f" ; literal@0x{x.literal_addr:08X}=0x{x.literal_value:08X}"
            lab = FOCUS_ADDRS.get(x.literal_value & ~1)
            if lab:
                suffix += f" <{lab}>"
        print(f"  0x{x.addr:08X}: {x.text}{suffix}")


def callgraph(aud: StaticAudit, root: int, depth: int = 3, max_funcs: int = 80):
    root &= ~1
    q = deque([(root, 0)])
    funcs: Dict[int, FuncAudit] = {}
    edges: Dict[int, Set[int]] = {}
    literals_to_focus = []
    strings = []

    while q and len(funcs) < max_funcs:
        entry, d = q.popleft()
        if entry in funcs:
            continue
        fa = aud.audit_func(entry)
        funcs[entry] = fa
        edges.setdefault(entry, set())

        for site, litaddr, val in fa.literals:
            norm = val & ~1
            if norm in FOCUS_ADDRS:
                literals_to_focus.append((entry, site, litaddr, val, FOCUS_ADDRS[norm]))
            s = aud.string_at(val)
            if s:
                strings.append((entry, site, val, s))

        if d >= depth:
            continue
        for site, raw_t in fa.calls:
            follow = aud.can_follow_thumb(raw_t)
            norm, _ = aud.normalized_target(raw_t)
            edges[entry].add(norm)
            if follow is not None and follow not in funcs:
                q.append((follow, d + 1))

    return funcs, edges, literals_to_focus, strings


def shortest_path(edges: Dict[int, Set[int]], root: int, target: int) -> Optional[List[int]]:
    root &= ~1
    target &= ~1
    q = deque([(root, [root])])
    seen = {root}
    while q:
        node, path = q.popleft()
        if node == target:
            return path
        for nxt in edges.get(node, set()):
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, path + [nxt]))
    return None


def print_root_audit(aud: StaticAudit, label: str, root: int):
    fa = aud.audit_func(root)
    print(f"\n{label}: entry=0x{root:08X} image={fa.image} insns={len(fa.insns)} "
          f"calls={len(fa.calls)} literals={len(fa.literals)} truncated={fa.truncated}")

    print("  DIRECT CALLS:")
    for site, raw in fa.calls:
        norm, via = aud.normalized_target(raw)
        lab = FOCUS_ADDRS.get(norm, "")
        tail = f" <{lab}>" if lab else ""
        if via:
            tail += f" [{via}]"
        print(f"    0x{site:08X} -> raw 0x{raw:08X} -> 0x{norm:08X}{tail}")

    print("  LITERALS / STRINGS:")
    any_lit = False
    for site, litaddr, val in fa.literals:
        lab = FOCUS_ADDRS.get(val & ~1)
        s = aud.string_at(val)
        if lab or s:
            any_lit = True
            extra = f" <{lab}>" if lab else ""
            if s:
                extra += f' STRING="{s}"'
            print(f"    0x{site:08X} lit@0x{litaddr:08X}=0x{val:08X}{extra}")
    if not any_lit:
        print("    none classified")

    funcs, edges, focus_lits, strings = callgraph(aud, root, depth=3, max_funcs=80)
    print(f"  CLOSURE(depth<=3): functions={len(funcs)}")

    for target, name in [
        (INIT_86C0, "INIT_86C0"),
        (INIT_8928, "AUDIO_INIT"),
        (AUDIO_PLAYER, "AUDIO_PLAYER"),
        (CB_8928, "CB_8928"),
    ]:
        p = shortest_path(edges, root, target)
        if p:
            print(f"    PATH to {name}: " + " -> ".join(f"0x{x:08X}" for x in p))
        else:
            print(f"    PATH to {name}: NONE within bounded direct-call closure")

    if focus_lits:
        print("  FOCUS POINTER LITERALS in closure:")
        for fentry, site, litaddr, val, name in focus_lits[:40]:
            print(f"    func=0x{fentry:08X} site=0x{site:08X} value=0x{val:08X} <{name}>")
    else:
        print("  FOCUS POINTER LITERALS in closure: none")

    uniq_strings = []
    seen = set()
    for fentry, site, val, s in strings:
        key = (s, val)
        if key not in seen:
            seen.add(key)
            uniq_strings.append((fentry, site, val, s))
    if uniq_strings:
        print("  PRINTABLE STRINGS referenced in closure:")
        for fentry, site, val, s in uniq_strings[:80]:
            print(f'    func=0x{fentry:08X} site=0x{site:08X} ptr=0x{val:08X} "{s}"')
    else:
        print("  PRINTABLE STRINGS referenced in closure: none")

    return fa, funcs, edges, focus_lits, uniq_strings


def print_mapper_contexts(aud: StaticAudit) -> None:
    for label, owner, load, call in MAPPER_CONTEXTS:
        print(f"\n{label}: owner~0x{owner:08X} load=0x{load:08X} call=0x{call:08X}")
        pc = owner & ~1
        stop = min(owner + 0xB0, call + 0x30)
        n = 0
        while pc < stop and n < 100:
            x = aud.decode_one(pc)
            if x is None:
                break
            mark = ""
            if x.addr == load:
                mark += " <ID_LITERAL_LOAD>"
            if x.addr == call:
                mark += " <ROOT_MAPPER_CALL>"
            suffix = ""
            if x.literal_value is not None:
                suffix += f" ; lit=0x{x.literal_value:08X}"
                if x.literal_value in FOCUS_IDS:
                    suffix += f" <{FOCUS_IDS[x.literal_value]}>"
            if x.target is not None:
                norm, via = aud.normalized_target(x.target)
                suffix += f" ; target=0x{norm:08X}"
                if norm == ROOT_MAPPER:
                    suffix += " <ROOT_MAPPER>"
            print(f"  0x{x.addr:08X}: {x.text}{suffix}{mark}")
            pc += x.size
            n += 1


def main() -> int:
    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO")
    print(f"F2_AUTOMATION_OFFLINE: {os.environ.get('F2_AUTOMATION_OFFLINE', '<unset>')}")
    if os.environ.get("F2_AUTOMATION_OFFLINE") != "1":
        raise SystemExit("Refusing to run outside the canonical offline automation runner.")

    hline("A. CANONICAL IMAGE GUARDS")
    alice, zimage = load_images()
    aud = StaticAudit(alice, zimage)

    hline("B. REGISTRATION CALLBACKS / STATIC REGISTERED POINTERS")
    print_callback(aud, "8569", CB_8569, 0x1033E032)
    print_callback(aud, "86C0", CB_86C0, 0x1033E28C)
    print_callback(aud, "8928", CB_8928, 0x1033D85C)

    print()
    print(f"Expected 8569 registered init ptr : 0x{INITPTR_8569:08X}")
    print(f"Expected 86C0 registered init ptr : 0x{INITPTR_86C0:08X}")
    print(f"Expected 8928 registered init ptr : 0x{INITPTR_8928:08X}")
    print(f"Known Audio Player entry          : 0x{AUDIO_PLAYER:08X}")

    hline("C. DISPATCHER / SLOT(0,1) STATIC CONTEXT")
    print(f"Dispatcher: 0x{DISPATCHER:08X}..0x{DISPATCHER_END - 1:08X}")
    for x in aud.linear(DISPATCHER, DISPATCHER_END):
        suffix = ""
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            suffix += f" ; target=0x{norm:08X}"
            if norm in FOCUS_ADDRS:
                suffix += f" <{FOCUS_ADDRS[norm]}>"
        if x.literal_value is not None:
            suffix += f" ; literal=0x{x.literal_value:08X}"
        if x.addr in (0x1033679E, 0x103367E6):
            suffix += " <BLX_R4_SITE_FROM_S13.4I>"
        print(f"  0x{x.addr:08X}: {x.text}{suffix}")

    print("\nSlot getter:")
    for x in aud.linear(SLOT_GETTER, SLOT_GETTER_END):
        suffix = ""
        if x.literal_value is not None:
            suffix += f" ; literal=0x{x.literal_value:08X}"
        print(f"  0x{x.addr:08X}: {x.text}{suffix}")

    hline("D. BOUNDED UNICORN PROBE OF REGISTRATION -> DISPATCHER SLOT(0,1)")
    print("This executes only canonical firmware bytes inside Unicorn with emulated RAM.")
    print("No init/launcher function is executed. No device API exists in this script.")

    probes = {}
    for name, seq in SCENARIOS.items():
        try:
            p = probe_scenario(alice, zimage, name, seq)
            probes[name] = p
            print(f"\nSCENARIO {name}")
            print(f"  baseline slot(0,1) = 0x{p['baseline_slot01']:08X}")
            for st in p["steps"]:
                print(
                    f"  {st['registrar']} 0x{st['registrar_addr']:08X} "
                    f"r0=0x{st['ptr']:08X} r1=1 -> slot(0,1)=0x{st['slot01_after']:08X}"
                )
                uniq = sorted({(a, s, v) for a, s, v in st["writes"] if not (STACK <= a < STACK + STACK_SIZE)})
                if uniq:
                    print("    writes:")
                    for a, s, v in uniq[:40]:
                        print(f"      0x{a:08X} size={s} value=0x{v:0{s*2}X}")
            print(f"  FINAL slot(0,1) = 0x{p['final_slot01']:08X}")
        except (UcError, RuntimeError) as exc:
            probes[name] = {"error": str(exc)}
            print(f"\nSCENARIO {name} ERROR: {exc}")

    hline("E. REGISTERED INIT CLASSIFICATION / BOUNDED CALLGRAPH")
    roots = {}
    roots["8569"] = print_root_audit(aud, "8569 registered init", INIT_8569)
    roots["86C0"] = print_root_audit(aud, "86C0 registered init", INIT_86C0)
    roots["8928"] = print_root_audit(aud, "8928 confirmed Audio init", INIT_8928)

    hline("F. ROOT DIRECT-CALL SET SIMILARITY")
    direct_sets = {}
    for name, root in [("8569", INIT_8569), ("86C0", INIT_86C0), ("8928", INIT_8928)]:
        fa = aud.audit_func(root)
        s = set()
        for _, raw in fa.calls:
            norm, _ = aud.normalized_target(raw)
            s.add(norm)
        direct_sets[name] = s
        print(f"{name}: {len(s)} direct normalized call targets")

    pairs = [("8569", "86C0"), ("8569", "8928"), ("86C0", "8928")]
    for a, b in pairs:
        sa, sb = direct_sets[a], direct_sets[b]
        inter = sa & sb
        union = sa | sb
        jac = len(inter) / len(union) if union else 1.0
        print(f"{a} vs {b}: shared={len(inter)} union={len(union)} jaccard={jac:.3f}")
        if inter:
            print("  shared:", ", ".join(f"0x{x:08X}" for x in sorted(inter)))

    hline("G. EXACT POINTER OCCURRENCES FOR THREE REGISTERED INITS")
    for name, ptr in [("8569", INITPTR_8569), ("86C0", INITPTR_86C0), ("8928", INITPTR_8928)]:
        hits = aud.pointer_occurrences(ptr)
        print(f"{name} ptr=0x{ptr:08X}: occurrences={len(hits)}")
        for img, addr, val in hits[:40]:
            print(f"  {img} 0x{addr:08X} = 0x{val:08X}")

    hline("H. KNOWN ROOT-MAPPER CALLSITE OWNER CONTEXT")
    print_mapper_contexts(aud)

    hline("I. DECISION GATE")
    expected = {
        "8569": INITPTR_8569,
        "86C0": INITPTR_86C0,
        "8928": INITPTR_8928,
    }
    all_slot_proven = True
    for name in ("8569", "86C0", "8928"):
        p = probes.get(name, {})
        if "error" in p:
            print(f"{name}: SLOT PROOF = ERROR ({p['error']})")
            all_slot_proven = False
            continue
        got = int(p["final_slot01"])
        want = expected[name]
        ok = got == want
        all_slot_proven &= ok
        print(
            f"{name}: dispatcher-observed slot(0,1)=0x{got:08X}; "
            f"expected registered ptr=0x{want:08X}; MATCH={'YES' if ok else 'NO'}"
        )

    print()
    print("Mechanical distinctions:")
    print(f"  8569 init == 86C0 init : {'YES' if INIT_8569 == INIT_86C0 else 'NO'}")
    print(f"  8569 init == 8928 init : {'YES' if INIT_8569 == INIT_8928 else 'NO'}")
    print(f"  86C0 init == 8928 init : {'YES' if INIT_86C0 == INIT_8928 else 'NO'}")

    # Bounded direct-call closure outcomes for 8569.
    _, edges_8569, focus_lits_8569, strings_8569 = callgraph(aud, INIT_8569, depth=3, max_funcs=80)
    p86 = shortest_path(edges_8569, INIT_8569, INIT_86C0)
    p89 = shortest_path(edges_8569, INIT_8569, INIT_8928)
    pap = shortest_path(edges_8569, INIT_8569, AUDIO_PLAYER)
    lit_targets = {val & ~1 for _, _, _, val, _ in focus_lits_8569}

    print()
    print(f"8569 bounded direct-call path -> 86C0 init      : {'YES' if p86 else 'NO'}")
    print(f"8569 bounded direct-call path -> 8928 Audio init: {'YES' if p89 else 'NO'}")
    print(f"8569 bounded direct-call path -> Audio Player   : {'YES' if pap else 'NO'}")
    print(f"8569 closure literal pointer -> 8928 Audio init : {'YES' if INIT_8928 in lit_targets else 'NO'}")
    print(f"8569 closure literal pointer -> Audio Player    : {'YES' if AUDIO_PLAYER in lit_targets else 'NO'}")

    print()
    if all_slot_proven:
        print("FACT: the three IDs install three distinct dispatcher-observed init pointers.")
        print("FACT: 8569 does not dispatch DIRECTLY to 86C0 or 8928; it dispatches to 0x10348D05.")
        print("FACT: 86C0 dispatches to 0x1033EF29.")
        print("FACT: 8928 dispatches to confirmed Audio init 0x1033E815.")
    else:
        print("Slot proof incomplete: do not promote dispatcher-init mappings beyond existing static evidence.")

    if p89 or pap or INIT_8928 in lit_targets or AUDIO_PLAYER in lit_targets:
        print("STRONGLY SUPPORTED: 8569 has a bounded static relationship to the confirmed Audio Player chain.")
        print("NEXT GATE: characterize that concrete relation and the visibility defect without choosing a patch yet.")
    else:
        print("NO bounded static convergence from 8569 to the confirmed Audio Player chain was found in this gate.")
        print("This weakens the '8569 is the Audio Player launcher' hypothesis; inspect 10348D05 semantics/strings/resources")
        print("and contrast it with 1033EF29 and 1033E815 before any menu mutation hypothesis is promoted.")

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
