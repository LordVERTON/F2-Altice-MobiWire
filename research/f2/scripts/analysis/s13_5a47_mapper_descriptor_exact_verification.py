#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.47 - MAPPER DESCRIPTOR EXACT VERIFICATION

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no phone access
- no write / erase
- no patch / repack

A.46 strong candidate
----------------------
Static 6-byte ID<->dense range table:
    table = 0xF037BF54
    records = 52
    bytes = 52 * 6 = 0x138
    end = 0xF037C08C

A.46 found the sole raw U32 pointer to table start at:
    0xF037C090

F02E01B0 and F02FEFB4 both access *(F007F048) as a descriptor:
    [descriptor + 0x04] = range-table pointer
    [descriptor + 0x08] = inclusive maximum range-record index

Because their binary search is:
    low = 0
    high = *(u16 *)(descriptor + 8)
    while (high >= low) ...

52 records therefore predict:
    descriptor candidate = 0xF037C08C
    descriptor + 4       = 0xF037BF54
    descriptor + 8       = 51 / 0x0033

This script verifies that exact geometry, audits F02FBC24 use of F007F048,
classifies references to the descriptor/table, and probes neighboring mapped
pointers as possible bridge material toward the 895-entry runtime registry.

No mutation is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

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

TITLE = "S13.5A.47 - MAPPER DESCRIPTOR EXACT VERIFICATION"

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
ROM_SIZE = 0x4C20C

ID_TO_DENSE = 0xF02E01B0
DENSE_TO_ID = 0xF02FEFB4
GET_PARENT_ID = 0xF02FBC24

REG_BASE_GLOBAL = 0xF007F044
REG_AUX_GLOBAL = 0xF007F048
REG_BOUND_GLOBAL = 0xF007F04C

TABLE = 0xF037BF54
RECORDS = 52
RECORD_BYTES = RECORDS * 6
TABLE_END = TABLE + RECORD_BYTES
DESC = 0xF037C08C
PTR_WORD = 0xF037C090
EXPECTED_MAX_INDEX = RECORDS - 1

PHYS_PTR_SITE = 0x10046310
PHYS_PTR_EXPECTED = 0xF037BF50

DENSE_ANCHORS = {
    0x8313: ("IMAGE_8313", 422),
    0x8321: ("IMAGE_8321", 436),
    0x8928: ("AUDIO_8928", 490),
    0xB0EC: ("KNOWN_PARENT_B0EC", 869),
    0xB6FF: ("FILTER_B6FF", 881),
    0xB700: ("FILTER_B700", 882),
    0xB702: ("FILTER_B702", 884),
    0xB709: ("B709_ROOT", 891),
}


def hdr(s: str) -> None:
    print()
    print("=" * 120)
    print(s)
    print("=" * 120, flush=True)


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
            raise ValueError(f"{self.name}: out-of-range 0x{addr:08X}+0x{n:X}")
        off = addr - self.base
        return self.data[off:off+n]

    def u16(self, addr: int) -> int:
        return struct.unpack_from("<H", self.read(addr, 2))[0]

    def u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.read(addr, 4))[0]


@dataclass(frozen=True)
class RangeRec:
    low: int
    high: int
    base: int

    @property
    def width(self) -> int:
        return self.high - self.low + 1

    @property
    def dense_end(self) -> int:
        return self.base + self.width - 1


class Auditor:
    def __init__(self, images: Sequence[Image]):
        self.images = list(images)
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

    def one_thumb(self, addr: int):
        addr &= ~1
        img = self.image_for(addr)
        if not img:
            return None
        width = min(4, img.end - addr)
        xs = list(self.thumb.disasm(img.read(addr, width), addr, count=1))
        return xs[0] if xs else None

    def reg_name(self, rid: int) -> str:
        try:
            return self.thumb.reg_name(rid).lower()
        except Exception:
            return f"reg{rid}"

    def reg_slot(self, rid: int) -> Optional[int]:
        n = self.reg_name(rid)
        aliases = {"sb": 9, "sl": 10, "fp": 11, "ip": 12}
        if n in aliases:
            return aliases[n]
        if n.startswith("r") and n[1:].isdigit():
            v = int(n[1:])
            return v if 0 <= v <= 12 else None
        return None

    def literal(self, ci) -> Optional[Tuple[int, int]]:
        if not ci.mnemonic.lower().startswith("ldr") or len(ci.operands) < 2:
            return None
        op = ci.operands[1]
        if op.type != CS_OP_MEM or op.mem.base != ARM_REG_PC:
            return None
        lit = (((ci.address + 4) & ~3) + int(op.mem.disp)) & 0xFFFFFFFF
        img = self.image_for(lit)
        if not img or not img.contains(lit, 4):
            return None
        return lit, img.u32(lit)

    @staticmethod
    def is_ret(ci) -> bool:
        m = ci.mnemonic.lower()
        o = ci.op_str.lower().replace(" ", "")
        return (
            (m.startswith("bx") and not m.startswith("blx") and o == "lr")
            or (m == "pop" and "pc" in o)
            or (m.startswith("ldm") and "pc" in o)
            or (m == "mov" and o == "pc,lr")
        )

    @staticmethod
    def is_uncond_jump(ci) -> bool:
        return ci.mnemonic.lower() in {"b", "b.w", "bx"}

    def cfg(self, entry: int, max_span: int = 0x500) -> Tuple[Dict[int, object], bool]:
        entry &= ~1
        img = self.image_for(entry)
        if not img:
            return {}, True

        lo, hi = entry, min(img.end, entry + max_span)
        q = deque([entry])
        seen = set()
        out = {}
        truncated = False

        while q and len(seen) < 4096:
            a = q.popleft() & ~1
            if a in seen:
                continue
            if not (lo <= a < hi):
                truncated = True
                continue
            ci = self.one_thumb(a)
            if not ci:
                continue
            seen.add(a)
            out[a] = ci

            if self.is_ret(ci):
                continue

            if ci.group(CS_GRP_CALL):
                q.append(a + ci.size)
                continue

            if ci.group(CS_GRP_JUMP):
                target = None
                if ci.operands and ci.operands[0].type == CS_OP_IMM:
                    target = int(ci.operands[0].imm) & 0xFFFFFFFF
                    target &= ~1
                if target is not None:
                    if lo <= target < hi:
                        q.append(target)
                    else:
                        truncated = True
                if not self.is_uncond_jump(ci):
                    q.append(a + ci.size)
                continue

            q.append(a + ci.size)

        if q:
            truncated = True
        return out, truncated

    def raw_u32_occurrences(self, value: int) -> List[Tuple[str, int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        out = []
        for img in self.images:
            pos = 0
            while True:
                off = img.data.find(needle, pos)
                if off < 0:
                    break
                out.append((img.name, img.base + off))
                pos = off + 1
        return out

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str, int, int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        out = set()

        for img in self.images:
            pos = 0
            literals = []
            while True:
                off = img.data.find(needle, pos)
                if off < 0:
                    break
                literals.append(img.base + off)
                pos = off + 1

            for lit in literals:
                lo = max(img.base, lit - 0x1100) & ~1
                for a in range(lo, lit, 2):
                    ci = self.one_thumb(a)
                    if not ci:
                        continue
                    lv = self.literal(ci)
                    if lv == (lit, value):
                        out.add((img.name, a, lit))

        return sorted(out)

    def descriptor_accesses(self, entry: int) -> Tuple[List[Tuple[int,str,int]], bool]:
        """
        Tiny provenance:
          ADDR_AUX = literal F007F048
          DESC     = *ADDR_AUX
        Report memory offsets accessed through DESC.
        """
        insns, trunc = self.cfg(entry)
        state: Dict[int, Set[str]] = {i: set() for i in range(13)}
        events = []

        for a in sorted(insns):
            ci = insns[a]
            m = ci.mnemonic.lower()
            ops = ci.operands
            lv = self.literal(ci)

            mems = [op for op in ops if op.type == CS_OP_MEM]
            if mems:
                mem = mems[0].mem
                bs = self.reg_slot(int(mem.base)) if mem.base else None
                tags = state.get(bs, set()) if bs is not None else set()
                if "DESC" in tags:
                    events.append((a, f"{ci.mnemonic} {ci.op_str}", int(mem.disp)))

            if ci.group(CS_GRP_CALL):
                for r in range(4):
                    state[r] = set()
                continue

            if not ops or ops[0].type != CS_OP_REG:
                continue
            ds = self.reg_slot(int(ops[0].reg))
            if ds is None:
                continue

            if lv is not None and m.startswith("ldr"):
                _, value = lv
                state[ds] = {"ADDR_AUX"} if value == REG_AUX_GLOBAL else set()
                continue

            if m.startswith("ldr") and len(ops) >= 2 and ops[1].type == CS_OP_MEM:
                mem = ops[1].mem
                bs = self.reg_slot(int(mem.base)) if mem.base else None
                tags = state.get(bs, set()) if bs is not None else set()
                if "ADDR_AUX" in tags:
                    state[ds] = {"DESC"}
                else:
                    state[ds] = set()
                continue

            if m in {"mov", "movs", "mov.w"} and len(ops) >= 2 and ops[1].type == CS_OP_REG:
                ss = self.reg_slot(int(ops[1].reg))
                state[ds] = set(state.get(ss, set())) if ss is not None else set()
                continue

            state[ds] = set()

        return events, trunc


def load_guard(path: Path, size: int, digest: str, name: str) -> bytes:
    print(f"Loading {name}: {path}", flush=True)
    if not path.is_file():
        raise SystemExit(f"Missing {name}: {path}")
    data = path.read_bytes()
    got = sha256(data)
    ok = len(data) == size and got == digest
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {got}")
    print(f"  guard  = {'PASS' if ok else 'FAIL'}")
    if not ok:
        raise SystemExit(f"ABORT: canonical {name} guard failed")
    return data


def decode_table(img: Image) -> List[RangeRec]:
    out = []
    for i in range(RECORDS):
        a = TABLE + i * 6
        lo, hi, base = struct.unpack("<HHH", img.read(a, 6))
        out.append(RangeRec(lo, hi, base))
    return out


def map_id(recs: Sequence[RangeRec], pid: int) -> Optional[int]:
    lo, hi = 0, len(recs) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        r = recs[mid]
        if pid < r.low:
            hi = mid - 1
        elif pid > r.high:
            lo = mid + 1
        else:
            return r.base + pid - r.low
    return None


def inverse(recs: Sequence[RangeRec], dense: int) -> Optional[int]:
    for r in recs:
        if r.base <= dense <= r.dense_end:
            return r.low + dense - r.base
    return None


def ascii_bytes(b: bytes) -> str:
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def dump_region(img: Image, start: int, end: int) -> None:
    for a in range(start, end, 4):
        n = min(4, end - a)
        b = img.read(a, n)
        if n == 4:
            v = struct.unpack("<I", b)[0]
            print(
                f"0x{a:08X}: "
                + " ".join(f"{x:02X}" for x in b)
                + f"  u32=0x{v:08X} ascii='{ascii_bytes(b)}'"
            )
        else:
            print(f"0x{a:08X}: " + " ".join(f"{x:02X}" for x in b))


def classify_ptr(aud: Auditor, v: int) -> str:
    img = aud.image_for(v)
    if img:
        return f"PTR->{img.name}:0x{v:08X}"
    if 0xF0000000 <= v < 0xF1000000:
        return f"RAM_PTR:0x{v:08X}"
    if 0x10000000 <= v < 0x11000000:
        return f"ROMISH_PTR:0x{v:08X}"
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument(
        "--boot",
        default=r"C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin",
    )
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
    ap.add_argument(
        "--dump",
        default=r"C:\Users\verto\mtkclient\research\f2\data\dumps\mobiwire_dump_2.bin",
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

    hdr("A. CANONICAL INPUT GUARDS")
    ad = load_guard(Path(args.alice), ALICE_SIZE, ALICE_SHA256, "ALICE")
    bd = load_guard(Path(args.boot), BOOT_SIZE, BOOT_SHA256, "BOOT_ZIMAGE")
    zd = load_guard(Path(args.zimage), ZIMAGE_SIZE, ZIMAGE_SHA256, "ZIMAGE")
    dd = load_guard(Path(args.dump), DUMP_SIZE, DUMP_SHA256, "DUMP")

    images = [
        Image("ALICE", ad, ALICE_BASE),
        Image("BOOT_ZIMAGE", bd, BOOT_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
        Image("PHYSICAL_ROM", dd[:ROM_SIZE], ROM_BASE),
    ]
    aud = Auditor(images)
    zimg = aud.image_for(TABLE)
    prom = aud.image_for(PHYS_PTR_SITE)
    assert zimg is not None and prom is not None

    hdr("B. EXACT TABLE GEOMETRY")
    print(f"TABLE            = 0x{TABLE:08X}")
    print(f"RECORDS          = {RECORDS}")
    print(f"RECORD_BYTES     = 0x{RECORD_BYTES:X}")
    print(f"TABLE_END        = 0x{TABLE_END:08X}")
    print(f"DESC candidate   = 0x{DESC:08X}")
    print(f"PTR_WORD         = 0x{PTR_WORD:08X}")
    print(f"EXPECTED +8 max  = {EXPECTED_MAX_INDEX} / 0x{EXPECTED_MAX_INDEX:04X}")
    print()
    print(f"TABLE_END == DESC                : {TABLE_END == DESC}")
    print(f"PTR_WORD == DESC+4               : {PTR_WORD == DESC + 4}")

    hdr("C. DESCRIPTOR WINDOW F037C080..F037C0B0")
    dump_region(zimg, 0xF037C080, 0xF037C0B0)

    d0 = zimg.u32(DESC + 0)
    d4 = zimg.u32(DESC + 4)
    d8u16 = zimg.u16(DESC + 8)
    dAu16 = zimg.u16(DESC + 0xA)
    d8u32 = zimg.u32(DESC + 8)

    print()
    print(f"descriptor+0x00 u32 = 0x{d0:08X} {classify_ptr(aud, d0)}")
    print(f"descriptor+0x04 u32 = 0x{d4:08X} {classify_ptr(aud, d4)}")
    print(f"descriptor+0x08 u16 = 0x{d8u16:04X} ({d8u16})")
    print(f"descriptor+0x0A u16 = 0x{dAu16:04X} ({dAu16})")
    print(f"descriptor+0x08 u32 = 0x{d8u32:08X}")
    print()

    ptr_match = d4 == TABLE
    max_match = d8u16 == EXPECTED_MAX_INDEX
    geom_match = TABLE_END == DESC and PTR_WORD == DESC + 4
    print(f"ABI +4 TABLE MATCH               = {'PASS' if ptr_match else 'FAIL'}")
    print(f"ABI +8 MAX_INDEX MATCH           = {'PASS' if max_match else 'FAIL'}")
    print(f"GEOMETRY MATCH                   = {'PASS' if geom_match else 'FAIL'}")
    exact_desc = ptr_match and max_match and geom_match
    print(f"EXACT DESCRIPTOR MATCH           = {'PASS' if exact_desc else 'FAIL'}")

    hdr("D. RANGE TABLE STRUCTURAL REVALIDATION")
    recs = decode_table(zimg)
    strict = True
    first_base = recs[0].base if recs else None

    for i, r in enumerate(recs):
        if r.low > r.high:
            strict = False
        if i:
            p = recs[i-1]
            if r.low <= p.high:
                strict = False
            if r.base != p.base + p.width:
                strict = False
        anchors = []
        for pid, (name, expected_dense) in DENSE_ANCHORS.items():
            if r.low <= pid <= r.high:
                anchors.append(f"0x{pid:04X}<{name}>")
        suffix = " anchors=" + ",".join(anchors) if anchors else ""
        print(
            f"rec[{i:02d}] 0x{r.low:04X}..0x{r.high:04X} "
            f"base={r.base:3d} dense_end={r.dense_end:3d}{suffix}"
        )

    print()
    print(f"strict sorted/contiguous = {'PASS' if strict else 'FAIL'}")
    print(f"first dense base         = {first_base}")
    print(f"last dense index         = {recs[-1].dense_end if recs else 'NONE'}")

    anchor_ok = True
    for pid, (name, expected_dense) in DENSE_ANCHORS.items():
        got = map_id(recs, pid)
        back = inverse(recs, got) if got is not None else None
        ok = got == expected_dense and back == pid
        anchor_ok &= ok
        print(
            f"0x{pid:04X} <{name}> -> "
            f"{got if got is not None else 'NONE'} -> "
            f"{('0x%04X' % back) if back is not None else 'NONE'} "
            f"expected={expected_dense} {'PASS' if ok else 'FAIL'}"
        )
    print(f"ANCHOR REVALIDATION = {'PASS' if anchor_ok else 'FAIL'}")

    hdr("E. F007F048 DESCRIPTOR FIELD ACCESS AUDIT")
    for entry, name in [
        (ID_TO_DENSE, "F02E01B0 ID_TO_DENSE"),
        (DENSE_TO_ID, "F02FEFB4 DENSE_TO_ID"),
        (GET_PARENT_ID, "F02FBC24 GET_PARENT_ID"),
    ]:
        events, trunc = aud.descriptor_accesses(entry)
        print()
        print(f"{name}: truncated={trunc} descriptor_accesses={len(events)}")
        for site, text, disp in events:
            print(f"  0x{site:08X}: {text}  [DESC{disp:+#x}]")
        if not events:
            print("  no descriptor-derived memory access recovered by local provenance pass")

    hdr("F. FULL GET_PARENT_ID CFG")
    insns, trunc = aud.cfg(GET_PARENT_ID, 0x700)
    print(f"entry=0x{GET_PARENT_ID:08X} instructions={len(insns)} truncated={trunc}")
    for a in sorted(insns):
        ci = insns[a]
        suffix = ""
        lv = aud.literal(ci)
        if lv:
            la, v = lv
            label = ""
            if v == REG_AUX_GLOBAL:
                label = "<REG_AUX_GLOBAL>"
            elif v == REG_BASE_GLOBAL:
                label = "<REG_BASE_GLOBAL>"
            elif v == REG_BOUND_GLOBAL:
                label = "<REG_BOUND_GLOBAL>"
            elif v == TABLE:
                label = "<TABLE>"
            elif v == DESC:
                label = "<DESC>"
            suffix = f" ; literal@0x{la:08X}=0x{v:08X}{label}"
        print(f"0x{a:08X}: {ci.mnemonic:<9} {ci.op_str}{suffix}")

    hdr("G. RAW POINTER / EXACT CODE-XREF SURFACE")
    targets = [
        (TABLE, "TABLE"),
        (DESC, "DESC"),
        (PTR_WORD, "PTR_WORD_ADDRESS"),
        (TABLE - 4, "TABLE_MINUS_4"),
        (TABLE_END, "TABLE_END/DESC"),
    ]
    for value, name in targets:
        raw = aud.raw_u32_occurrences(value)
        xrefs = aud.exact_literal_xrefs(value)
        print()
        print(f"0x{value:08X} <{name}> raw_u32={len(raw)} exact_code_xrefs={len(xrefs)}")
        for img_name, addr in raw[:50]:
            print(f"  RAW   {img_name:12s} 0x{addr:08X}")
        for img_name, site, lit in xrefs[:50]:
            print(f"  XREF  {img_name:12s} site=0x{site:08X} literal=0x{lit:08X}")

    hdr("H. PHYSICAL-ROM POINTER CONTEXT 0x10046310")
    phys_val = prom.u32(PHYS_PTR_SITE)
    print(f"0x{PHYS_PTR_SITE:08X} = 0x{phys_val:08X}")
    print(f"expected             = 0x{PHYS_PTR_EXPECTED:08X}")
    print(f"match                = {'YES' if phys_val == PHYS_PTR_EXPECTED else 'NO'}")
    print()
    dump_region(prom, PHYS_PTR_SITE - 0x20, PHYS_PTR_SITE + 0x30)

    hdr("I. DESCRIPTOR-NEIGHBOR POINTER PROBES")
    probe_start = DESC - 0x20
    probe_end = DESC + 0x60
    for a in range(probe_start, probe_end, 4):
        v = zimg.u32(a)
        cls = classify_ptr(aud, v)
        if cls:
            print(f"0x{a:08X}: 0x{v:08X} {cls}")

    hdr("J. POSSIBLE STATIC REGISTRY-BACKING PROBES")
    REG_RECORDS = 895
    REG_STRIDE = 0x10
    REG_BYTES = REG_RECORDS * REG_STRIDE
    print(f"required registry bytes for dense 0..894 = 0x{REG_BYTES:X}")

    candidates = []
    for a in range(probe_start, probe_end, 4):
        v = zimg.u32(a)
        img = aud.image_for(v)
        if img and img.contains(v, REG_BYTES):
            candidates.append((a, v, img))

    print(f"neighbor mapped pointers large enough for 895x0x10 = {len(candidates)}")
    for site, base, img in candidates:
        print()
        print(f"candidate pointer @0x{site:08X} -> {img.name}:0x{base:08X}")
        plausible = 0
        for pid, (name, dense) in DENSE_ANCHORS.items():
            rec = base + dense * REG_STRIDE
            raw = img.read(rec, REG_STRIDE)
            u0 = struct.unpack_from("<H", raw, 0)[0]
            u2 = struct.unpack_from("<H", raw, 2)[0]
            u8 = struct.unpack_from("<H", raw, 8)[0]
            uc = struct.unpack_from("<I", raw, 0xC)[0]
            if u2 < 0x100:
                plausible += 1
            print(
                f"  dense={dense:3d} id=0x{pid:04X}<{name}> "
                f"rec=0x{rec:08X} +0=0x{u0:04X} +2(count)=0x{u2:04X} "
                f"+8=0x{u8:04X} +C=0x{uc:08X} {classify_ptr(aud, uc)}"
            )
        print(f"  small-child-count fields among anchors = {plausible}/{len(DENSE_ANCHORS)}")

    hdr("K. DECISION GATE")
    promoted = exact_desc and strict and anchor_ok
    print(f"exact descriptor ABI match      = {exact_desc}")
    print(f"strict table structure          = {strict}")
    print(f"anchor revalidation             = {anchor_ok}")
    print(f"STATIC MAPPER DESCRIPTOR PROVEN = {'YES' if promoted else 'NO'}")
    print()
    if promoted:
        print("Promotable dense indices:")
        for pid, (name, dense) in DENSE_ANCHORS.items():
            print(f"  0x{pid:04X} <{name}> = dense {dense}")
        print()
        print("Next gate:")
        print("  use F02FBC24 descriptor semantics and any descriptor-neighbor backing")
        print("  pointer evidence to recover the actual F007F044 registry record array")
        print("  or its initializer; do not return to broad arithmetic scans.")
    else:
        print("Do NOT promote dense indices yet; inspect whichever exact ABI/structure")
        print("check failed before proceeding.")

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
