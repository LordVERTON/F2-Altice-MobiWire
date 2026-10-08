#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.45 - REG_ROOT F02FDAA8 / F03492xx STATIC TABLE AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no write / erase
- no phone access

Why A.45 exists
---------------
A.44's raw descriptor scan was intentionally broad and produced thousands of
arithmetic false positives. A concrete false-positive family appeared around
F02FDB70/F02FDB74.

But A.43 had already established that F02FDB74 is a literal consumed by
F02FDAA8 for F007F040 (REG_ROOT). The same local literal pool contains static
F03492xx addresses that A.44 misread as copy-descriptor fields.

A.45 therefore audits the REAL relation:
    F02FDAA8
      <-> F007F040 (REG_ROOT)
      <-> F007F078
      <-> F0349214
      <-> F0349290
      <-> F0349292

Goals
-----
1. reconstruct the exact CFG of F02FDAA8;
2. enumerate every PC literal actually consumed by that function;
3. annotate dataflow from tracked global/static-table addresses;
4. classify memory accesses through those tracked addresses;
5. dump the static F03491E0..F03492C0 family in multiple widths;
6. find all exact code xrefs to tracked static tables and resolve owners;
7. enumerate direct callers of F02FDAA8 and nearby focus IDs;
8. decide whether F03492xx participates in a lookup tied to REG_ROOT.

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

TITLE = "S13.5A.45 - REG_ROOT F02FDAA8 / F03492xx STATIC TABLE AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

BOOT_BASE = 0xF01F19E4
BOOT_SIZE = 0x4B06C
BOOT_SHA256 = "aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

TARGET_FN = 0xF02FDAA8
LITERAL_POOL_START = 0xF02FDB60
LITERAL_POOL_END = 0xF02FDB90

STATIC_DUMP_START = 0xF03491E0
STATIC_DUMP_END = 0xF03492C0

TRACKED = {
    0xF007F040: "REG_ROOT",
    0xF007F078: "GLOBAL_F078",
    0xF0349214: "STATIC_9214",
    0xF0349290: "STATIC_9290",
    0xF0349292: "STATIC_9292",
}

FOCUS_IDS = {
    0xB709: "B709_ROOT",
    0x8313: "IMAGE_8313",
    0x8321: "IMAGE_8321",
    0x8928: "AUDIO_8928",
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

    def read_u16(self, addr: int) -> int:
        return struct.unpack_from("<H", self.read(addr, 2))[0]

    def read_u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.read(addr, 4))[0]


@dataclass(frozen=True)
class Call:
    image: str
    site: int
    raw_target: int
    effective_target: int
    veneer: Optional[int]


@dataclass
class FnResult:
    entry: int
    visited: Dict[int, object]
    truncated: bool


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
        a = (addr & 0xFFFFFFFF) & ~1
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

    def reg_name(self, reg_id: int) -> str:
        try:
            return self.thumb.reg_name(reg_id).lower()
        except Exception:
            return f"reg{reg_id}"

    def reg_slot(self, reg_id: int) -> Optional[int]:
        n = self.reg_name(reg_id)
        aliases = {"sb": 9, "sl": 10, "fp": 11, "ip": 12}
        if n in aliases:
            return aliases[n]
        if n.startswith("r") and n[1:].isdigit():
            v = int(n[1:])
            if 0 <= v <= 12:
                return v
        return None

    def raw_arm_veneer_target(self, addr: int) -> Optional[int]:
        addr = (addr & 0xFFFFFFFF) & ~3
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
        print(f"unique effective targets = {len(self.calls_by_target)}")

    def build_prologue_index(self) -> None:
        hdr("C. PROLOGUE INDEX")
        pro = set()
        for img in self.images:
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
        print(f"prologue candidates = {len(self.prologues)}")

    def resolve_owner(self, site: int, max_back: int = 0x1000) -> Tuple[int, str]:
        img = self.image_for(site)
        if not img:
            return site & ~1, "OUTSIDE"

        lo = max(img.base, site - max_back)

        both = [
            a for a in self.prologues
            if lo <= a <= site and a in self.call_targets and self.image_for(a) == img
        ]
        if both:
            return max(both), "CALL_TARGET+PROLOGUE"

        pros = [a for a in self.prologues if lo <= a <= site and self.image_for(a) == img]
        if pros:
            return max(pros), "PROLOGUE_ONLY"

        cts = [a for a in self.call_targets if lo <= a <= site and self.image_for(a) == img]
        if cts:
            return max(cts), "CALL_TARGET_ONLY"

        return site & ~1, "UNRESOLVED"

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str, int, int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        out = set()

        for img in self.images:
            start = 0
            lit_addrs = []
            while True:
                off = img.data.find(needle, start)
                if off < 0:
                    break
                lit_addrs.append(img.base + off)
                start = off + 1

            for lit_addr in lit_addrs:
                lo = max(img.base, lit_addr - 0x1100) & ~1
                for a in range(lo, lit_addr, 2):
                    ci = self.cs_one(a)
                    if ci is None:
                        continue
                    lv = self.literal_value(ci)
                    if lv and lv[0] == lit_addr and lv[1] == value:
                        out.add((img.name, a, lit_addr))

        return sorted(out)

    def audit_function(self, entry: int, max_span: int = 0x500) -> FnResult:
        entry &= ~1
        img = self.image_for(entry)
        if not img:
            return FnResult(entry, {}, True)

        lo = entry
        hi = min(img.end, entry + max_span)
        q = deque([entry])
        seen = set()
        visited = {}
        truncated = False

        while q and len(seen) < 3000:
            addr = (q.popleft() & 0xFFFFFFFF) & ~1
            if addr in seen:
                continue
            if addr < lo or addr >= hi:
                truncated = True
                continue

            ci = self.cs_one(addr)
            if ci is None:
                continue

            seen.add(addr)
            visited[addr] = ci

            if self.is_return(ci):
                continue

            # CALL = current-function fallthrough.
            if ci.group(CS_GRP_CALL):
                q.append((addr + ci.size) & 0xFFFFFFFF)
                continue

            if ci.group(CS_GRP_JUMP):
                direct = None
                if ci.operands and ci.operands[0].type == CS_OP_IMM:
                    direct = (int(ci.operands[0].imm) & 0xFFFFFFFF) & ~1

                if direct is not None:
                    if lo <= direct < hi:
                        q.append(direct)
                    else:
                        truncated = True

                if not self.is_unconditional_jump(ci):
                    q.append((addr + ci.size) & 0xFFFFFFFF)
                continue

            q.append((addr + ci.size) & 0xFFFFFFFF)

        if q:
            truncated = True

        return FnResult(entry, visited, truncated)

    def local_constant_args(self, callsite: int, back: int = 0x80) -> Dict[str, str]:
        img = self.image_for(callsite)
        if not img:
            return {}

        lo = max(img.base, callsite - back) & ~1
        decoded = []
        a = lo
        while a < callsite:
            ci = self.cs_one(a)
            if ci:
                decoded.append(ci)
                a += ci.size
            else:
                a += 2

        # Reset at last control transfer.
        cut = 0
        for i, ci in enumerate(decoded):
            if ci.group(CS_GRP_CALL) or ci.group(CS_GRP_JUMP):
                cut = i + 1
        decoded = decoded[cut:]

        state: Dict[str, str] = {}
        for ci in decoded:
            if not ci.operands or ci.operands[0].type != CS_OP_REG:
                continue
            dst = self.reg_name(ci.operands[0].reg)
            if dst not in {"r0", "r1", "r2", "r3"}:
                continue

            m = ci.mnemonic.lower()
            lv = self.literal_value(ci)
            if m.startswith("ldr") and lv is not None:
                value = lv[1] & 0xFFFFFFFF
                label = ""
                if (value & 0xFFFF) in FOCUS_IDS:
                    label = f"<{FOCUS_IDS[value & 0xFFFF]}>"
                state[dst] = f"0x{value:08X}{label}"
                continue

            if m in {"mov", "movs", "mov.w", "movw"} and len(ci.operands) >= 2:
                src = ci.operands[1]
                if src.type == CS_OP_IMM:
                    value = int(src.imm) & 0xFFFFFFFF
                    label = ""
                    if (value & 0xFFFF) in FOCUS_IDS:
                        label = f"<{FOCUS_IDS[value & 0xFFFF]}>"
                    state[dst] = f"0x{value:X}{label}"
                elif src.type == CS_OP_REG:
                    state[dst] = state.get(self.reg_name(src.reg), self.reg_name(src.reg))
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
    print(f"  guard  = {'PASS' if ok else 'FAIL'}")
    if not ok:
        raise SystemExit(f"ABORT: canonical {name} guard failed")
    return data


def ascii4(v: int) -> str:
    b = struct.pack("<I", v)
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument(
        "--boot",
        default=r"C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin",
    )
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
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

    aud = Auditor([
        Image("ALICE", ad, ALICE_BASE),
        Image("BOOT_ZIMAGE", bd, BOOT_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
    ])

    aud.build_call_index()
    aud.build_prologue_index()

    hdr("D. TARGET FUNCTION CFG / DISASSEMBLY")
    fn = aud.audit_function(TARGET_FN, max_span=0x500)
    print(
        f"entry=0x{TARGET_FN:08X} instructions={len(fn.visited)} "
        f"truncated={fn.truncated}"
    )

    if not fn.visited:
        print("ABORT ANALYTICAL PROMOTION: target function could not be decoded.")
        return 2

    # Symbolic provenance: r0..r12 -> small set of symbolic strings.
    state: Dict[int, Set[str]] = {i: set() for i in range(13)}
    events = []

    def slot(reg_id: int) -> Optional[int]:
        return aud.reg_slot(reg_id)

    def st(slot_id: Optional[int]) -> Set[str]:
        return set() if slot_id is None else set(state.get(slot_id, set()))

    def setst(slot_id: Optional[int], vals: Iterable[str]) -> None:
        if slot_id is None:
            return
        state[slot_id] = set(vals)

    for addr in sorted(fn.visited):
        ci = fn.visited[addr]
        tags = []

        lv = aud.literal_value(ci)
        if lv is not None:
            lit_addr, value = lv
            label = TRACKED.get(value)
            tags.append(
                f"LITERAL@0x{lit_addr:08X}=0x{value:08X}"
                + (f"<{label}>" if label else "")
            )

        # Report calls.
        if ci.group(CS_GRP_CALL) and ci.operands and ci.operands[0].type == CS_OP_IMM:
            raw = int(ci.operands[0].imm) & 0xFFFFFFFF
            eff, veneer = aud.normalize_target(raw)
            tags.append(
                f"CALL=0x{eff:08X}"
                + (f" via=0x{veneer:08X}" if veneer is not None else "")
            )

        # Semantic memory annotation before destination changes.
        m = ci.mnemonic.lower()
        memops = [op for op in ci.operands if op.type == CS_OP_MEM]
        if memops:
            mem = memops[0].mem
            bs = slot(int(mem.base)) if mem.base else None
            ix = slot(int(mem.index)) if mem.index else None
            btags = st(bs)
            itags = st(ix)

            if btags:
                tags.append("BASE=" + "|".join(sorted(btags)))
            if itags:
                tags.append("INDEX=" + "|".join(sorted(itags)))

            for bt in btags:
                if bt.startswith("ADDR:") or bt.startswith("VALUE:") or bt.startswith("DERIVED:"):
                    events.append(
                        (
                            addr,
                            "MEM_ACCESS",
                            ci.mnemonic,
                            ci.op_str,
                            bt,
                            "|".join(sorted(itags)) if itags else "",
                            int(mem.disp),
                        )
                    )

        suffix = " ; " + " | ".join(tags) if tags else ""
        print(f"0x{addr:08X}: {ci.mnemonic:<9} {ci.op_str}{suffix}")

        # Calls clobber r0-r3 after reporting.
        if ci.group(CS_GRP_CALL):
            for r in range(4):
                state[r] = set()
            continue

        if not ci.operands or ci.operands[0].type != CS_OP_REG:
            continue

        ds = slot(int(ci.operands[0].reg))
        if ds is None:
            continue

        # PC literal -> tracked absolute address.
        if m.startswith("ldr") and lv is not None:
            value = lv[1] & 0xFFFFFFFF
            if value in TRACKED:
                setst(ds, [f"ADDR:{TRACKED[value]}"])
            else:
                setst(ds, [])
            continue

        # General LDR through tracked address/value.
        if m.startswith("ldr") and len(ci.operands) >= 2 and ci.operands[1].type == CS_OP_MEM:
            mem = ci.operands[1].mem
            bs = slot(int(mem.base)) if mem.base else None
            btags = st(bs)
            derived = []
            for bt in btags:
                if bt.startswith("ADDR:"):
                    derived.append("VALUE:" + bt.split(":", 1)[1])
                elif bt.startswith(("VALUE:", "DERIVED:")):
                    derived.append("DERIVED:" + bt.split(":", 1)[1])
            setst(ds, derived)
            continue

        # MOV copies symbolic provenance.
        if m in {"mov", "movs", "mov.w"} and len(ci.operands) >= 2:
            src = ci.operands[1]
            if src.type == CS_OP_REG:
                ss = slot(int(src.reg))
                setst(ds, st(ss))
            else:
                setst(ds, [])
            continue

        # ADD/SUB/LSL preserve a "derived from X" marker.
        if m.startswith(("add", "sub", "lsl", "lsr", "asr", "and", "orr", "eor")):
            union = set()
            for op in ci.operands[1:]:
                if op.type == CS_OP_REG:
                    union |= st(slot(int(op.reg)))
            derived = []
            for bt in union:
                name = bt.split(":", 1)[1] if ":" in bt else bt
                derived.append("DERIVED:" + name)
            setst(ds, derived)
            continue

        setst(ds, [])

    print()
    print(f"CFG COMPLETE = {'YES' if not fn.truncated else 'NO'}")

    hdr("E. TARGET-FUNCTION LITERAL CENSUS")
    function_literals = []
    for addr in sorted(fn.visited):
        ci = fn.visited[addr]
        lv = aud.literal_value(ci)
        if lv:
            function_literals.append((addr, lv[0], lv[1]))

    print(f"PC literals consumed by F02FDAA8 = {len(function_literals)}")
    for site, lit_addr, value in function_literals:
        print(
            f"site=0x{site:08X} literal_word=0x{lit_addr:08X} "
            f"value=0x{value:08X}"
            + (f" <{TRACKED[value]}>" if value in TRACKED else "")
        )

    hdr("F. LOCAL LITERAL POOL RAW WORDS")
    zi = aud.image_for(LITERAL_POOL_START)
    if zi is None:
        print("literal pool outside known image")
    else:
        for a in range(LITERAL_POOL_START, LITERAL_POOL_END, 4):
            v = zi.read_u32(a)
            consumers = [site for site, la, _ in function_literals if la == a]
            print(
                f"0x{a:08X}: 0x{v:08X} ascii='{ascii4(v)}'"
                + (f" <{TRACKED[v]}>" if v in TRACKED else "")
                + (
                    " consumers=" + ",".join(f"0x{x:08X}" for x in consumers)
                    if consumers else " consumers=NONE_IN_TARGET"
                )
            )

    hdr("G. TRACKED-PROVENANCE MEMORY EVENTS")
    print(f"events = {len(events)}")
    for e in events:
        addr, kind, mnemonic, op_str, base_tag, index_tag, disp = e
        print(
            f"0x{addr:08X}: {kind} {mnemonic} {op_str} "
            f"base={base_tag} index={index_tag or '-'} disp={disp:+#x}"
        )

    hdr("H. STATIC TABLE FAMILY DUMP F03491E0..F03492C0")
    zimg = aud.image_for(STATIC_DUMP_START)
    if zimg is None:
        print("static dump range outside known image")
    else:
        print("[U32 aligned view]")
        for a in range(STATIC_DUMP_START, STATIC_DUMP_END, 4):
            v = zimg.read_u32(a)
            print(
                f"0x{a:08X}: 0x{v:08X} "
                f"lo16=0x{v & 0xFFFF:04X} hi16=0x{(v >> 16) & 0xFFFF:04X} "
                f"ascii='{ascii4(v)}'"
                + (f" <TRACKED:{TRACKED[a]}>" if a in TRACKED else "")
            )

        print()
        print("[U16 view]")
        row = []
        for a in range(STATIC_DUMP_START, STATIC_DUMP_END, 2):
            v = zimg.read_u16(a)
            row.append(f"{a:08X}:{v:04X}")
            if len(row) == 8:
                print("  " + "  ".join(row))
                row = []
        if row:
            print("  " + "  ".join(row))

        print()
        print("[FOCUS U16 occurrences in static family]")
        for value, name in FOCUS_IDS.items():
            hits = []
            needle = struct.pack("<H", value)
            blob = zimg.read(STATIC_DUMP_START, STATIC_DUMP_END - STATIC_DUMP_START)
            start = 0
            while True:
                off = blob.find(needle, start)
                if off < 0:
                    break
                hits.append(STATIC_DUMP_START + off)
                start = off + 1
            print(
                f"0x{value:04X} <{name}> count={len(hits)} "
                + " ".join(f"0x{x:08X}" for x in hits)
            )

    hdr("I. EXACT XREFS TO TRACKED ADDRESSES")
    tracked_xrefs = {}
    for value, name in TRACKED.items():
        hits = aud.exact_literal_xrefs(value)
        tracked_xrefs[value] = hits
        print()
        print(f"0x{value:08X} <{name}> exact_xrefs={len(hits)}")
        for img_name, site, lit_addr in hits:
            owner, reason = aud.resolve_owner(site)
            mark = " <TARGET_FN>" if owner == TARGET_FN else ""
            print(
                f"  {img_name:12s} site=0x{site:08X} literal=0x{lit_addr:08X} "
                f"owner=0x{owner:08X} reason={reason}{mark}"
            )

    hdr("J. DIRECT CALLERS OF F02FDAA8")
    callers = aud.calls_by_target.get(TARGET_FN, [])
    print(f"direct callers = {len(callers)}")

    for c in callers:
        args = aud.local_constant_args(c.site)
        argtext = ", ".join(f"{k}={v}" for k, v in sorted(args.items()))

        img = aud.image_for(c.site)
        nearby_focus = []
        if img:
            lo = max(img.base, c.site - 0x80)
            hi = min(img.end, c.site + 0x40)
            blob = img.read(lo, hi - lo)
            for value, name in FOCUS_IDS.items():
                needle = struct.pack("<H", value)
                pos = 0
                count = 0
                locs = []
                while True:
                    off = blob.find(needle, pos)
                    if off < 0:
                        break
                    count += 1
                    locs.append(lo + off)
                    pos = off + 1
                if count:
                    nearby_focus.append(
                        f"0x{value:04X}<{name}>@" + ",".join(f"0x{x:08X}" for x in locs)
                    )

        print(
            f"  {c.image:12s} site=0x{c.site:08X}"
            + (f" via=0x{c.veneer:08X}" if c.veneer is not None else "")
            + (f" args[{argtext}]" if argtext else "")
            + (f" focus[{'; '.join(nearby_focus)}]" if nearby_focus else "")
        )

    hdr("K. STRUCTURAL DECISION GATE")
    target_tracked = [
        (site, value)
        for site, _, value in function_literals
        if value in TRACKED
    ]

    other_static_xrefs = 0
    for value in (0xF0349214, 0xF0349290, 0xF0349292):
        for img_name, site, lit_addr in tracked_xrefs.get(value, []):
            owner, _ = aud.resolve_owner(site)
            if owner != TARGET_FN:
                other_static_xrefs += 1

    regroot_consumed = any(value == 0xF007F040 for _, value in target_tracked)
    static_consumed = any(value in {0xF0349214, 0xF0349290, 0xF0349292} for _, value in target_tracked)

    print(f"target CFG truncated                    = {fn.truncated}")
    print(f"tracked literals consumed by target     = {len(target_tracked)}")
    print(f"REG_ROOT consumed by target             = {regroot_consumed}")
    print(f"F03492xx consumed by target             = {static_consumed}")
    print(f"tracked provenance memory events        = {len(events)}")
    print(f"other-owner exact F03492xx xrefs        = {other_static_xrefs}")
    print(f"direct callers of F02FDAA8              = {len(callers)}")
    print()
    print("Interpretation:")
    print("  - REG_ROOT + F03492xx consumed in the same proven CFG is real structural")
    print("    evidence; unlike A.44 raw descriptor arithmetic, it is code-backed.")
    print("  - The provenance events show whether F03492xx is used as an indexed lookup,")
    print("    compared with REG_ROOT-derived state, or merely loaded independently.")
    print("  - Other-owner xrefs can identify the semantic family of each static table.")
    print("  - Focus-ID proximity at callers is supporting evidence only, never membership proof.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
