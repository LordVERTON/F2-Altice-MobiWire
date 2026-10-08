#!/usr/bin/env python3
"""
S13.5A.4 - canonical ALICE + registry population / constructor audit

STRICTLY OFFLINE / READ-ONLY.

Why this follows S13.5A.3
-------------------------
S13.5A.3 established:
  - F02E01B0 performs an ID -> registry-index lookup using F007F048.
  - F007F044 is the registry-record base global.
  - no direct writer to F007F044/F007F048 was found in canonical ZIMAGE.
  - one static GET_CHILD_COUNT parent ID was recovered: 0xB0EC.
  - the 0xB0EC caller tests child_count == 1, making it an unlikely visible
    Multimedia parent (which already exposes at least Image Viewer + FM Radio).
  - ENUM_CHILD_IDS has no direct BL and no exact raw function pointer inside
    canonical ZIMAGE.

This audit therefore:
  A. verifies canonical ZIMAGE + canonical ALICE identities;
  B. dumps the full F02E01B0 range-mapper and F02FEFB4 inverse-mapper candidate;
  C. scans canonical ALICE for F007F044/F007F048 references and classifies
     read/write/pass-to-call behavior;
  D. scans both images for provider pointers / Thumb pointers and LDR-literal
     veneers to GET_CHILD_COUNT / ENUM_CHILD_IDS / GET_CHILD_META;
  E. audits the constructor-like function immediately following GET_CHILD_COUNT:
       F02D8888
     finds all direct callers / function pointers, and backward-slices r0/r1/r2;
  F. when a sliced argument is a pointer into ZIMAGE/ALICE, dumps nearby U16s
     and highlights 0x8313 / 0x8321 / 0x8928;
  G. searches 0xB0EC / 0xB0ED and target resolver IDs as supporting evidence;
  H. emits a strict decision gate. It does NOT build a patch.

No USB/COM, no phone access, no LZMA/repack, no firmware write.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
except Exception as exc:
    print(f"ERROR: capstone import failed: {exc}")
    raise SystemExit(2)


# -----------------------------------------------------------------------------
# Canonical identities
# -----------------------------------------------------------------------------

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

GET_CHILD_COUNT = 0xF02D8870
ENUM_CHILD_IDS = 0xF032ACDC
GET_CHILD_META = 0xF02F9CCC
PARENT_TO_INDEX = 0xF02E01B0

REGISTRY_GLOBAL = 0xF007F044
LOOKUP_GLOBAL = 0xF007F048

# Strong semantic candidate discovered next to GET_CHILD_COUNT.
CONSTRUCTOR_CANDIDATE = 0xF02D8888

# S13.5A.3 revealed this function to use the same 6-byte lookup entries in the
# reverse direction. Keep "candidate" wording until caller semantics close it.
INDEX_TO_ID_CANDIDATE = 0xF02FEFB4

IMAGE_A = 0x8313
IMAGE_B = 0x8321
AUDIO = 0x8928
B0EC = 0xB0EC
B0ED = 0xB0ED

KNOWN = {
    GET_CHILD_COUNT: "GET_CHILD_COUNT",
    GET_CHILD_COUNT | 1: "GET_CHILD_COUNT Thumb",
    ENUM_CHILD_IDS: "ENUM_CHILD_IDS",
    ENUM_CHILD_IDS | 1: "ENUM_CHILD_IDS Thumb",
    GET_CHILD_META: "GET_CHILD_META",
    GET_CHILD_META | 1: "GET_CHILD_META Thumb",
    PARENT_TO_INDEX: "PARENT_TO_INDEX",
    PARENT_TO_INDEX | 1: "PARENT_TO_INDEX Thumb",
    CONSTRUCTOR_CANDIDATE: "CONSTRUCTOR_CANDIDATE",
    CONSTRUCTOR_CANDIDATE | 1: "CONSTRUCTOR_CANDIDATE Thumb",
    INDEX_TO_ID_CANDIDATE: "INDEX_TO_ID_CANDIDATE",
    INDEX_TO_ID_CANDIDATE | 1: "INDEX_TO_ID_CANDIDATE Thumb",
    REGISTRY_GLOBAL: "REGISTRY_GLOBAL",
    LOOKUP_GLOBAL: "LOOKUP_GLOBAL",
}

TARGET_U16 = {IMAGE_A, IMAGE_B, AUDIO, B0EC, B0ED}


# -----------------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------------

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for stream in self.streams:
            stream.write(s)
        return len(s)

    def flush(self):
        for stream in self.streams:
            stream.flush()


@dataclass
class Image:
    name: str
    data: bytes
    base: int

    @property
    def end(self):
        return self.base + len(self.data)

    def contains(self, addr: int) -> bool:
        a = addr & ~1
        return self.base <= a < self.end

    def off(self, addr: int) -> int:
        return (addr & ~1) - self.base


@dataclass
class Sym:
    kind: str
    value: Optional[int] = None
    source: str = ""

    def text(self):
        if self.kind == "CONST" and self.value is not None:
            return f"CONST 0x{self.value & 0xffffffff:08X} via {self.source}"
        return f"{self.kind}" + (f" via {self.source}" if self.source else "")


def banner(s):
    print()
    print("=" * 118)
    print(s)
    print("=" * 118)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def u16(data, off):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def name_of(v):
    return KNOWN.get(v, KNOWN.get(v & ~1, ""))


def decode_one(img: Image, addr: int):
    off = img.off(addr)
    if off < 0 or off >= len(img.data):
        return None
    out = list(md.disasm(img.data[off:off + 4], addr, count=1))
    return out[0] if out else None


def disasm(img: Image, start: int, size: int):
    off = img.off(start)
    if off < 0 or off >= len(img.data):
        return []
    blob = img.data[off:min(len(img.data), off + size)]
    return list(md.disasm(blob, start))


def direct_target(insn):
    if insn.mnemonic not in {
        "bl", "blx", "b", "b.w", "beq", "bne", "bhi", "bls", "bcc", "bcs",
        "bgt", "blt", "bge", "ble", "cbz", "cbnz",
    }:
        return None
    if not insn.operands or insn.operands[0].type != ARM_OP_IMM:
        return None
    return insn.operands[0].imm & 0xffffffff


def literal_load(img: Image, insn):
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    dst, src = insn.operands[0], insn.operands[1]
    if dst.type != ARM_OP_REG or src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
        return None
    pc = (insn.address + 4) & ~3
    lit_addr = (pc + src.mem.disp) & 0xffffffff
    if not img.contains(lit_addr):
        return None
    value = u32(img.data, img.off(lit_addr))
    if value is None:
        return None
    return {
        "dst_reg": dst.reg,
        "dst": insn.reg_name(dst.reg),
        "literal_addr": lit_addr,
        "value": value,
    }


def fmt(img: Image, insn):
    c = []
    tgt = direct_target(insn)
    if tgt is not None:
        n = name_of(tgt)
        c.append(f"TARGET=0x{tgt:08X}" + (f" <{n}>" if n else ""))
    lit = literal_load(img, insn)
    if lit:
        n = name_of(lit["value"])
        loc = ""
        if zimage.contains(lit["value"]):
            loc = " ZIMAGE"
        elif alice.contains(lit["value"]):
            loc = " ALICE"
        c.append(
            f"LITERAL[0x{lit['literal_addr']:08X}]=0x{lit['value']:08X}{loc}"
            f" -> {lit['dst']}" + (f" <{n}>" if n else "")
        )
    return (
        f"0x{insn.address:08X}: {insn.bytes.hex(' '):<14} "
        f"{insn.mnemonic:<9} {insn.op_str:<35}"
        + ((" ; " + " ; ".join(c)) if c else "")
    )


def dump_function(img: Image, start: int, max_size=0x100):
    print(f"{img.name} @0x{start:08X} +0x{img.off(start):X}")
    count = 0
    for insn in disasm(img, start, max_size):
        print(fmt(img, insn))
        count += 1
        if count >= 6 and (
            (insn.mnemonic == "pop" and "pc" in insn.op_str)
            or (insn.mnemonic == "bx" and insn.op_str.strip() == "lr")
        ):
            # Do not stop at PARENT_TO_INDEX first early-return: include full
            # binary-search tail explicitly below.
            if start != PARENT_TO_INDEX:
                break
        if start == PARENT_TO_INDEX and insn.address >= 0xF02E01FC:
            break
    print(f"instructions shown = {count}")


def raw_word_positions(img: Image, value: int):
    pat = struct.pack("<I", value & 0xffffffff)
    out = []
    pos = 0
    while True:
        pos = img.data.find(pat, pos)
        if pos < 0:
            break
        out.append(pos)
        pos += 1
    return out


def raw_u16_positions(img: Image, value: int):
    pat = struct.pack("<H", value & 0xffff)
    out = []
    pos = 0
    while True:
        pos = img.data.find(pat, pos)
        if pos < 0:
            break
        out.append(pos)
        pos += 1
    return out


def find_literal_xrefs(img: Image, value: int):
    """
    Real LDR-literal xrefs to an exact 32-bit value.
    """
    hits = {}
    for raw_off in raw_word_positions(img, value):
        lit_addr = img.base + raw_off
        start = max(0, raw_off - 0x1100) & ~1
        for off in range(start, min(len(img.data) - 2, raw_off + 2), 2):
            insn = decode_one(img, img.base + off)
            if insn is None:
                continue
            lit = literal_load(img, insn)
            if not lit:
                continue
            if lit["literal_addr"] == lit_addr and lit["value"] == value:
                hits[insn.address] = (insn, lit)
    return [hits[k] for k in sorted(hits)]


def window(img: Image, center: int, before=0x30, after=0x60):
    start = max(img.base, (center - before) & ~1)
    end = min(img.end, center + after)
    for insn in disasm(img, start, end - start):
        mark = ">>>" if insn.address == center else "   "
        print(mark, fmt(img, insn))


def classify_global_xref(img: Image, insn, lit, max_insns=28):
    tracked = lit["dst_reg"]
    events = []
    insns = disasm(img, insn.address, 0x90)
    for i, x in enumerate(insns):
        if i == 0:
            continue
        if i > max_insns:
            break

        # Detect memory use via the loaded address.
        for op in x.operands:
            if op.type == ARM_OP_MEM and op.mem.base == tracked:
                if x.mnemonic.startswith("str"):
                    events.append(("WRITE_THROUGH_GLOBAL_ADDRESS", x))
                elif x.mnemonic.startswith("ldr"):
                    events.append(("READ_THROUGH_GLOBAL_ADDRESS", x))
                else:
                    events.append(("MEMORY_USE", x))

        # Address passed into a call is also important: a generic initializer
        # can write through the pointer without a local STR.
        if x.mnemonic in {"bl", "blx"}:
            events.append(("CALL_AFTER_ADDRESS_LOAD", x))

        if x.mnemonic == "pop" and "pc" in x.op_str:
            break
    return events


def looks_thumb32_branch(img: Image, off: int):
    a = u16(img.data, off)
    b = u16(img.data, off + 2)
    if a is None or b is None:
        return False
    return (a & 0xF800) == 0xF000 and (b & 0xC000) == 0xC000


def direct_calls_to(img: Image, target: int):
    out = []
    nt = target & ~1
    for off in range(0, len(img.data) - 4, 2):
        if not looks_thumb32_branch(img, off):
            continue
        insn = decode_one(img, img.base + off)
        if insn is None or insn.mnemonic not in {"bl", "blx"}:
            continue
        tgt = direct_target(insn)
        if tgt is not None and (tgt & ~1) == nt:
            out.append((insn.address, tgt, insn))
    return out


# -----------------------------------------------------------------------------
# conservative local constant propagation for r0/r1/r2
# -----------------------------------------------------------------------------

def const(v, src):
    return Sym("CONST", v & 0xffffffff, src)


def unknown(src=""):
    return Sym("UNKNOWN", None, src)


def propagate_args(img: Image, call_addr: int, before=0xB0):
    start = max(img.base, (call_addr - before) & ~1)
    insns = [x for x in disasm(img, start, call_addr - start + 4)
             if x.address < call_addr]

    regs = {}

    def get(rid):
        return regs.get(rid, unknown())

    for x in insns:
        m = x.mnemonic
        ops = x.operands

        if m in {"bl", "blx"}:
            # caller-saved registers clobbered
            for rid in list(regs):
                n = x.reg_name(rid)
                if n in {"r0", "r1", "r2", "r3", "r12", "lr"}:
                    regs[rid] = unknown(f"call @0x{x.address:08X}")
            continue

        if not ops or ops[0].type != ARM_OP_REG:
            continue

        dst = ops[0].reg
        lit = literal_load(img, x)
        if lit:
            regs[dst] = const(lit["value"], f"literal @0x{lit['literal_addr']:08X}")
            continue

        if m.startswith("ldr"):
            regs[dst] = unknown(f"{m} memory @0x{x.address:08X}")
            continue

        if m in {"mov", "movs"} and len(ops) >= 2:
            if ops[1].type == ARM_OP_IMM:
                regs[dst] = const(ops[1].imm, f"{m} imm @0x{x.address:08X}")
            elif ops[1].type == ARM_OP_REG:
                regs[dst] = get(ops[1].reg)
            else:
                regs[dst] = unknown(m)
            continue

        if m == "movw" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            old = get(dst)
            hi = old.value & 0xffff0000 if old.kind == "CONST" and old.value is not None else 0
            regs[dst] = const(hi | (ops[1].imm & 0xffff), f"movw @0x{x.address:08X}")
            continue

        if m == "movt" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            old = get(dst)
            lo = old.value & 0xffff if old.kind == "CONST" and old.value is not None else 0
            regs[dst] = const(lo | ((ops[1].imm & 0xffff) << 16), f"movt @0x{x.address:08X}")
            continue

        if m in {"add", "adds", "sub", "subs"}:
            if len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                old = get(dst)
                if old.kind == "CONST":
                    delta = ops[1].imm
                    regs[dst] = const(
                        old.value + delta if m.startswith("add") else old.value - delta,
                        f"{m} @0x{x.address:08X}",
                    )
                else:
                    regs[dst] = unknown(m)
            elif len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                old = get(ops[1].reg)
                if old.kind == "CONST":
                    delta = ops[2].imm
                    regs[dst] = const(
                        old.value + delta if m.startswith("add") else old.value - delta,
                        f"{m} @0x{x.address:08X}",
                    )
                else:
                    regs[dst] = unknown(m)
            else:
                regs[dst] = unknown(m)
            continue

        if m in {"lsls", "lsrs"}:
            # Track simple immediate shifts, including the common U16 truncate:
            # lsls rX,rX,#16 ; lsrs rX,rX,#16
            if len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                old = get(dst)
                if old.kind == "CONST":
                    sh = ops[1].imm
                    val = ((old.value << sh) & 0xffffffff) if m == "lsls" else (old.value >> sh)
                    regs[dst] = const(val, f"{m} @0x{x.address:08X}")
                else:
                    regs[dst] = unknown(m)
            elif len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                old = get(ops[1].reg)
                if old.kind == "CONST":
                    sh = ops[2].imm
                    val = ((old.value << sh) & 0xffffffff) if m == "lsls" else (old.value >> sh)
                    regs[dst] = const(val, f"{m} @0x{x.address:08X}")
                else:
                    regs[dst] = unknown(m)
            else:
                regs[dst] = unknown(m)
            continue

        # Writes to destination through unmodelled instruction invalidate it.
        regs[dst] = unknown(f"{m} @0x{x.address:08X}")

    # recover Capstone IDs for r0/r1/r2 by observed names
    ids = {}
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG:
                n = x.reg_name(op.reg)
                if n in {"r0", "r1", "r2"}:
                    ids[n] = op.reg
    return {n: get(ids[n]) if n in ids else unknown("not observed")
            for n in ("r0", "r1", "r2")}


def dump_pointer_u16(value: int, images):
    for img in images:
        if img.contains(value):
            off = img.off(value)
            print(f"      -> pointer inside {img.name}: {img.name}+0x{off:X}")
            vals = []
            for i in range(16):
                v = u16(img.data, off + i * 2)
                if v is None:
                    break
                tag = ""
                if v == IMAGE_A:
                    tag = "<IMAGE_A>"
                elif v == IMAGE_B:
                    tag = "<IMAGE_B>"
                elif v == AUDIO:
                    tag = "<AUDIO>"
                elif v == B0EC:
                    tag = "<B0EC>"
                elif v == B0ED:
                    tag = "<B0ED>"
                vals.append(f"0x{v:04X}{tag}")
            print("         U16[0:16] = " + ", ".join(vals))
            return True
    return False


# -----------------------------------------------------------------------------
# audit sections
# -----------------------------------------------------------------------------

def verify_image(path: Path, name: str, base: int, size: int, digest: str):
    print(f"{name} = {path}")
    if not path.exists():
        print(f"[FAIL] missing {name}")
        return None
    data = path.read_bytes()
    got = sha256(data)
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {got}")
    if len(data) != size or got.lower() != digest.lower():
        print(f"[FAIL] non-canonical {name}; refusing mixed baseline")
        return None
    print(f"[PASS] canonical {name}")
    return Image(name, data, base)


def global_scan(img: Image, gv: int):
    label = name_of(gv) or f"0x{gv:08X}"
    print()
    print("-" * 118)
    print(f"{img.name}: {label} 0x{gv:08X}")

    raw = raw_word_positions(img, gv)
    xrefs = find_literal_xrefs(img, gv)
    print(f"raw word occurrences = {len(raw)}")
    print(f"real LDR-literal xrefs = {len(xrefs)}")

    writes = []
    passes = []
    for off in raw:
        print(f"  raw {img.name}+0x{off:X} runtime=0x{img.base + off:08X}")

    for insn, lit in xrefs:
        print(f"\nXREF {fmt(img, insn)}")
        events = classify_global_xref(img, insn, lit)
        for kind, ev in events:
            print(f"  {kind}: {fmt(img, ev)}")
            if kind.startswith("WRITE"):
                writes.append(ev.address)
            if kind == "CALL_AFTER_ADDRESS_LOAD":
                passes.append(ev.address)
        window(img, insn.address, 0x20, 0x70)

    print(f"\n{img.name} {label} classified local writes = {len(set(writes))}")
    print(f"{img.name} {label} calls after address load = {len(set(passes))}")
    return {"raw": raw, "xrefs": xrefs, "writes": writes, "passes": passes}


def pointer_scan(img: Image, value: int):
    positions = raw_word_positions(img, value)
    print(f"{img.name}: exact 0x{value:08X} <{name_of(value) or 'value'}> = {len(positions)}")
    for off in positions[:50]:
        print(f"  {img.name}+0x{off:X} runtime=0x{img.base + off:08X}")
    if len(positions) > 50:
        print(f"  ... {len(positions) - 50} more")

    xrefs = find_literal_xrefs(img, value)
    print(f"  real LDR-literal xrefs = {len(xrefs)}")
    for insn, lit in xrefs:
        print(f"    {fmt(img, insn)}")
        window(img, insn.address, 0x18, 0x38)
    return positions, xrefs


def constructor_audit(images):
    banner("E. F02D8888 CONSTRUCTOR-LIKE CANDIDATE")

    if not zimage.contains(CONSTRUCTOR_CANDIDATE):
        print("[FAIL] constructor candidate outside ZIMAGE")
        return {}

    print("This function is NOT yet named a registry constructor as a fact.")
    print("It is audited because it receives r0/r1/r2, calls F021604A, then stores:")
    print("  arg0 -> [returned_object + 0x06]")
    print("  arg1 -> [returned_object + 0x08]")
    print("  arg2 -> [returned_object + 0x0C]")
    print("and initializes additional low fields.")
    print()

    dump_function(zimage, CONSTRUCTOR_CANDIDATE, 0x70)

    results = {}
    for img in images:
        print()
        print(f"--- direct calls from {img.name} ---")
        calls = direct_calls_to(img, CONSTRUCTOR_CANDIDATE)
        print(f"count = {len(calls)}")
        results[img.name] = calls

        for call_addr, tgt, insn in calls:
            print()
            print(f"CALL {img.name} 0x{call_addr:08X} -> 0x{tgt:08X}")
            args = propagate_args(img, call_addr)
            for reg in ("r0", "r1", "r2"):
                s = args[reg]
                print(f"  {reg}: {s.text()}")
                if s.kind == "CONST" and s.value is not None:
                    dump_pointer_u16(s.value, images)
            window(img, call_addr, 0x70, 0x24)

        for ptr in (CONSTRUCTOR_CANDIDATE, CONSTRUCTOR_CANDIDATE | 1):
            pos = raw_word_positions(img, ptr)
            if pos:
                print(f"{img.name}: raw pointer 0x{ptr:08X} occurrences = {len(pos)}")
                for off in pos:
                    print(f"  +0x{off:X} runtime=0x{img.base + off:08X}")

    return results


def id_support_scan(img: Image):
    print()
    print(f"--- {img.name} U16 supporting evidence ---")
    for value in sorted(TARGET_U16):
        pos = raw_u16_positions(img, value)
        print(f"0x{value:04X}: {len(pos)} occurrence(s)")
        for off in pos[:20]:
            print(f"  {img.name}+0x{off:X} runtime=0x{img.base + off:08X}")
        if len(pos) > 20:
            print(f"  ... {len(pos) - 20} more")


# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--zimage",
        default="research/f2/work/extracted/altice_platform/zimage.bin",
    )
    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a4_alice_registry_population_audit.txt",
    )
    return p.parse_args()


def main():
    global zimage, alice

    args = parse_args()
    root = Path.cwd()

    zp = Path(args.zimage)
    ap = Path(args.alice)
    rp = Path(args.report)
    if not zp.is_absolute():
        zp = root / zp
    if not ap.is_absolute():
        ap = root / ap
    if not rp.is_absolute():
        rp = root / rp
    rp.parent.mkdir(parents=True, exist_ok=True)

    capture = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, capture)

    rc = 0
    try:
        banner("S13.5A.4 - CANONICAL ALICE + REGISTRY POPULATION / CONSTRUCTOR AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")

        banner("A. CANONICAL INPUTS")
        zimage = verify_image(zp, "ZIMAGE", ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA256)
        alice = verify_image(ap, "ALICE", ALICE_BASE, ALICE_SIZE, ALICE_SHA256)

        if zimage is None or alice is None:
            return 3

        images = [zimage, alice]

        banner("B. RANGE MAPPER / INVERSE-MAPPER SEMANTICS")
        print("F02E01B0 — ID -> dense registry index")
        dump_function(zimage, PARENT_TO_INDEX, 0x60)
        print()
        print("Observed 6-byte lookup entry model from S13.5A.3:")
        print("  +0x00 u16 lower_id")
        print("  +0x02 u16 upper_id")
        print("  +0x04 u16 base_index")
        print("return on hit: base_index + input_id - lower_id")
        print()
        print("F02FEFB4 — inverse mapper candidate using the same lookup descriptor")
        dump_function(zimage, INDEX_TO_ID_CANDIDATE, 0x70)

        banner("C. F007F044 / F007F048 CROSS-IMAGE XREF CENSUS")
        summaries = {}
        for img in images:
            for gv in (REGISTRY_GLOBAL, LOOKUP_GLOBAL):
                summaries[(img.name, gv)] = global_scan(img, gv)

        banner("D. PROVIDER POINTER / VENEER CENSUS")
        provider_values = [
            GET_CHILD_COUNT, GET_CHILD_COUNT | 1,
            ENUM_CHILD_IDS, ENUM_CHILD_IDS | 1,
            GET_CHILD_META, GET_CHILD_META | 1,
        ]
        provider_hits = {}
        for img in images:
            print()
            print(f"### {img.name}")
            for value in provider_values:
                provider_hits[(img.name, value)] = pointer_scan(img, value)

        constructor_results = constructor_audit(images)

        banner("F. TARGET-ID SUPPORTING EVIDENCE")
        for img in images:
            id_support_scan(img)

        banner("G. S13.5A.4 DECISION GATE")

        alice_global_refs = (
            len(summaries[("ALICE", REGISTRY_GLOBAL)]["xrefs"])
            + len(summaries[("ALICE", LOOKUP_GLOBAL)]["xrefs"])
        )
        alice_writes = (
            len(set(summaries[("ALICE", REGISTRY_GLOBAL)]["writes"]))
            + len(set(summaries[("ALICE", LOOKUP_GLOBAL)]["writes"]))
        )
        alice_provider_ptrs = sum(
            len(provider_hits[("ALICE", value)][0]) for value in provider_values
        )
        z_ctor_calls = len(constructor_results.get("ZIMAGE", []))
        a_ctor_calls = len(constructor_results.get("ALICE", []))

        print(f"ALICE real global LDR xrefs        = {alice_global_refs}")
        print(f"ALICE classified direct writes     = {alice_writes}")
        print(f"ALICE raw provider pointer words    = {alice_provider_ptrs}")
        print(f"ZIMAGE direct F02D8888 calls        = {z_ctor_calls}")
        print(f"ALICE direct F02D8888 calls         = {a_ctor_calls}")
        print()

        if alice_writes:
            print("[NEXT] Promote ALICE writer candidate(s) and slice source data into F007F044/F048.")
        elif a_ctor_calls or z_ctor_calls:
            print("[NEXT] Inspect F02D8888 call contracts and any constant child-array pointers.")
            print("       Promote it to a menu-registry constructor only if its produced objects")
            print("       are proven to back F007F044 records.")
        elif alice_provider_ptrs or alice_global_refs:
            print("[NEXT] Follow ALICE veneers / indirect provider users and recover parent arguments.")
        else:
            print("[NEXT] No cross-image ownership found. Pivot to registry population APIs /")
            print("       allocation path around F021604A and the object returned to F02D8888.")
            print("       Do NOT patch.")

        print()
        print("Important:")
        print("- 0xB0EC is a real static GET_CHILD_COUNT argument from S13.5A.3.")
        print("- Its caller specifically checks child_count == 1.")
        print("- Therefore it is not promoted as visible Multimedia without new evidence.")
        print("- No raw ID occurrence alone establishes menu membership.")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {rp}")

        return rc
    finally:
        sys.stdout = old
        rp.write_text(capture.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
