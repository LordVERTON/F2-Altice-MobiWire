#!/usr/bin/env python3
"""
S13.5A.16 - PLATFORM CURRENT-ITEM GETTER CONSUMER AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.15 proved an exact setter/getter pair for the same platform field:

    SETTER F02D1E90(value):
        state = *(u32 *)(F00BADA8 + 8)
        *(u32 *)(state + 0x264) = value

    GETTER F02FBC10():
        state = *(u32 *)(F00BADA8 + 8)
        return *(u32 *)(state + 0x264)

The generic UI wrappers call the setter with (index0 + 1), while the original
index0 is dispatched to SELECT_CB, which resolves descriptor.children[index0].

A.15's linear scanner accidentally continued beyond the getter's BX LR into
the next function. Any later comparison from that linear window is therefore
SUPERSEDED as getter-return evidence.

This pass audits ONLY real consumers of F02FBC10:

  A. validate canonical ALICE + ZIMAGE;
  B. confirm exact getter bytes;
  C. find all direct ZIMAGE calls to F02FBC10;
  D. find ALICE ARM import veneers targeting Thumb pointer F02FBC11;
  E. find callers of those veneers;
  F. trace getter return r0 to its first meaningful use;
  G. detect return-1 / return+1 conversions, indexing, count checks;
  H. detect same-function correlation with ALICE zero-based state F004B04C;
  I. inventory raw/function-pointer references to the getter;
  J. strict decision gate.

NO USB/COM.
NO PHONE ACCESS.
NO FLASH WRITE.
NO PATCH.
NO REPACK.
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

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

GETTER = 0xF02FBC10
GETTER_THUMB = GETTER | 1
SETTER = 0xF02D1E90

STATE_GLOBAL = 0xF00BADA8
ZERO_BASED_GLOBAL = 0xF004B04C

ARM_VENEER_WORD = 0xE51FF004  # ldr pc,[pc,#-4]

md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md_t.detail = True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md_a.detail = True


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
        return len(s)

    def flush(self):
        for st in self.streams:
            st.flush()


@dataclass
class Image:
    name: str
    data: bytes
    base: int

    @property
    def end(self):
        return self.base + len(self.data)

    def contains(self, addr: int):
        return self.base <= addr < self.end

    def off(self, addr: int):
        return addr - self.base


@dataclass
class UseEvent:
    kind: str
    insn_addr: int
    text: str


def banner(s: str):
    print()
    print("=" * 132)
    print(s)
    print("=" * 132)


def sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def verify(path: Path, name: str, base: int, size: int, expected_sha: str):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical {name}: {path}")

    data = path.read_bytes()
    got = sha256(data)

    print(f"{name} = {path}")
    print(f"  runtime base = 0x{base:08X}")
    print(f"  size         = 0x{len(data):X}")
    print(f"  sha256       = {got}")

    if len(data) != size:
        raise SystemExit(f"ABORT: {name} size mismatch")

    if got.lower() != expected_sha.lower():
        raise SystemExit(f"ABORT: {name} SHA256 mismatch")

    print(f"[PASS] canonical {name}")
    return Image(name, data, base)


def decode1(img: Image, addr: int, mode="THUMB"):
    if not img.contains(addr):
        return None

    md = md_t if mode == "THUMB" else md_a
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+4], addr, count=1))
    return xs[0] if xs else None


def dis(img: Image, start: int, end: int, mode="THUMB"):
    if not img.contains(start):
        return []

    md = md_t if mode == "THUMB" else md_a
    end = min(end, img.end)
    return [
        x for x in md.disasm(img.data[img.off(start):img.off(end)], start)
        if x.address < end
    ]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<9} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None
    op = x.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def literal_load(img: Image, x, mode="THUMB"):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None

    d, s = x.operands[0], x.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None

    pc = ((x.address + 4) & ~3) if mode == "THUMB" else (x.address + 8)
    la = (pc + s.mem.disp) & 0xFFFFFFFF

    if not img.contains(la):
        return None

    return x.reg_name(d.reg), d.reg, la, u32(img.data, img.off(la))


def print_region(img: Image, start: int, end: int, mode="THUMB", marks=None):
    marks = marks or set()

    for x in dis(img, start, end, mode):
        notes = []

        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")

        li = literal_load(img, x, mode)
        if li:
            rn, _, la, val = li
            tags = []
            if val == ZERO_BASED_GLOBAL:
                tags.append("ZERO_BASED_GLOBAL")
            if val == STATE_GLOBAL:
                tags.append("STATE_GLOBAL")
            if val in {GETTER, GETTER_THUMB}:
                tags.append("GETTER_PTR")
            notes.append(
                f"literal@0x{la:08X}=0x{val:08X}->{rn}"
                + (f" <{'|'.join(tags)}>" if tags else "")
            )

        mark = ">>>" if x.address in marks else "   "
        print(mark, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def all_hits(data: bytes, needle: bytes):
    out = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(pos)
        pos += 1


def is_prologue(x):
    return bool(x and x.mnemonic == "push" and "lr" in x.op_str)


def candidate_prologues(img: Image, target: int, back=0x500, forward=0x900):
    lo = max(img.base, target-back) & ~1
    out = []

    for a in range(lo, target+1, 2):
        x = decode1(img, a, "THUMB")
        if not is_prologue(x):
            continue
        xs = dis(img, a, min(img.end, a+forward), "THUMB")
        if any(z.address == target for z in xs):
            out.append(a)

    return out


def enclosing_start(img: Image, target: int):
    cands = candidate_prologues(img, target)
    return cands[-1] if cands else None


def scan_direct_calls(img: Image, target: int):
    out = []

    # Thumb immediate BL/BLX
    for off in range(0, len(img.data)-4, 2):
        h1 = u16(img.data, off)
        h2 = u16(img.data, off+2)

        if h1 is None or h2 is None:
            continue

        if (h1 & 0xF800) != 0xF000 or (h2 & 0xC000) != 0xC000:
            continue

        xs = list(md_t.disasm(img.data[off:off+4], img.base+off, count=1))
        if not xs:
            continue

        x = xs[0]
        if x.mnemonic not in {"bl", "blx"}:
            continue

        t = direct_target(x)
        if t is not None and (t & ~1) == (target & ~1):
            out.append(("THUMB", x))

    # ARM immediate BL/BLX
    for off in range(0, len(img.data)-4, 4):
        w = u32(img.data, off)

        if w is None:
            continue

        if not (
            (w & 0x0E000000) == 0x0A000000
            or (w & 0xFE000000) == 0xFA000000
        ):
            continue

        xs = list(md_a.disasm(img.data[off:off+4], img.base+off, count=1))
        if not xs:
            continue

        x = xs[0]
        if x.mnemonic not in {"bl", "blx"}:
            continue

        t = direct_target(x)
        if t is not None and (t & ~1) == (target & ~1):
            out.append(("ARM", x))

    uniq = {(m, x.address): (m, x) for m, x in out}
    return [uniq[k] for k in sorted(uniq, key=lambda q: (q[1], q[0]))]


def raw_pointer_refs(img: Image, target: int):
    vals = {
        target & 0xFFFFFFFF,
        (target | 1) & 0xFFFFFFFF,
    }

    out = []

    for v in vals:
        pat = struct.pack("<I", v)
        for off in all_hits(img.data, pat):
            out.append((img.base+off, v))

    return sorted(set(out))


def find_arm_import_veneers(img: Image, target_thumb: int):
    """
    Find exact ALICE-style 8-byte veneers:
        E51FF004
        target_word
    """
    out = []

    pat = struct.pack("<I", target_thumb & 0xFFFFFFFF)

    for off in all_hits(img.data, pat):
        if off < 4:
            continue

        prev = u32(img.data, off-4)
        if prev != ARM_VENEER_WORD:
            continue

        start = img.base + off - 4
        target_word_addr = img.base + off
        out.append((start, target_word_addr))

    return sorted(set(out))


def reg_written(x):
    if not x.operands:
        return None
    op0 = x.operands[0]
    return op0.reg if op0.type == ARM_OP_REG else None


def aliases_after_call(img: Image, call_addr: int, max_bytes=0x90):
    """
    Track aliases of getter return r0 after a call.
    Stop after first later call once meaningful use has been recorded, because
    caller-saved r0 semantics cease to be reliable.
    """
    xs = dis(img, call_addr+4, min(img.end, call_addr+4+max_bytes), "THUMB")

    # discover r0 register id from local instructions
    r0_id = None
    for x in xs:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == "r0":
                r0_id = op.reg
                break
        if r0_id is not None:
            break

    if r0_id is None:
        return xs, []

    aliases = {r0_id}
    derived_minus1 = set()
    derived_plus1 = set()

    events: list[UseEvent] = []

    for x in xs:
        ops = x.operands

        # Return / branch-to-lr ends local function path.
        if x.mnemonic == "bx" and x.op_str.strip() == "lr":
            break

        if x.mnemonic == "pop" and "pc" in x.op_str:
            break

        # Propagate aliases.
        if x.mnemonic in {"mov", "movs"} and len(ops) >= 2:
            d, s = ops[0], ops[1]
            if d.type == ARM_OP_REG and s.type == ARM_OP_REG:
                if s.reg in aliases:
                    aliases.add(d.reg)
                    events.append(
                        UseEvent(
                            "ALIAS",
                            x.address,
                            f"{x.reg_name(d.reg)} <- getter_result"
                        )
                    )
                elif s.reg in derived_minus1:
                    derived_minus1.add(d.reg)
                elif s.reg in derived_plus1:
                    derived_plus1.add(d.reg)

        # +/- 1 conversion.
        if x.mnemonic in {"add", "adds", "sub", "subs"} and ops:
            d = ops[0]
            if d.type == ARM_OP_REG:
                source_is_result = d.reg in aliases
                imm1 = any(
                    op.type == ARM_OP_IMM and op.imm == 1
                    for op in ops[1:]
                )

                # 3-op form can use separate source register.
                if len(ops) >= 3 and ops[1].type == ARM_OP_REG:
                    source_is_result = ops[1].reg in aliases
                    imm1 = ops[2].type == ARM_OP_IMM and ops[2].imm == 1

                if source_is_result and imm1:
                    if x.mnemonic.startswith("sub"):
                        derived_minus1.add(d.reg)
                        events.append(
                            UseEvent(
                                "MINUS1",
                                x.address,
                                f"{x.reg_name(d.reg)} = getter_result - 1"
                            )
                        )
                    else:
                        derived_plus1.add(d.reg)
                        events.append(
                            UseEvent(
                                "PLUS1",
                                x.address,
                                f"{x.reg_name(d.reg)} = getter_result + 1"
                            )
                        )

        # Compare.
        if x.mnemonic.startswith("cmp"):
            names = []
            for op in ops:
                if op.type == ARM_OP_REG:
                    if op.reg in aliases:
                        names.append(f"{x.reg_name(op.reg)}=getter")
                    elif op.reg in derived_minus1:
                        names.append(f"{x.reg_name(op.reg)}=getter-1")
                    elif op.reg in derived_plus1:
                        names.append(f"{x.reg_name(op.reg)}=getter+1")

            if names:
                events.append(
                    UseEvent(
                        "COMPARE",
                        x.address,
                        f"{', '.join(names)} ; {x.op_str}"
                    )
                )

        # Store of result / derived result.
        if x.mnemonic.startswith("str") and len(ops) >= 2:
            src, mem = ops[0], ops[1]
            if src.type == ARM_OP_REG and mem.type == ARM_OP_MEM:
                tag = None
                if src.reg in aliases:
                    tag = "getter_result"
                elif src.reg in derived_minus1:
                    tag = "getter_result-1"
                elif src.reg in derived_plus1:
                    tag = "getter_result+1"

                if tag:
                    events.append(
                        UseEvent(
                            "STORE",
                            x.address,
                            f"{tag} -> [{x.reg_name(mem.mem.base)}{mem.mem.disp:+#x}]"
                        )
                    )

        # Memory index use. Capstone ARM mem can expose index register.
        for op in ops:
            if op.type != ARM_OP_MEM:
                continue

            idx = op.mem.index
            if not idx:
                continue

            if idx in aliases:
                events.append(
                    UseEvent(
                        "INDEX",
                        x.address,
                        f"getter_result used as memory index in {x.op_str}"
                    )
                )
            elif idx in derived_minus1:
                events.append(
                    UseEvent(
                        "INDEX_MINUS1",
                        x.address,
                        f"getter_result-1 used as memory index in {x.op_str}"
                    )
                )
            elif idx in derived_plus1:
                events.append(
                    UseEvent(
                        "INDEX_PLUS1",
                        x.address,
                        f"getter_result+1 used as memory index in {x.op_str}"
                    )
                )

        # Shift of result commonly precedes table indexing.
        if x.mnemonic in {"lsls", "lsrs"} and ops:
            d = ops[0]
            src_reg = None

            if len(ops) >= 2 and ops[1].type == ARM_OP_REG:
                src_reg = ops[1].reg
            elif d.type == ARM_OP_REG:
                src_reg = d.reg

            if src_reg in aliases:
                events.append(
                    UseEvent(
                        "SCALE",
                        x.address,
                        f"getter_result scaled: {x.op_str}"
                    )
                )
            elif src_reg in derived_minus1:
                events.append(
                    UseEvent(
                        "SCALE_MINUS1",
                        x.address,
                        f"getter_result-1 scaled: {x.op_str}"
                    )
                )

        # Another call consumes current r0 / aliases indirectly.
        if x.mnemonic in {"bl", "blx"}:
            # If r0 itself is still an alias/derived value, record pass-through.
            if r0_id in aliases:
                events.append(
                    UseEvent(
                        "CALL_WITH_RESULT_R0",
                        x.address,
                        f"getter_result passed as r0 to {x.op_str}"
                    )
                )
            elif r0_id in derived_minus1:
                events.append(
                    UseEvent(
                        "CALL_WITH_MINUS1_R0",
                        x.address,
                        f"getter_result-1 passed as r0 to {x.op_str}"
                    )
                )

            # Caller-saved values become unreliable after call.
            aliases = {
                rid for rid in aliases
                if x.reg_name(rid) not in {"r0","r1","r2","r3","r12","ip","lr"}
            }
            derived_minus1 = {
                rid for rid in derived_minus1
                if x.reg_name(rid) not in {"r0","r1","r2","r3","r12","ip","lr"}
            }
            derived_plus1 = {
                rid for rid in derived_plus1
                if x.reg_name(rid) not in {"r0","r1","r2","r3","r12","ip","lr"}
            }

    return xs, events


def function_has_zero_based_global(img: Image, func_start: int, max_len=0x600):
    xs = dis(img, func_start, min(img.end, func_start+max_len), "THUMB")
    hits = []

    for x in xs:
        li = literal_load(img, x, "THUMB")
        if li and li[3] == ZERO_BASED_GLOBAL:
            hits.append((x, li[2]))

    return hits


def analyze_consumer(img: Image, call_addr: int, label: str):
    fs = enclosing_start(img, call_addr)

    print()
    print("-" * 132)
    print(f"{label} call @0x{call_addr:08X}")

    if fs is None:
        print("enclosing function: UNKNOWN")
        context_lo = max(img.base, call_addr-0x50)
    else:
        print(f"enclosing function start = 0x{fs:08X}")
        context_lo = fs

    xs, events = aliases_after_call(img, call_addr)

    print("return-use events:")
    if not events:
        print("  none resolved")
    else:
        for e in events:
            print(f"  {e.kind:<22} @0x{e.insn_addr:08X}: {e.text}")

    zrefs = []
    if fs is not None:
        zrefs = function_has_zero_based_global(img, fs)
        print(f"same-function F004B04C literal xrefs = {len(zrefs)}")
        for x, la in zrefs:
            print(f"  {fmt(x)} ; literal@0x{la:08X}")

    # Show compact post-call context.
    print("post-call context:")
    print_region(
        img,
        call_addr,
        min(img.end, call_addr+0x70),
        "THUMB",
        {call_addr, *(e.insn_addr for e in events)},
    )

    return fs, events, zrefs


def classify_events(events):
    kinds = {e.kind for e in events}

    if "MINUS1" in kinds or "CALL_WITH_MINUS1_R0" in kinds or "INDEX_MINUS1" in kinds:
        return "EXPLICIT_MINUS1"

    if "INDEX" in kinds or "SCALE" in kinds:
        return "DIRECT_INDEX_OR_SCALE"

    if "COMPARE" in kinds:
        return "COMPARE"

    if "STORE" in kinds:
        return "STORE"

    if "CALL_WITH_RESULT_R0" in kinds:
        return "PASS_TO_CALLEE"

    return "UNKNOWN"


def real_literal_xrefs_to_pointer_word(img: Image, word_addr: int):
    """
    Identify real Thumb LDR-literal instructions using a specific word address.
    """
    out = []

    lo = max(img.base, word_addr-0x500) & ~1

    for a in range(lo, word_addr+1, 2):
        x = decode1(img, a, "THUMB")
        li = literal_load(img, x, "THUMB") if x else None
        if li and li[2] == word_addr:
            out.append((x, li[3]))

    return out


def parse_args():
    p = argparse.ArgumentParser()

    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )

    p.add_argument(
        "--zimage",
        default="research/f2/work/extracted/altice_platform/zimage.bin",
    )

    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a16_platform_current_item_getter_consumers.txt",
    )

    return p.parse_args()


def resolve(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    args = parse_args()
    root = Path.cwd()

    report_path = resolve(root, args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    cap = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, cap)

    try:
        banner("S13.5A.16 - PLATFORM CURRENT-ITEM GETTER CONSUMER AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")
        print()
        print(f"GETTER           = 0x{GETTER:08X}")
        print(f"GETTER_THUMB     = 0x{GETTER_THUMB:08X}")
        print(f"SETTER           = 0x{SETTER:08X}")
        print(f"ZERO_BASED_GLOBAL= 0x{ZERO_BASED_GLOBAL:08X}")

        banner("A. CANONICAL INPUTS")
        alice = verify(
            resolve(root,args.alice),
            "ALICE",
            ALICE_BASE,
            ALICE_SIZE,
            ALICE_SHA256,
        )

        zimage = verify(
            resolve(root,args.zimage),
            "ZIMAGE",
            ZIMAGE_BASE,
            ZIMAGE_SIZE,
            ZIMAGE_SHA256,
        )

        banner("B. EXACT GETTER")
        print_region(
            zimage,
            GETTER,
            GETTER+0x10,
            "THUMB",
            {GETTER, GETTER+0x0A, GETTER+0x0C},
        )

        xret = decode1(zimage, GETTER+0x0C, "THUMB")
        exact_return = bool(
            xret
            and xret.mnemonic == "bx"
            and xret.op_str.strip() == "lr"
        )

        print()
        print(f"getter immediate BX LR @0x{GETTER+0x0C:08X} = {'PASS' if exact_return else 'OPEN'}")

        banner("C. DIRECT ZIMAGE CALLERS")
        zcalls = scan_direct_calls(zimage, GETTER)
        print(f"direct ZIMAGE calls to GETTER = {len(zcalls)}")

        all_consumers = []

        for mode, x in zcalls:
            print()
            print(f"{mode} {fmt(x)}")

            if mode == "THUMB":
                fs, events, zrefs = analyze_consumer(
                    zimage,
                    x.address,
                    "ZIMAGE_DIRECT",
                )
                all_consumers.append(
                    ("ZIMAGE_DIRECT", zimage, x.address, fs, events, zrefs)
                )

        banner("D. ALICE IMPORT VENEERS TO F02FBC11")
        veneers = find_arm_import_veneers(alice, GETTER_THUMB)

        print(f"ALICE exact ARM veneers = {len(veneers)}")

        for start, word_addr in veneers:
            print()
            print(f"veneer start    = 0x{start:08X}")
            print(f"target word addr= 0x{word_addr:08X}")
            print(f"target word     = 0x{u32(alice.data,alice.off(word_addr)):08X}")
            print_region(alice,start,start+8,"ARM",{start})

            vcalls = scan_direct_calls(alice,start)
            print(f"direct callers of veneer = {len(vcalls)}")

            for mode,x in vcalls:
                print(f"  {mode} {fmt(x)}")

                if mode == "THUMB":
                    fs, events, zrefs = analyze_consumer(
                        alice,
                        x.address,
                        f"ALICE_VENEER_0x{start:08X}",
                    )
                    all_consumers.append(
                        (f"ALICE_VENEER_0x{start:08X}",alice,x.address,fs,events,zrefs)
                    )

        banner("E. RAW / FUNCTION-POINTER REFERENCES")
        for img in (alice,zimage):
            refs = raw_pointer_refs(img, GETTER)
            print()
            print(f"{img.name}: raw GETTER/Thumb pointer refs = {len(refs)}")

            for addr,val in refs:
                print(f"  word@0x{addr:08X}=0x{val:08X}")

                lx = real_literal_xrefs_to_pointer_word(img,addr)
                print(f"    real Thumb literal xrefs = {len(lx)}")

                for x,loaded in lx:
                    print(f"      {fmt(x)} -> 0x{loaded:08X}")

        banner("F. CONSUMER CLASSIFICATION")
        counts = {}

        same_func_global = []

        for source,img,call_addr,fs,events,zrefs in all_consumers:
            cls = classify_events(events)
            counts[cls] = counts.get(cls,0)+1

            print(
                f"{source:<28} call@0x{call_addr:08X} "
                f"class={cls}"
            )

            if zrefs:
                same_func_global.append(
                    (source,img.name,call_addr,fs,events,zrefs)
                )

        if not all_consumers:
            print("No direct/veneer consumers recovered.")

        print()
        print("classification counts:")
        for k in sorted(counts):
            print(f"  {k:<24} {counts[k]}")

        banner("G. F004B04C SAME-FUNCTION CORRELATION")
        print(f"consumer functions also referencing F004B04C = {len(same_func_global)}")

        for source,img_name,call_addr,fs,events,zrefs in same_func_global:
            print()
            print(
                f"{source} {img_name} call@0x{call_addr:08X} "
                f"function=0x{fs:08X}"
            )

            for e in events:
                print(f"  return use: {e.kind:<20} @0x{e.insn_addr:08X} {e.text}")

            for x,la in zrefs:
                print(f"  F004B04C xref: {fmt(x)} literal@0x{la:08X}")

        banner("H. SEARCH FOR GETTER-1 PATTERN NEAR ALL CONSUMERS")
        minus1_consumers = []

        for source,img,call_addr,fs,events,zrefs in all_consumers:
            if any(
                e.kind in {"MINUS1","CALL_WITH_MINUS1_R0","INDEX_MINUS1"}
                for e in events
            ):
                minus1_consumers.append(
                    (source,img.name,call_addr,events)
                )

        print(f"explicit getter_result-1 consumers = {len(minus1_consumers)}")

        for source,img_name,call_addr,events in minus1_consumers:
            print()
            print(f"{source} {img_name} call@0x{call_addr:08X}")
            for e in events:
                if e.kind in {"MINUS1","CALL_WITH_MINUS1_R0","INDEX_MINUS1"}:
                    print(f"  {e.kind}: @0x{e.insn_addr:08X} {e.text}")

        banner("I. DECISION GATE")
        direct_count = len(zcalls)
        veneer_count = len(veneers)
        consumer_count = len(all_consumers)
        minus1_count = len(minus1_consumers)
        corr_count = len(same_func_global)

        print(f"getter exact immediate return      = {'PASS' if exact_return else 'OPEN'}")
        print(f"direct ZIMAGE callers             = {direct_count}")
        print(f"ALICE ARM import veneers          = {veneer_count}")
        print(f"resolved getter consumer callsites= {consumer_count}")
        print(f"explicit getter-1 consumers       = {minus1_count}")
        print(f"same-function F004B04C correlation= {corr_count}")
        print()

        if minus1_count:
            print("[PASS] Explicit one-based -> zero-based conversion recovered from real getter consumer(s).")
            print("[PROMOTION CANDIDATE] Combined with A.14 wrapper flow, dispatcher argument")
            print("is now eligible for FACT classification as zero-based UI/list item index")
            print("IF the consuming path is structurally UI/list-related.")
        elif corr_count:
            print("[PASS] Getter consumer shares a function with F004B04C access.")
            print("[NEXT] Inspect the exact relation printed above; promote only if")
            print("getter result and F004B04C differ by one or are compared as positions.")
        elif consumer_count:
            print("[PASS] Real getter consumer(s) recovered.")
            print("[NEXT] Follow only the strongest return-use path above until current-item")
            print("or list-position semantics are structurally proven.")
        else:
            print("[OPEN] No static getter callers recovered through direct or ALICE veneer paths.")
            print("[NEXT] Follow raw function-pointer owners of GETTER_THUMB only; do not")
            print("return to broad menu-ID scans.")

        print()
        print("INVARIANTS:")
        print("  F02D1E90(value) writes platform field state+0x264")
        print("  F02FBC10() returns exactly the same field")
        print("  wrappers write index0+1 through SETTER")
        print("  wrappers dispatch index0 to SELECT_CB")
        print("  SELECT_CB(index0) resolves descriptor.children[index0]")
        print()
        print("CURRENT CLASSIFICATION:")
        print("  dispatcher argument = zero-based UI/list item index : STRONGLY SUPPORTED")
        print()
        print("STILL UNKNOWN:")
        print("  numeric ID corresponding to visible Multimedia")
        print("  FM Radio child ID")
        print("  exact Multimedia children[]")
        print("  whether 0x8928 is absent vs present-but-filtered")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {report_path}")

        return 0

    finally:
        sys.stdout = old
        report_path.write_text(cap.getvalue(),encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
