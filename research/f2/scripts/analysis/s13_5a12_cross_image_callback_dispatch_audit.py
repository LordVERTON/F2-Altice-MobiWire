#!/usr/bin/env python3
"""
S13.5A.12 - CROSS-IMAGE CALLBACK SLOT READER / DISPATCH AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.11 proved:

    0x10317C58:
        ldr r1, =0xF0096018
        str r0, [r1,#0x44]
        bx  lr

Therefore:
    CALLBACK_BASE = 0xF0096018
    CALLBACK_SLOT = 0xF009605C

and the generic menu selection callback 0x10342FC5 is installed there.

A.11 only searched ALICE readers of the exact effective slot address.
That is insufficient because:
  - the global lives in F0... platform space;
  - readers may load F0096018 then dereference +0x44;
  - the dispatcher may live in canonical ZIMAGE.

This pass audits BOTH canonical images:
  ALICE  runtime base 0x1024EC00
  ZIMAGE runtime base 0xF023CA50

It searches:
  1) real PC-relative literal loads of F0096018 and F009605C;
  2) nearby F00960xx seeds that can resolve to the slot;
  3) short symbolic forward paths that produce:
         callback = *(CALLBACK_SLOT)
         ...
         blx/bx callback
  4) r0/r1/r2/r3 provenance at the indirect transfer;
  5) exact slot READ/WRITE candidates only.

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

# -----------------------------------------------------------------------------
# Canonical inputs
# -----------------------------------------------------------------------------

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

CALLBACK_BASE = 0xF0096018
CALLBACK_SLOT = 0xF009605C
CALLBACK_OFF = CALLBACK_SLOT - CALLBACK_BASE  # 0x44

SELECT_CB = 0x10342FC4
SELECT_CB_THUMB = SELECT_CB | 1

# allow nearby platform-global seeds, but do not infer ownership from proximity alone
SEED_MIN = 0xF0095F00
SEED_MAX = 0xF0096100

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0x346C: "FIXED_PARENT_346C",
    0x3473: "FIXED_CHILD_3473",
    0xB0EC: "B0EC_PARENT",
}

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
class Sym:
    kind: str
    value: Optional[int] = None
    desc: str = ""

    def text(self):
        if self.kind == "CONST" and self.value is not None:
            return f"CONST 0x{self.value & 0xFFFFFFFF:08X}" + (
                f" ({self.desc})" if self.desc else ""
            )
        if self.kind == "CALLBACK_SLOT":
            return "CALLBACK_SLOT_VALUE" + (f" ({self.desc})" if self.desc else "")
        return self.kind + (f" ({self.desc})" if self.desc else "")


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
        raise SystemExit(f"ABORT: missing {name}: {path}")
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


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<9} {x.op_str}"


def md_for(mode: str):
    return md_t if mode == "THUMB" else md_a


def decode1(img: Image, addr: int, mode: str):
    if not img.contains(addr):
        return None
    md = md_for(mode)
    maxlen = 4
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+maxlen], addr, count=1))
    return xs[0] if xs else None


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None
    op = x.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def is_indirect_transfer(x):
    return (
        x is not None
        and x.mnemonic in {"blx", "bx"}
        and x.operands
        and x.operands[0].type == ARM_OP_REG
    )


def literal_load(img: Image, x, mode: str):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None

    dst, src = x.operands[0], x.operands[1]
    if dst.type != ARM_OP_REG or src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
        return None

    if mode == "THUMB":
        pc = (x.address + 4) & ~3
    else:
        pc = x.address + 8

    lit_addr = (pc + src.mem.disp) & 0xFFFFFFFF
    if not img.contains(lit_addr):
        return None

    val = u32(img.data, img.off(lit_addr))
    return x.reg_name(dst.reg), dst.reg, lit_addr, val


def all_hits(data: bytes, needle: bytes):
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def real_literal_xrefs_for_value(img: Image, value: int):
    """
    Find real ARM/Thumb PC-relative literal LDRs whose literal word == value.
    """
    raw = all_hits(img.data, struct.pack("<I", value & 0xFFFFFFFF))
    out = []

    for raw_off in raw:
        lit_addr = img.base + raw_off

        # Thumb: possible literal users generally within ~1 KiB.
        lo = max(0, raw_off - 0x500) & ~1
        for off in range(lo, raw_off + 1, 2):
            x = decode1(img, img.base + off, "THUMB")
            if x is None:
                continue
            li = literal_load(img, x, "THUMB")
            if li and li[2] == lit_addr and li[3] == value:
                out.append(("THUMB", x, lit_addr, value))

        # ARM
        lo = max(0, raw_off - 0x1000) & ~3
        for off in range(lo, raw_off + 1, 4):
            x = decode1(img, img.base + off, "ARM")
            if x is None:
                continue
            li = literal_load(img, x, "ARM")
            if li and li[2] == lit_addr and li[3] == value:
                out.append(("ARM", x, lit_addr, value))

    uniq = {}
    for mode, x, la, v in out:
        uniq[(mode, x.address, la)] = (mode, x, la, v)
    return [uniq[k] for k in sorted(uniq, key=lambda q: (q[1], q[0]))]


def nearby_platform_seed_values(img: Image):
    """
    Enumerate literal WORD values in the narrow F0095F00..F0096100 range.
    This is context only. Exact slot proof still requires symbolic effective address.
    """
    vals = {}
    for off in range(0, len(img.data)-4):
        v = u32(img.data, off)
        if v is None:
            continue
        if SEED_MIN <= v <= SEED_MAX:
            vals.setdefault(v, []).append(img.base + off)
    return vals


def sequential_decode(img: Image, start: int, mode: str, max_bytes=0x90):
    md = md_for(mode)
    end = min(img.end, start + max_bytes)
    if not img.contains(start):
        return []
    return list(md.disasm(img.data[img.off(start):img.off(end)], start))


def reg_name(x, reg):
    try:
        return x.reg_name(reg)
    except Exception:
        return f"reg{reg}"


def reg_writes(x):
    if not x.operands:
        return None
    op0 = x.operands[0]
    if op0.type == ARM_OP_REG:
        return op0.reg
    return None


def call_clobbers(regname: str):
    return regname in {"r0", "r1", "r2", "r3", "r12", "lr", "ip"}


def symbolic_forward_from_literal(img: Image, mode: str, seed_insn, seed_value: int, max_bytes=0xB0):
    """
    Short conservative symbolic execution from a REAL literal load.

    Tracks:
      - constants / base aliases;
      - effective memory loads;
      - callback-slot value if effective address == F009605C;
      - indirect BLX/BX through callback-slot value.

    This does not cross arbitrary branches. It reports what it sees on the
    linear decoded stream and is used for candidate recovery, not proof alone.
    """
    xs = sequential_decode(img, seed_insn.address, mode, max_bytes=max_bytes)
    regs = {}
    events = []

    seed_dst = None
    if seed_insn.operands and seed_insn.operands[0].type == ARM_OP_REG:
        seed_dst = seed_insn.operands[0].reg
        regs[seed_dst] = Sym("CONST", seed_value, f"seed literal @0x{seed_insn.address:08X}")

    for idx, x in enumerate(xs):
        if idx == 0:
            continue

        # Literal load
        li = literal_load(img, x, mode)
        if li:
            _, rid, la, val = li
            regs[rid] = Sym("CONST", val, f"literal @0x{la:08X}")
            continue

        # Calls clobber caller-saved regs, but preserve callee-saved aliases.
        if x.mnemonic in {"bl", "blx"}:
            if is_indirect_transfer(x):
                rid = x.operands[0].reg
                s = regs.get(rid, Sym("UNKNOWN"))
                if s.kind == "CALLBACK_SLOT":
                    events.append(("DISPATCH", x, rid, s))
                elif s.kind == "CONST" and s.value == SELECT_CB_THUMB:
                    events.append(("DIRECT_KNOWN_CB_TRANSFER", x, rid, s))

            # For a plain BLX reg, process transfer before clobbering.
            for rid in list(regs.keys()):
                rn = reg_name(x, rid)
                if call_clobbers(rn):
                    regs.pop(rid, None)
            continue

        if x.mnemonic == "bx":
            if is_indirect_transfer(x):
                rid = x.operands[0].reg
                s = regs.get(rid, Sym("UNKNOWN"))
                if s.kind == "CALLBACK_SLOT":
                    events.append(("DISPATCH", x, rid, s))
                elif s.kind == "CONST" and s.value == SELECT_CB_THUMB:
                    events.append(("DIRECT_KNOWN_CB_TRANSFER", x, rid, s))
            continue

        ops = x.operands
        dst = reg_writes(x)

        # MOV
        if x.mnemonic in {"mov", "movs"} and len(ops) >= 2 and dst is not None:
            src = ops[1]
            if src.type == ARM_OP_REG:
                regs[dst] = regs.get(src.reg, Sym("UNKNOWN", None, "mov source unknown"))
            elif src.type == ARM_OP_IMM:
                regs[dst] = Sym("CONST", src.imm & 0xFFFFFFFF, f"{x.mnemonic} imm")
            else:
                regs.pop(dst, None)
            continue

        # MOVW/MOVT
        if x.mnemonic == "movw" and len(ops) >= 2 and dst is not None and ops[1].type == ARM_OP_IMM:
            old = regs.get(dst)
            high = old.value & 0xFFFF0000 if old and old.kind == "CONST" and old.value is not None else 0
            regs[dst] = Sym("CONST", high | (ops[1].imm & 0xFFFF), "movw")
            continue

        if x.mnemonic == "movt" and len(ops) >= 2 and dst is not None and ops[1].type == ARM_OP_IMM:
            old = regs.get(dst)
            low = old.value & 0xFFFF if old and old.kind == "CONST" and old.value is not None else 0
            regs[dst] = Sym("CONST", low | ((ops[1].imm & 0xFFFF) << 16), "movt")
            continue

        # ADD/SUB immediate
        if x.mnemonic in {"add", "adds", "sub", "subs"} and dst is not None:
            if len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                old = regs.get(dst)
                if old and old.kind == "CONST" and old.value is not None:
                    d = ops[1].imm
                    nv = old.value + d if x.mnemonic.startswith("add") else old.value - d
                    regs[dst] = Sym("CONST", nv & 0xFFFFFFFF, f"{x.mnemonic} immediate")
                else:
                    regs.pop(dst, None)
                continue

            if len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                s = regs.get(ops[1].reg)
                if s and s.kind == "CONST" and s.value is not None:
                    d = ops[2].imm
                    nv = s.value + d if x.mnemonic.startswith("add") else s.value - d
                    regs[dst] = Sym("CONST", nv & 0xFFFFFFFF, f"{x.mnemonic} immediate")
                else:
                    regs.pop(dst, None)
                continue

        # LDR/LDxx memory
        if x.mnemonic.startswith("ldr") and len(ops) >= 2 and dst is not None and ops[1].type == ARM_OP_MEM:
            mem = ops[1].mem
            bn = reg_name(x, mem.base) if mem.base else "?"
            base_sym = regs.get(mem.base)
            if base_sym and base_sym.kind == "CONST" and base_sym.value is not None:
                ea = (base_sym.value + mem.disp) & 0xFFFFFFFF
                if ea == CALLBACK_SLOT:
                    regs[dst] = Sym("CALLBACK_SLOT", CALLBACK_SLOT, f"load @0x{x.address:08X}")
                    events.append(("SLOT_READ", x, dst, regs[dst]))
                else:
                    regs[dst] = Sym("MEM", None, f"[0x{base_sym.value:08X}{mem.disp:+#x}] => 0x{ea:08X}")
            else:
                regs[dst] = Sym("MEM", None, f"[{bn}{mem.disp:+#x}]")
            continue

        # Store to exact slot
        if x.mnemonic.startswith("str") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            mem = ops[1].mem
            base_sym = regs.get(mem.base)
            if base_sym and base_sym.kind == "CONST" and base_sym.value is not None:
                ea = (base_sym.value + mem.disp) & 0xFFFFFFFF
                if ea == CALLBACK_SLOT:
                    src = None
                    if ops[0].type == ARM_OP_REG:
                        src = regs.get(ops[0].reg, Sym("UNKNOWN"))
                    events.append(("SLOT_WRITE", x, ops[0].reg if ops[0].type == ARM_OP_REG else None, src))
            continue

        # Unknown writer invalidates dst.
        if dst is not None:
            regs.pop(dst, None)

    return xs, events


def local_backward_args(img: Image, mode: str, insns, call_addr: int):
    """
    Lightweight backwards source display for r0-r3 immediately before indirect transfer.
    """
    wanted = ["r0", "r1", "r2", "r3"]
    out = {}

    # discover capstone IDs by names from the local stream
    name_to_id = {}
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG:
                name_to_id.setdefault(reg_name(x, op.reg), op.reg)

    for rn in wanted:
        rid = name_to_id.get(rn)
        if rid is None:
            out[rn] = "UNKNOWN"
            continue

        desc = "ARG/INHERITED"
        hist = [x for x in insns if x.address < call_addr]
        for x in reversed(hist):
            # barrier only if this is a caller-saved reg
            if x.mnemonic in {"bl", "blx"} and call_clobbers(rn):
                desc = f"UNKNOWN(clobbered by call @0x{x.address:08X})"
                break

            if reg_writes(x) != rid:
                continue

            li = literal_load(img, x, mode)
            if li and li[1] == rid:
                desc = f"CONST 0x{li[3]:08X} via literal @0x{li[2]:08X}"
                break

            if x.mnemonic in {"mov", "movs"} and len(x.operands) >= 2:
                src = x.operands[1]
                if src.type == ARM_OP_IMM:
                    desc = f"CONST 0x{src.imm & 0xFFFFFFFF:08X} via {x.mnemonic} @0x{x.address:08X}"
                elif src.type == ARM_OP_REG:
                    desc = f"{rn} <- {reg_name(x, src.reg)} @0x{x.address:08X}"
                else:
                    desc = f"{x.mnemonic} @0x{x.address:08X}"
                break

            if x.mnemonic.startswith("ldr") and len(x.operands) >= 2 and x.operands[1].type == ARM_OP_MEM:
                m = x.operands[1].mem
                desc = f"MEM {x.mnemonic} [{reg_name(x,m.base)}{m.disp:+#x}] @0x{x.address:08X}"
                break

            desc = f"{x.mnemonic} {x.op_str} @0x{x.address:08X}"
            break

        out[rn] = desc

    return out


def print_candidate(img: Image, mode: str, seed_x, seed_value: int, xs, events):
    print()
    print("-" * 132)
    print(
        f"{img.name} {mode} seed @0x{seed_x.address:08X} "
        f"value=0x{seed_value:08X}"
    )
    print(fmt(seed_x))

    for kind, ev, rid, sym in events:
        print(f"  EVENT {kind}: {fmt(ev)} | {sym.text() if sym else ''}")

        if kind == "DISPATCH":
            args = local_backward_args(img, mode, xs, ev.address)
            print("    arguments at indirect transfer:")
            for rn in ("r0", "r1", "r2", "r3"):
                print(f"      {rn}: {args[rn]}")

    # Compact local context up through last interesting event.
    if events:
        last = max(ev.address for _, ev, _, _ in events)
        hi = min(img.end, last + 0x20)
    else:
        hi = min(img.end, seed_x.address + 0x60)

    print("  local decode:")
    md = md_for(mode)
    for x in md.disasm(
        img.data[img.off(seed_x.address):img.off(hi)],
        seed_x.address,
    ):
        mark = ">>> " if any(x.address == e.address for _, e, _, _ in events) else "    "
        print(mark + fmt(x))


def scan_image(img: Image):
    banner(f"CROSS-IMAGE SCAN — {img.name}")

    exact_values = [CALLBACK_BASE, CALLBACK_SLOT]
    all_candidates = []
    exact_counts = {}

    for value in exact_values:
        refs = real_literal_xrefs_for_value(img, value)
        exact_counts[value] = len(refs)
        print(f"real literal xrefs to 0x{value:08X} = {len(refs)}")
        for mode, x, la, v in refs:
            print(
                f"  {mode} {fmt(x)} "
                f"; literal@0x{la:08X}=0x{v:08X}"
            )
            xs, events = symbolic_forward_from_literal(img, mode, x, value)
            if events:
                all_candidates.append((mode, x, value, xs, events))

    # Nearby seeds: only values that really occur as words and have real xrefs.
    seed_vals = nearby_platform_seed_values(img)
    print(f"nearby F0095F00..F0096100 raw seed values = {len(seed_vals)}")

    seen_seed = set(exact_values)
    for value in sorted(seed_vals):
        if value in seen_seed:
            continue
        refs = real_literal_xrefs_for_value(img, value)
        if not refs:
            continue
        for mode, x, la, v in refs:
            xs, events = symbolic_forward_from_literal(img, mode, x, value)
            if any(kind in {"SLOT_READ", "SLOT_WRITE", "DISPATCH"} for kind, *_ in events):
                all_candidates.append((mode, x, value, xs, events))

    # Deduplicate candidate by seed address/mode
    uniq = {}
    for mode, x, value, xs, events in all_candidates:
        uniq[(mode, x.address)] = (mode, x, value, xs, events)
    candidates = [uniq[k] for k in sorted(uniq, key=lambda q: (q[1], q[0]))]

    print()
    print(f"symbolic candidates reaching exact slot = {len(candidates)}")

    dispatch_count = 0
    read_count = 0
    write_count = 0

    for mode, x, value, xs, events in candidates:
        for kind, *_ in events:
            if kind == "DISPATCH":
                dispatch_count += 1
            elif kind == "SLOT_READ":
                read_count += 1
            elif kind == "SLOT_WRITE":
                write_count += 1
        print_candidate(img, mode, x, value, xs, events)

    return {
        "exact_counts": exact_counts,
        "candidates": candidates,
        "dispatch_count": dispatch_count,
        "read_count": read_count,
        "write_count": write_count,
    }


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
        default="research/f2/work/reports/s13_5a12_cross_image_callback_dispatch.txt",
    )
    return p.parse_args()


def resolve(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    args = parse_args()
    root = Path.cwd()

    alice_path = resolve(root, args.alice)
    zimage_path = resolve(root, args.zimage)
    report_path = resolve(root, args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    cap = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = Tee(old_stdout, cap)

    try:
        banner("S13.5A.12 - CROSS-IMAGE CALLBACK SLOT READER / DISPATCH AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")
        print()
        print(f"CALLBACK_BASE = 0x{CALLBACK_BASE:08X}")
        print(f"CALLBACK_SLOT = 0x{CALLBACK_SLOT:08X}")
        print(f"OFFSET        = 0x{CALLBACK_OFF:X}")
        print(f"SELECT_CB     = 0x{SELECT_CB_THUMB:08X}")

        banner("A. CANONICAL INPUTS")
        alice = verify(
            alice_path, "ALICE",
            ALICE_BASE, ALICE_SIZE, ALICE_SHA256,
        )
        zimage = verify(
            zimage_path, "ZIMAGE",
            ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA256,
        )

        results = {}
        for img in (alice, zimage):
            results[img.name] = scan_image(img)

        banner("B. CROSS-IMAGE DECISION GATE")

        total_dispatch = sum(r["dispatch_count"] for r in results.values())
        total_reads = sum(r["read_count"] for r in results.values())
        total_writes = sum(r["write_count"] for r in results.values())

        for name, r in results.items():
            print(f"{name}:")
            print(f"  xrefs CALLBACK_BASE = {r['exact_counts'].get(CALLBACK_BASE,0)}")
            print(f"  xrefs CALLBACK_SLOT = {r['exact_counts'].get(CALLBACK_SLOT,0)}")
            print(f"  exact-slot reads    = {r['read_count']}")
            print(f"  exact-slot writes   = {r['write_count']}")
            print(f"  indirect dispatches = {r['dispatch_count']}")

        print()
        print(f"TOTAL exact-slot reads    = {total_reads}")
        print(f"TOTAL exact-slot writes   = {total_writes}")
        print(f"TOTAL indirect dispatches = {total_dispatch}")
        print()

        if total_dispatch:
            print("[PASS] At least one exact callback-slot reader reaches an indirect transfer.")
            print("[NEXT] Promote only candidates where the callback value loaded from")
            print("       F009605C is the register used by BLX/BX.")
            print("       Then classify r0 at that transfer as selection index only if")
            print("       its producer is structurally a list/menu cursor/index.")
        elif total_reads:
            print("[PASS] Exact callback-slot reader recovered, but no transfer yet.")
            print("[NEXT] Extend only the recovered reader function/control-flow path.")
        else:
            print("[OPEN] No literal-seeded exact slot reader recovered.")
            print("[NEXT] Audit writers/readers of nearby platform object F0096018 using")
            print("       callers that receive its address indirectly; do not broad-scan IDs.")

        print()
        print("INVARIANTS:")
        print("  0x10317C58 stores current callback at F009605C")
        print("  0x10342FC5 is installed there on the generic menu path")
        print("  0x10315514(index) returns descriptor.children[index]")
        print("  SELECT_CB stores that child ID to descriptor+0x18")
        print("  enter-submenu copies +0x18 -> +0x14 before provider-backed rebuild")
        print()
        print("STILL UNKNOWN:")
        print("  exact semantic source of r0 when SELECT_CB is dispatched")
        print("  numeric Multimedia ID")
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
        sys.stdout = old_stdout
        report_path.write_text(cap.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
