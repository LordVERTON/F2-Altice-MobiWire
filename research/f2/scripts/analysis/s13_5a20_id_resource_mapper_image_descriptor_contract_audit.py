#!/usr/bin/env python3
"""
S13.5A.20 - ID->RESOURCE MAPPER / IMAGE DESCRIPTOR CONTRACT AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.19 established two strong facts:

  1) Image ID 0x8321 and Audio ID 0x8928 are both passed as r0 to
     the same ALICE helper 0x10319094.

  2) ALICE wrapper 0x10348810 does:
         r0 = 0xF03B3870
         bl  0x1034C208

     and 0x1034C208 interprets that descriptor structurally:
         descriptor+0x00 : u16 ID
         descriptor+0x04 : pointer to an entry list
     then iterates the list with stride 0x10 and terminates when
         [entry+0x04] == 0.

Therefore A.19's zero-terminated-u16 interpretation of F03B388C/F03B38D8
is SUPERSEDED. Those targets must be decoded as fixed-size records.

This pass answers:

  A. What exactly does 0x10319094 do?
  B. Which real constant IDs are passed to it by code?
  C. How is its return value consumed?
  D. Which resolver IDs flow through it?
  E. What is the exact F03B3870 descriptor / 0x10-entry contract?
  F. What other constant descriptors are genuinely passed to 0x1034C208?
  G. Does any such descriptor expose a sibling family useful for identifying
     FM Radio or the visible Multimedia node?

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
from collections import defaultdict

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

# -----------------------------------------------------------------------------
# Canonical images
# -----------------------------------------------------------------------------

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

# -----------------------------------------------------------------------------
# Known targets
# -----------------------------------------------------------------------------

ID_MAP_HELPER = 0x10319094
IMAGE_DESC_CONSUMER = 0x1034C208
IMAGE_DESC_WRAPPER = 0x10348810

IMAGE_DESC_BASE = 0xF03B3870
IMAGE_DESC_SECOND = 0xF03B3878

RESOLVER_BASE = 0xF0345E68
RESOLVER_COUNT = 58
RESOLVER_STRIDE = 8

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
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
class ResolverRow:
    index: int
    addr: int
    menu_id: int
    field2: int
    callback_ptr: int

    @property
    def callback(self):
        return self.callback_ptr & ~1


@dataclass
class Descriptor:
    addr: int
    root_id: int
    field2: int
    list_ptr: int


@dataclass
class Entry16:
    addr: int
    item_id: int
    field2: int
    ptr_a: int
    ptr_b: int
    value_c: int


# -----------------------------------------------------------------------------
# Basic helpers
# -----------------------------------------------------------------------------

def banner(s: str):
    print()
    print("=" * 140)
    print(s)
    print("=" * 140)


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


def image_for(images, addr: int):
    a = addr & ~1
    for img in images:
        if img.contains(a):
            return img
    return None


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


def is_prologue(x):
    return bool(x and x.mnemonic == "push" and "lr" in x.op_str)


def is_return(x):
    if x is None:
        return False

    if x.mnemonic == "bx" and x.op_str.strip() == "lr":
        return True

    if x.mnemonic == "pop" and "pc" in x.op_str:
        return True

    return False


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
            notes.append(f"literal@0x{la:08X}=0x{val:08X}->{rn}")

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


def enclosing_function(img: Image, target: int, back=0x500, forward=0x900):
    cands = candidate_prologues(img, target, back, forward)

    if not cands:
        # tiny leaf function may begin exactly at target without PUSH
        xs = dis(img, target, min(img.end, target+0x100), "THUMB")
        end = None
        for x in xs:
            if is_return(x):
                end = x.address + len(x.bytes)
                break
        return target, end or min(img.end, target+0x80)

    start = cands[-1]
    xs = dis(img, start, min(img.end, start+forward), "THUMB")

    end = None
    passed = False

    for x in xs:
        if x.address >= target:
            passed = True

        if passed and is_return(x):
            end = x.address + len(x.bytes)
            break

    return start, end or min(img.end, start+0x180)


def scan_direct_calls(img: Image, target: int):
    out = []

    # Thumb BL/BLX immediate.
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

    # ARM BL/BLX immediate.
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
        for off in all_hits(img.data, struct.pack("<I", v)):
            out.append((img.base+off, v))

    return sorted(set(out))


def real_literal_xrefs_to_word(img: Image, word_addr: int):
    out = []

    for a in range(max(img.base, word_addr-0x500) & ~1, word_addr+1, 2):
        x = decode1(img, a, "THUMB")
        li = literal_load(img, x, "THUMB") if x else None
        if li and li[2] == word_addr:
            out.append(("THUMB", x, li[3]))

    for a in range(max(img.base, word_addr-0x1000) & ~3, word_addr+1, 4):
        x = decode1(img, a, "ARM")
        li = literal_load(img, x, "ARM") if x else None
        if li and li[2] == word_addr:
            out.append(("ARM", x, li[3]))

    uniq = {(m, x.address): (m, x, v) for m, x, v in out}
    return [uniq[k] for k in sorted(uniq)]


# -----------------------------------------------------------------------------
# Resolver
# -----------------------------------------------------------------------------

def parse_resolver(zimage: Image):
    rows = []
    off = zimage.off(RESOLVER_BASE)

    for i in range(RESOLVER_COUNT):
        roff = off + i*RESOLVER_STRIDE

        rows.append(
            ResolverRow(
                index=i,
                addr=RESOLVER_BASE+i*RESOLVER_STRIDE,
                menu_id=u16(zimage.data, roff),
                field2=u16(zimage.data, roff+2),
                callback_ptr=u32(zimage.data, roff+4),
            )
        )

    return rows


# -----------------------------------------------------------------------------
# Backward value recovery for caller arguments
# -----------------------------------------------------------------------------

def reg_written(x):
    if not x.operands:
        return None

    o = x.operands[0]
    return o.reg if o.type == ARM_OP_REG else None


def reg_id_by_name(insns, name):
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == name:
                return op.reg
    return None


def backward_const(img: Image, insns, before_addr: int, regname: str, depth=0):
    """
    Conservative backwards constant/source slicer.
    Returns tuple(kind, value, description), where value is int for CONST.
    """
    if depth > 10:
        return ("UNKNOWN", None, "depth-limit")

    hist = [x for x in insns if x.address < before_addr]
    rid = reg_id_by_name(hist, regname)

    if rid is None:
        return ("UNKNOWN", None, f"{regname} unseen")

    caller_saved = regname in {"r0","r1","r2","r3","r12","ip","lr"}

    for i in range(len(hist)-1, -1, -1):
        x = hist[i]

        if x.mnemonic in {"bl","blx"} and caller_saved:
            return ("UNKNOWN", None, f"{regname} clobbered by call @0x{x.address:08X}")

        if reg_written(x) != rid:
            continue

        li = literal_load(img, x, "THUMB")
        if li and li[1] == rid:
            return ("CONST", li[3], f"literal @0x{li[2]:08X}")

        ops = x.operands

        if x.mnemonic in {"mov","movs"} and len(ops)>=2:
            s = ops[1]

            if s.type == ARM_OP_IMM:
                return ("CONST", s.imm & 0xFFFFFFFF, f"{x.mnemonic} @0x{x.address:08X}")

            if s.type == ARM_OP_REG:
                src = x.reg_name(s.reg)
                kind,val,desc = backward_const(
                    img, hist[:i+1], x.address, src, depth+1
                )
                return (kind,val,f"{regname}<-{src} @0x{x.address:08X} <- {desc}")

        # movw / movt local pair
        if x.mnemonic == "movw" and len(ops)>=2 and ops[1].type == ARM_OP_IMM:
            low = ops[1].imm & 0xFFFF
            high = 0

            # Search earlier movt for same register is not valid order;
            # search forward between x and before_addr for movt.
            for y in hist[i+1:]:
                if y.address >= before_addr:
                    break
                if (
                    y.mnemonic == "movt"
                    and reg_written(y) == rid
                    and len(y.operands)>=2
                    and y.operands[1].type == ARM_OP_IMM
                ):
                    high = (y.operands[1].imm & 0xFFFF) << 16
                    break

            return ("CONST", high|low, f"movw[/movt] @0x{x.address:08X}")

        if x.mnemonic.startswith("ldr") and len(ops)>=2 and ops[1].type == ARM_OP_MEM:
            m = ops[1].mem
            return (
                "MEM",
                None,
                f"{x.mnemonic} [{x.reg_name(m.base)}{m.disp:+#x}] @0x{x.address:08X}"
            )

        if x.mnemonic in {"add","adds","sub","subs"}:
            # 2-op register += immediate form.
            imm = None
            for op in ops[1:]:
                if op.type == ARM_OP_IMM:
                    imm = op.imm
                    break

            if imm is not None:
                # recover source from same register before arithmetic
                kind,val,desc = backward_const(
                    img, hist[:i], x.address, regname, depth+1
                )
                if kind == "CONST" and val is not None:
                    if x.mnemonic.startswith("add"):
                        val = (val + imm) & 0xFFFFFFFF
                    else:
                        val = (val - imm) & 0xFFFFFFFF
                    return ("CONST", val, f"{desc}; {x.mnemonic} #{imm} @0x{x.address:08X}")

            return ("EXPR", None, f"{x.mnemonic} {x.op_str} @0x{x.address:08X}")

        return ("UNKNOWN", None, f"writer {x.mnemonic} {x.op_str} @0x{x.address:08X}")

    return ("ARG", None, regname)


# -----------------------------------------------------------------------------
# Return-use tracing
# -----------------------------------------------------------------------------

def trace_return_use(img: Image, call_addr: int, function_end: int, max_insns=24):
    """
    Follow result initially in r0 until first meaningful store/pass/transform.
    """
    xs = dis(img, call_addr+4, min(function_end, call_addr+4+0x80), "THUMB")

    r0_id = reg_id_by_name(xs, "r0")
    if r0_id is None:
        return []

    aliases = {r0_id}
    events = []

    for x in xs[:max_insns]:
        ops = x.operands

        if is_return(x):
            events.append(("RETURN", x, ""))
            break

        # alias result into another register
        if x.mnemonic in {"mov","movs"} and len(ops)>=2:
            d,s = ops[0],ops[1]
            if d.type==ARM_OP_REG and s.type==ARM_OP_REG and s.reg in aliases:
                aliases.add(d.reg)
                events.append(("ALIAS",x,f"{x.reg_name(d.reg)} <- return"))

        # Store returned scalar.
        if x.mnemonic.startswith("str") and len(ops)>=2:
            src,mem = ops[0],ops[1]
            if (
                src.type==ARM_OP_REG
                and src.reg in aliases
                and mem.type==ARM_OP_MEM
            ):
                events.append(
                    ("STORE",x,
                     f"return -> [{x.reg_name(mem.mem.base)}{mem.mem.disp:+#x}]")
                )

        # Passed in r1/r2/r3 at a later call.
        if x.mnemonic in {"bl","blx"}:
            target=direct_target(x)
            passed=[]

            for rid in aliases:
                rn=x.reg_name(rid)
                if rn in {"r0","r1","r2","r3"}:
                    passed.append(rn)

            if passed:
                events.append(
                    ("CALL_USE",x,
                     f"return in {','.join(sorted(passed))} -> "
                     f"{('0x%08X'%target) if target is not None else x.op_str}")
                )

            # caller-saved aliases die
            aliases={
                rid for rid in aliases
                if x.reg_name(rid) not in {"r0","r1","r2","r3","r12","ip","lr"}
            }

        # Compare result.
        if x.mnemonic.startswith("cmp"):
            if any(op.type==ARM_OP_REG and op.reg in aliases for op in ops):
                events.append(("COMPARE",x,x.op_str))

        # Arithmetic result.
        if x.mnemonic in {"add","adds","sub","subs","lsls","lsrs"}:
            if any(op.type==ARM_OP_REG and op.reg in aliases for op in ops):
                events.append(("ARITH",x,x.op_str))

        # Generic overwrite of alias destination.
        if ops and ops[0].type==ARM_OP_REG and ops[0].reg in aliases:
            dst=ops[0].reg
            preserving=(
                x.mnemonic in {"mov","movs"}
                and len(ops)>=2
                and ops[1].type==ARM_OP_REG
                and ops[1].reg in aliases
            )
            if not preserving and not x.mnemonic.startswith("str"):
                aliases.discard(dst)

        if not aliases and events:
            break

    return events


# -----------------------------------------------------------------------------
# 0x10319094 helper audit
# -----------------------------------------------------------------------------

def helper_audit(images, alice: Image, rows):
    banner("B. 0x10319094 ID->RESOURCE/MAPPING HELPER")

    start,end = enclosing_function(alice, ID_MAP_HELPER)

    print(f"target                 = 0x{ID_MAP_HELPER:08X}")
    print(f"enclosing function     = 0x{start:08X}..0x{end:08X}")
    print_region(alice,start,end,"THUMB",{ID_MAP_HELPER})

    # literal/global inventory inside helper
    print()
    print("helper literal/global inventory:")
    literals=[]

    for x in dis(alice,start,end,"THUMB"):
        li=literal_load(alice,x,"THUMB")
        if li:
            literals.append((x,li))
            print(
                f"  {fmt(x)} ; literal@0x{li[2]:08X}=0x{li[3]:08X}"
            )

    # callers
    banner("C. REAL CALLERS OF 0x10319094")

    resolver_ids={r.menu_id:r for r in rows}
    call_records=[]
    constants=defaultdict(list)

    for img in images:
        calls=scan_direct_calls(img,ID_MAP_HELPER)
        print(f"{img.name}: direct callers = {len(calls)}")

        for mode,x in calls:
            if mode!="THUMB":
                print(f"  {mode} {fmt(x)}")
                continue

            fs,fe=enclosing_function(img,x.address)
            ins=dis(img,fs,fe,"THUMB")
            kind,val,desc=backward_const(img,ins,x.address,"r0")

            tag=[]
            if kind=="CONST" and val is not None:
                if val in KNOWN_IDS:
                    tag.append(KNOWN_IDS[val])
                if val in resolver_ids:
                    tag.append("RESOLVER_ID")
                if 0x8300 <= val <= 0x83FF:
                    tag.append("83xx")
                if 0x8900 <= val <= 0x89FF:
                    tag.append("89xx")

            print()
            print(
                f"{img.name} caller {fmt(x)} "
                f"function=0x{fs:08X}..0x{fe:08X}"
            )

            if kind=="CONST":
                print(
                    f"  r0 source = CONST 0x{val:08X}"
                    + (f" <{'|'.join(tag)}>" if tag else "")
                    + f" via {desc}"
                )
                constants[val].append((img,x,fs,fe))
            else:
                print(f"  r0 source = {kind}: {desc}")

            events=trace_return_use(img,x.address,fe)
            print("  return use:")
            if not events:
                print("    none auto-resolved")
            else:
                for ek,ex,ed in events:
                    print(
                        f"    {ek:<10} {fmt(ex)}"
                        + (f" | {ed}" if ed else "")
                    )

            call_records.append((img,mode,x,fs,fe,kind,val,desc,events))

    banner("D. CONSTANT IDS PASSED TO 0x10319094")
    print(f"unique constant inputs = {len(constants)}")

    resolver_constant_ids=[]

    for val in sorted(constants):
        tags=[]
        if val in KNOWN_IDS:
            tags.append(KNOWN_IDS[val])
        if val in resolver_ids:
            tags.append("RESOLVER_ID")
            resolver_constant_ids.append(val)
        if 0x8300 <= val <= 0x83FF:
            tags.append("83xx")
        if 0x8900 <= val <= 0x89FF:
            tags.append("89xx")

        print(
            f"  0x{val:08X}"
            + (f" <{'|'.join(tags)}>" if tags else "")
            + f" callers={len(constants[val])}"
        )

        if val in resolver_ids:
            r=resolver_ids[val]
            print(
                f"      resolver row#{r.index} @0x{r.addr:08X} "
                f"callback=0x{r.callback_ptr:08X}"
            )

        for img,x,fs,fe in constants[val][:10]:
            print(
                f"      {img.name} call@0x{x.address:08X} "
                f"function=0x{fs:08X}"
            )

    print()
    print(
        "resolver IDs passed as real constants = "
        + (
            ", ".join(f"0x{x:04X}" for x in sorted(resolver_constant_ids))
            if resolver_constant_ids else "NONE"
        )
    )

    return start,end,call_records,constants,resolver_constant_ids


# -----------------------------------------------------------------------------
# Descriptor contract
# -----------------------------------------------------------------------------

def read_descriptor(images, addr: int):
    img=image_for(images,addr)
    if img is None or not img.contains(addr+7):
        return None

    off=img.off(addr)

    return Descriptor(
        addr=addr,
        root_id=u16(img.data,off),
        field2=u16(img.data,off+2),
        list_ptr=u32(img.data,off+4),
    )


def read_entry16(images, addr: int):
    img=image_for(images,addr)
    if img is None or not img.contains(addr+15):
        return None

    off=img.off(addr)

    return Entry16(
        addr=addr,
        item_id=u16(img.data,off),
        field2=u16(img.data,off+2),
        ptr_a=u32(img.data,off+4),
        ptr_b=u32(img.data,off+8),
        value_c=u32(img.data,off+12),
    )


def parse_entry_list(images, ptr: int, max_records=64):
    records=[]

    p=ptr & ~1

    for _ in range(max_records):
        rec=read_entry16(images,p)
        if rec is None:
            break

        # Owner 0x1034C208 terminates when [entry+4] == 0.
        if rec.ptr_a == 0:
            return records,p,rec

        records.append(rec)
        p += 0x10

    return records,p,None


def print_descriptor(images, desc: Descriptor, resolver_ids):
    tags=[]
    if desc.root_id in KNOWN_IDS:
        tags.append(KNOWN_IDS[desc.root_id])
    if desc.root_id in resolver_ids:
        tags.append("RESOLVER_ID")

    print(
        f"descriptor@0x{desc.addr:08X}: "
        f"root_id=0x{desc.root_id:04X}"
        + (f" <{'|'.join(tags)}>" if tags else "")
        + f" field2=0x{desc.field2:04X} "
        f"list_ptr=0x{desc.list_ptr:08X}"
    )

    records,term_addr,term_rec=parse_entry_list(images,desc.list_ptr)

    print(f"  0x10-byte records = {len(records)}")

    for i,rec in enumerate(records):
        itags=[]
        if rec.item_id in KNOWN_IDS:
            itags.append(KNOWN_IDS[rec.item_id])
        if rec.item_id in resolver_ids:
            itags.append("RESOLVER_ID")

        print(
            f"    [{i:02d}] 0x{rec.addr:08X}: "
            f"id=0x{rec.item_id:04X}"
            + (f" <{'|'.join(itags)}>" if itags else "")
            + f" field2=0x{rec.field2:04X} "
            f"ptrA=0x{rec.ptr_a:08X} "
            f"ptrB=0x{rec.ptr_b:08X} "
            f"valueC=0x{rec.value_c:08X}"
        )

        # Small u16 view of ptrB when it points inside images: often looks like
        # an ID sub-array. Supporting only.
        pimg=image_for(images,rec.ptr_b)
        if pimg and pimg.contains((rec.ptr_b & ~1)+1):
            vals=[]
            for j in range(min(rec.value_c if 0 < rec.value_c < 32 else 8, 16)):
                off=pimg.off((rec.ptr_b & ~1)+j*2)
                v=u16(pimg.data,off)
                if v is None:
                    break
                vals.append(v)

            if vals:
                print(
                    "         ptrB u16 support: "
                    + " ".join(
                        f"{v:04X}"
                        + (
                            f"<{KNOWN_IDS[v]}>"
                            if v in KNOWN_IDS
                            else ("<RES>" if v in resolver_ids else "")
                        )
                        for v in vals
                    )
                )

    if term_rec is not None:
        print(
            f"  terminator @0x{term_addr:08X}: "
            f"id=0x{term_rec.item_id:04X} ptrA=0"
        )
    else:
        print("  terminator: not recovered inside bound")


def descriptor_contract_audit(images, alice: Image, rows):
    banner("E. 0x1034C208 DESCRIPTOR CONTRACT")

    resolver_ids={r.menu_id:r for r in rows}

    # Show wrapper.
    ws,we=enclosing_function(alice,IMAGE_DESC_WRAPPER)
    print(
        f"known wrapper function = 0x{ws:08X}..0x{we:08X}"
    )
    print_region(
        alice,ws,we,"THUMB",
        {IMAGE_DESC_WRAPPER,IMAGE_DESC_WRAPPER+2,IMAGE_DESC_WRAPPER+4}
    )

    # Show consumer.
    cs,ce=enclosing_function(alice,IMAGE_DESC_CONSUMER)
    print()
    print(
        f"descriptor consumer = 0x{cs:08X}..0x{ce:08X}"
    )
    print_region(
        alice,cs,ce,"THUMB",
        {
            0x1034C210, # r4=[desc+4]
            0x1034C220, # ldrh [desc]
            0x1034C242, # ldrh [entry]
            0x1034C290, # entry += 0x10
            0x1034C292, # ldr [entry+4]
        }
    )

    banner("F. CORRECTED F03B3870/F03B3878 DESCRIPTORS")

    known_descs=[]

    for addr in (IMAGE_DESC_BASE,IMAGE_DESC_SECOND):
        desc=read_descriptor(images,addr)
        if desc:
            known_descs.append(desc)
            print_descriptor(images,desc,resolver_ids)
            print()

    # Direct callers to 1034C208 and their r0 sources.
    banner("G. ALL REAL CALLERS OF 0x1034C208")

    desc_candidates={}

    for img in images:
        calls=scan_direct_calls(img,IMAGE_DESC_CONSUMER)
        print(f"{img.name}: direct callers = {len(calls)}")

        for mode,x in calls:
            if mode!="THUMB":
                print(f"  {mode} {fmt(x)}")
                continue

            fs,fe=enclosing_function(img,x.address)
            ins=dis(img,fs,fe,"THUMB")
            kind,val,desc_text=backward_const(img,ins,x.address,"r0")

            print()
            print(
                f"{img.name} {fmt(x)} "
                f"function=0x{fs:08X}..0x{fe:08X}"
            )

            if kind=="CONST":
                print(f"  r0 = 0x{val:08X} via {desc_text}")
                candidate=read_descriptor(images,val)
                if candidate:
                    desc_candidates[val]=candidate
                    print("  [DESCRIPTOR-SHAPE PASS]")
                    print_descriptor(images,candidate,resolver_ids)
                else:
                    print("  [NOT AN IN-IMAGE 8-BYTE DESCRIPTOR]")
            else:
                print(f"  r0 source = {kind}: {desc_text}")

    print()
    print(
        "unique constant descriptors passed to 0x1034C208 = "
        f"{len(desc_candidates)}"
    )

    # Raw function pointer ownership for the known wrapper.
    banner("H. WRAPPER 0x10348810 OWNERSHIP")
    direct=[]
    ptrs=[]

    for img in images:
        dc=scan_direct_calls(img,IMAGE_DESC_WRAPPER)
        rp=raw_pointer_refs(img,IMAGE_DESC_WRAPPER)
        direct.extend((img,mode,x) for mode,x in dc)
        ptrs.extend((img,a,v) for a,v in rp)

    print(f"direct callers = {len(direct)}")
    for img,mode,x in direct:
        print(f"  {img.name} {mode} {fmt(x)}")

    print(f"raw pointer refs = {len(ptrs)}")
    for img,a,v in ptrs:
        print(f"  {img.name} word@0x{a:08X}=0x{v:08X}")
        lx=real_literal_xrefs_to_word(img,a)
        print(f"    real literal xrefs={len(lx)}")
        for mode,x,val in lx[:20]:
            print(f"      {mode} {fmt(x)}")

    return known_descs,desc_candidates


# -----------------------------------------------------------------------------
# Cross-correlation
# -----------------------------------------------------------------------------

def cross_correlation(rows, constants, descriptors):
    banner("I. CROSS-CORRELATION: MAPPER INPUTS vs DESCRIPTOR IDS")

    resolver_ids={r.menu_id:r for r in rows}

    desc_ids=set()

    for desc in descriptors:
        desc_ids.add(desc.root_id)
        records,_,_=parse_entry_list(IMAGES,desc.list_ptr)
        desc_ids.update(r.item_id for r in records)

        for r in records:
            pimg=image_for(IMAGES,r.ptr_b)
            if pimg and 0 < r.value_c <= 32:
                for i in range(r.value_c):
                    v=u16(pimg.data,pimg.off((r.ptr_b & ~1)+i*2))
                    if v is not None:
                        desc_ids.add(v)

    mapper_ids=set(
        val for val in constants
        if 0 <= val <= 0xFFFF
    )

    shared=sorted(desc_ids & mapper_ids)

    print(f"descriptor-family 16-bit IDs = {len(desc_ids)}")
    print(f"mapper constant 16-bit IDs   = {len(mapper_ids)}")
    print(
        "intersection = "
        + (", ".join(f"0x{x:04X}" for x in shared) if shared else "NONE")
    )

    for v in shared:
        tags=[]
        if v in KNOWN_IDS:
            tags.append(KNOWN_IDS[v])
        if v in resolver_ids:
            tags.append("RESOLVER_ID")

        print(
            f"  0x{v:04X}"
            + (f" <{'|'.join(tags)}>" if tags else "")
        )


# Global populated after load for helper function above.
IMAGES=[]


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def parse_args():
    p=argparse.ArgumentParser()

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
        default="research/f2/work/reports/s13_5a20_id_resource_mapper_image_descriptor_contract.txt",
    )

    return p.parse_args()


def resolve(root: Path,s: str):
    p=Path(s)
    return p if p.is_absolute() else root/p


def main():
    global IMAGES

    args=parse_args()
    root=Path.cwd()

    report_path=resolve(root,args.report)
    report_path.parent.mkdir(parents=True,exist_ok=True)

    capture=io.StringIO()
    old=sys.stdout
    sys.stdout=Tee(old,capture)

    try:
        banner("S13.5A.20 - ID->RESOURCE MAPPER / IMAGE DESCRIPTOR CONTRACT AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice=verify(
            resolve(root,args.alice),
            "ALICE",
            ALICE_BASE,
            ALICE_SIZE,
            ALICE_SHA256,
        )

        zimage=verify(
            resolve(root,args.zimage),
            "ZIMAGE",
            ZIMAGE_BASE,
            ZIMAGE_SIZE,
            ZIMAGE_SHA256,
        )

        IMAGES=[alice,zimage]
        rows=parse_resolver(zimage)

        helper_start,helper_end,call_records,constants,resolver_mapper_ids = helper_audit(
            IMAGES,alice,rows
        )

        known_descs,desc_candidates = descriptor_contract_audit(
            IMAGES,alice,rows
        )

        all_descs={d.addr:d for d in known_descs}
        all_descs.update(desc_candidates)

        cross_correlation(rows,constants,list(all_descs.values()))

        banner("J. DECISION GATE")

        shared_helper_fact = (
            0x8321 in constants
            and 0x8928 in constants
        )

        f03_contract_fact = False

        d0=read_descriptor(IMAGES,IMAGE_DESC_BASE)
        if d0:
            records,term_addr,term_rec=parse_entry_list(IMAGES,d0.list_ptr)
            f03_contract_fact = (
                d0.root_id == 0x8313
                and d0.list_ptr == 0xF03B388C
                and len(records) >= 1
                and term_rec is not None
            )

        print(
            f"0x8321 and 0x8928 both call 0x10319094 = "
            f"{'PASS' if shared_helper_fact else 'OPEN'}"
        )

        print(
            f"F03B3870 corrected descriptor/list contract = "
            f"{'PASS' if f03_contract_fact else 'OPEN'}"
        )

        print(
            f"unique constant descriptors -> 1034C208 = {len(desc_candidates)}"
        )

        print(
            "resolver IDs passed as constants to 10319094 = "
            + (
                ", ".join(f"0x{x:04X}" for x in sorted(resolver_mapper_ids))
                if resolver_mapper_ids else "NONE"
            )
        )

        print()

        if f03_contract_fact:
            print("[FACT] F03B3870 is consumed as an Image-style descriptor:")
            print("       +0x00 u16 root ID, +0x04 pointer to 0x10-byte records,")
            print("       with record iteration terminating on [entry+0x04] == 0.")
            print("       A.19's zero-terminated-u16 interpretation is SUPERSEDED.")
            print("       This still does NOT make it a Multimedia child table.")

        if shared_helper_fact:
            print()
            print("[FACT] Image 0x8321 and Audio 0x8928 both flow through 0x10319094.")
            print("[NEXT] Classify 0x10319094 from its exact body and constant-input census.")
            print("       If it is an ID->label/resource mapping API, use its real caller set")
            print("       to recover the IDs of sibling visible applications, including FM.")

        print()
        print("PROMOTION RULES:")
        print("  - Do not call an unknown 0x83xx value a menu item solely because it")
        print("    appears in an Image descriptor.")
        print("  - Do not call mapper inputs Multimedia/FM without a structural owner.")
        print("  - Only use real callsites and provider-backed menu relations for final membership.")
        print()
        print("STILL UNKNOWN:")
        print("  numeric visible Multimedia ID")
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
        sys.stdout=old
        report_path.write_text(capture.getvalue(),encoding="utf-8")


if __name__=="__main__":
    raise SystemExit(main())
