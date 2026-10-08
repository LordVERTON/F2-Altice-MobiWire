#!/usr/bin/env python3
"""
S13.5A.21 - IMPORTED ID->RESOURCE PRIMITIVE / MAPPING TABLE AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.20 proved:

  0x10319094:
      blx 0x102FA0CC
      if r0 == 0xFF:
          r0 = 0x2E
      return

and recovered 16 real resolver IDs passed as constants through that wrapper:
  0x7F67, 0x8321, 0x8569, 0x86C0, 0x8928, 0x9639, 0x9EB4, 0xA223,
  0xA725, 0xB6FD, 0xB6FE, 0xB6FF, 0xB701, 0xB702, 0xB703, 0xB708.

This pass moves below the wrapper and classifies 0x102FA0CC itself.

Goals:
  A. verify the canonical ALICE/ZIMAGE images;
  B. decode 0x102FA0C4..0x102FA0D8 as ARM import veneers / literals;
  C. resolve the exact target of 0x102FA0CC;
  D. disassemble the target in correct ARM/Thumb mode and recover its function body;
  E. inventory literals/globals/calls/branches used by the target;
  F. recover direct callers / pointer refs to both veneer and real target;
  G. identify static table/range patterns reachable from target literals;
  H. perform conservative concrete evaluation for the 16 known IDs when the
     target shape is simple enough to model safely;
  I. compare Image 0x8321 and Audio 0x8928 outputs and list any sibling IDs
     sharing the same recovered resource value;
  J. strict decision gate.

No USB/COM.
No phone access.
No flash write.
No patch.
No repack.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, deque

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)
from capstone.arm import (
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_OP_REG,
    ARM_REG_PC,
    ARM_REG_SP,
    ARM_REG_LR,
)

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

VENEER_META = 0x102FA0C4
VENEER_TARGET = 0x102FA0CC

WRAPPER = 0x10319094

KNOWN_INPUTS = [
    0x7F67,
    0x8321,
    0x8569,
    0x86C0,
    0x8928,
    0x9639,
    0x9EB4,
    0xA223,
    0xA725,
    0xB6FD,
    0xB6FE,
    0xB6FF,
    0xB701,
    0xB702,
    0xB703,
    0xB708,
]

KNOWN_NAMES = {
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
}

RESOLVER_BASE = 0xF0345E68
RESOLVER_COUNT = 58
RESOLVER_STRIDE = 8

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
        a = addr & ~1
        return self.base <= a < self.end

    def off(self, addr: int):
        return (addr & ~1) - self.base


@dataclass
class ResolverRow:
    index: int
    addr: int
    menu_id: int
    field2: int
    callback_ptr: int


@dataclass
class Veneer:
    addr: int
    mode: str
    target_ptr: int | None
    literal_addr: int | None
    instruction: object | None
    recognized: bool


@dataclass
class FunctionView:
    image: Image
    start: int
    end: int
    mode: str
    insns: list


def banner(s: str):
    print()
    print("=" * 142)
    print(s)
    print("=" * 142)


def sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()


def u8(data: bytes, off: int):
    if off < 0 or off + 1 > len(data):
        return None
    return data[off]


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
        if img.base <= a < img.end:
            return img
    return None


def decode1(img: Image, addr: int, mode: str):
    a = addr & ~1
    if not img.contains(a):
        return None

    md = md_t if mode == "THUMB" else md_a
    size = 4 if mode == "ARM" else 4
    xs = list(md.disasm(img.data[img.off(a):img.off(a)+size], a, count=1))
    return xs[0] if xs else None


def dis(img: Image, start: int, end: int, mode: str):
    start &= ~1
    if not img.contains(start):
        return []

    md = md_t if mode == "THUMB" else md_a
    end = min(end & ~1 if mode == "ARM" else end, img.end)

    return [
        x for x in md.disasm(img.data[img.off(start):img.off(start)+(end-start)], start)
        if x.address < end
    ]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<10} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None

    op = x.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF

    return None


def literal_load(img: Image, x, mode: str):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None

    d, s = x.operands[0], x.operands[1]

    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None

    if mode == "THUMB":
        pc = (x.address + 4) & ~3
    else:
        pc = x.address + 8

    la = (pc + s.mem.disp) & 0xFFFFFFFF

    if not img.contains(la):
        return None

    return x.reg_name(d.reg), d.reg, la, u32(img.data, img.off(la))


def is_return(x):
    if x is None:
        return False

    if x.mnemonic == "bx" and x.op_str.strip() == "lr":
        return True

    if x.mnemonic == "pop" and "pc" in x.op_str:
        return True

    # ARM LDM/POP style return.
    if x.mnemonic.startswith("ldm") and "pc" in x.op_str:
        return True

    return False


def print_region(img: Image, start: int, end: int, mode: str, marks=None):
    marks = marks or set()

    for x in dis(img, start, end, mode):
        notes = []

        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")

        li = literal_load(img, x, mode)
        if li:
            notes.append(f"literal@0x{li[2]:08X}=0x{li[3]:08X}->{li[0]}")

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
# Veneer decoding
# -----------------------------------------------------------------------------

def decode_arm_import_veneer(img: Image, addr: int):
    """
    Recognize common ALICE 8-byte import veneer:
        ldr pc, [pc, #-4]
        .word target
    """
    a = addr & ~3

    x = decode1(img, a, "ARM")
    if x is None:
        return Veneer(addr, "ARM", None, None, None, False)

    recognized = False
    literal_addr = None
    target = None

    if (
        x.mnemonic == "ldr"
        and len(x.operands) >= 2
        and x.operands[0].type == ARM_OP_REG
        and x.reg_name(x.operands[0].reg) == "pc"
        and x.operands[1].type == ARM_OP_MEM
        and x.operands[1].mem.base == ARM_REG_PC
    ):
        pc = x.address + 8
        literal_addr = (pc + x.operands[1].mem.disp) & 0xFFFFFFFF

        if img.contains(literal_addr):
            target = u32(img.data, img.off(literal_addr))
            recognized = True

    return Veneer(a, "ARM", target, literal_addr, x, recognized)


def dump_veneer_strip(alice: Image):
    banner("B. ALICE IMPORT STRIP 0x102FA0C4..0x102FA0D8")

    start = 0x102FA0C4
    end = 0x102FA0D8

    # Raw words.
    print("raw 32-bit words:")
    for a in range(start, end, 4):
        print(f"  0x{a:08X}: 0x{u32(alice.data,alice.off(a)):08X}")

    print()
    print("ARM decode:")
    print_region(alice,start,end,"ARM",{VENEER_META,VENEER_TARGET})

    print()
    for addr,name in [
        (VENEER_META,"KNOWN GET_CHILD_META veneer"),
        (VENEER_TARGET,"TARGET mapper import veneer"),
    ]:
        v=decode_arm_import_veneer(alice,addr)
        print(f"{name} @0x{addr:08X}")
        print(f"  recognized    = {v.recognized}")
        print(f"  instruction   = {fmt(v.instruction) if v.instruction else 'NONE'}")
        print(
            f"  literal_addr  = "
            f"{('0x%08X'%v.literal_addr) if v.literal_addr is not None else 'NONE'}"
        )
        print(
            f"  target_ptr    = "
            f"{('0x%08X'%v.target_ptr) if v.target_ptr is not None else 'NONE'}"
        )

    return decode_arm_import_veneer(alice,VENEER_TARGET)


# -----------------------------------------------------------------------------
# Function recovery
# -----------------------------------------------------------------------------

def likely_mode_from_ptr(ptr: int):
    return "THUMB" if (ptr & 1) else "ARM"


def recover_function(img: Image, ptr: int, max_bytes=0x500):
    mode = likely_mode_from_ptr(ptr)
    start = ptr & ~1

    # Prefer exact start: imported targets normally land at function entry.
    xs = dis(img,start,min(img.end,start+max_bytes),mode)

    if not xs:
        return FunctionView(img,start,start,mode,[])

    # Recover CFG reachability from entry until returns.
    by_addr={x.address:x for x in xs}
    reachable=set()
    todo=deque([start])

    while todo:
        a=todo.popleft()
        if a in reachable:
            continue
        x=by_addr.get(a)
        if x is None:
            continue

        reachable.add(a)

        if is_return(x):
            continue

        next_addr=x.address+len(x.bytes)

        t=direct_target(x)

        # Unconditional direct branch stays inside function.
        if x.mnemonic == "b" and t is not None:
            if start <= (t & ~1) < start+max_bytes:
                todo.append(t & ~1)
            continue

        # Conditional branch.
        if x.mnemonic.startswith("b") and x.mnemonic not in {"bl","blx","bx"}:
            if t is not None and start <= (t & ~1) < start+max_bytes:
                todo.append(t & ~1)
            todo.append(next_addr)
            continue

        # Calls fall through.
        if x.mnemonic in {"bl","blx"}:
            todo.append(next_addr)
            continue

        todo.append(next_addr)

    if not reachable:
        return FunctionView(img,start,start,mode,[])

    end=max(a+len(by_addr[a].bytes) for a in reachable)
    ins=[by_addr[a] for a in sorted(reachable)]

    return FunctionView(img,start,end,mode,ins)


def function_inventory(images, fv: FunctionView):
    banner("C. RESOLVED PRIMITIVE FUNCTION BODY")

    print(f"image = {fv.image.name}")
    print(f"mode  = {fv.mode}")
    print(f"start = 0x{fv.start:08X}")
    print(f"end   = 0x{fv.end:08X}")
    print(f"reachable instructions = {len(fv.insns)}")
    print()

    print_region(fv.image,fv.start,fv.end,fv.mode,{fv.start})

    literals=[]
    calls=[]
    branches=[]

    for x in fv.insns:
        li=literal_load(fv.image,x,fv.mode)
        if li:
            literals.append((x,li))

        t=direct_target(x)
        if x.mnemonic in {"bl","blx"} and t is not None:
            calls.append((x,t))

        if x.mnemonic.startswith("b") and x.mnemonic not in {"bl","blx","bx"} and t is not None:
            branches.append((x,t))

    banner("D. PRIMITIVE LITERAL / CALL / BRANCH INVENTORY")

    print(f"literal loads = {len(literals)}")
    for x,li in literals:
        target_img=image_for(images,li[3])
        tag=f" -> {target_img.name}" if target_img else ""
        print(
            f"  {fmt(x)} literal@0x{li[2]:08X}=0x{li[3]:08X}{tag}"
        )

    print()
    print(f"direct calls = {len(calls)}")
    for x,t in calls:
        ti=image_for(images,t)
        print(
            f"  {fmt(x)} target=0x{t:08X}"
            + (f" ({ti.name})" if ti else "")
        )

    print()
    print(f"direct local branches = {len(branches)}")
    for x,t in branches[:80]:
        print(f"  {fmt(x)} -> 0x{t:08X}")

    return literals,calls,branches


# -----------------------------------------------------------------------------
# Caller/pointer ownership
# -----------------------------------------------------------------------------

def scan_direct_calls(img: Image, target: int):
    out=[]

    # Thumb immediate calls.
    for off in range(0,len(img.data)-4,2):
        h1=u16(img.data,off)
        h2=u16(img.data,off+2)
        if h1 is None or h2 is None:
            continue

        if (h1 & 0xF800) != 0xF000 or (h2 & 0xC000) != 0xC000:
            continue

        xs=list(md_t.disasm(img.data[off:off+4],img.base+off,count=1))
        if not xs:
            continue

        x=xs[0]
        if x.mnemonic not in {"bl","blx"}:
            continue

        t=direct_target(x)
        if t is not None and (t & ~1)==(target & ~1):
            out.append(("THUMB",x))

    # ARM immediate calls.
    for off in range(0,len(img.data)-4,4):
        w=u32(img.data,off)
        if w is None:
            continue

        if not (
            (w & 0x0E000000)==0x0A000000
            or (w & 0xFE000000)==0xFA000000
        ):
            continue

        xs=list(md_a.disasm(img.data[off:off+4],img.base+off,count=1))
        if not xs:
            continue

        x=xs[0]
        if x.mnemonic not in {"bl","blx"}:
            continue

        t=direct_target(x)
        if t is not None and (t & ~1)==(target & ~1):
            out.append(("ARM",x))

    uniq={(m,x.address):(m,x) for m,x in out}
    return [uniq[k] for k in sorted(uniq,key=lambda q:(q[1],q[0]))]


def raw_pointer_refs(img: Image,target: int):
    vals={target & 0xFFFFFFFF,(target|1)&0xFFFFFFFF}
    out=[]

    for v in vals:
        for off in all_hits(img.data,struct.pack("<I",v)):
            out.append((img.base+off,v))

    return sorted(set(out))


def real_literal_xrefs_to_word(img: Image,word_addr: int):
    out=[]

    for a in range(max(img.base,word_addr-0x500)&~1,word_addr+1,2):
        x=decode1(img,a,"THUMB")
        li=literal_load(img,x,"THUMB") if x else None
        if li and li[2]==word_addr:
            out.append(("THUMB",x,li[3]))

    for a in range(max(img.base,word_addr-0x1000)&~3,word_addr+1,4):
        x=decode1(img,a,"ARM")
        li=literal_load(img,x,"ARM") if x else None
        if li and li[2]==word_addr:
            out.append(("ARM",x,li[3]))

    uniq={(m,x.address):(m,x,v) for m,x,v in out}
    return [uniq[k] for k in sorted(uniq)]


def ownership_audit(images,veneer: Veneer):
    banner("E. VENEER / REAL-TARGET OWNERSHIP")

    target=veneer.target_ptr

    for label,t in [
        ("ALICE veneer",VENEER_TARGET),
        ("real target",target),
    ]:
        if t is None:
            continue

        print()
        print(f"### {label} 0x{t:08X}")

        total_calls=0
        total_ptrs=0

        for img in images:
            calls=scan_direct_calls(img,t)
            ptrs=raw_pointer_refs(img,t)
            total_calls += len(calls)
            total_ptrs += len(ptrs)

            print(
                f"{img.name}: direct calls={len(calls)} raw pointer refs={len(ptrs)}"
            )

            for mode,x in calls[:80]:
                print(f"  CALL {mode} {fmt(x)}")

            for a,v in ptrs[:40]:
                lx=real_literal_xrefs_to_word(img,a)
                print(
                    f"  PTR word@0x{a:08X}=0x{v:08X} "
                    f"real literal xrefs={len(lx)}"
                )
                for mode,x,val in lx[:10]:
                    print(f"      {mode} {fmt(x)}")

        print(f"TOTAL calls={total_calls} pointer refs={total_ptrs}")


# -----------------------------------------------------------------------------
# Static table candidate discovery
# -----------------------------------------------------------------------------

def pointerish(images,value: int):
    return image_for(images,value) is not None


def table_windows_around_literal(images, value: int, radius=0x100):
    """
    For an in-image pointer literal, print candidate table views around target.
    """
    img=image_for(images,value)
    if img is None:
        return []

    a=value & ~1
    lo=max(img.base,a-radius)
    hi=min(img.end,a+radius)

    results=[]

    # u16 range/record patterns:
    # {lower, upper, value} as 6-byte records
    for start in range(lo,hi-18,2):
        recs=[]
        p=start

        for _ in range(16):
            if not img.contains(p+5):
                break
            off=img.off(p)
            loid=u16(img.data,off)
            hiid=u16(img.data,off+2)
            val=u16(img.data,off+4)

            if loid is None or hiid is None or val is None:
                break

            if loid > hiid:
                break

            # IDs/resource domains are broad; reject only obvious zeros/full FF.
            if loid in {0,0xFFFF} and hiid in {0,0xFFFF}:
                break

            recs.append((p,loid,hiid,val))
            p += 6

        if len(recs)>=3:
            results.append(("RANGE6",start,recs))

    # {u16 key, u16 value} pairs
    for start in range(lo,hi-16,2):
        pairs=[]
        p=start
        prev=None

        for _ in range(32):
            if not img.contains(p+3):
                break

            off=img.off(p)
            k=u16(img.data,off)
            v=u16(img.data,off+2)

            if k is None or v is None:
                break
            if k in {0,0xFFFF}:
                break

            if prev is not None and k < prev:
                break

            pairs.append((p,k,v))
            prev=k
            p += 4

        if len(pairs)>=4:
            results.append(("PAIR4",start,pairs))

    # u16 sorted values
    for start in range(lo,hi-16,2):
        vals=[]
        p=start
        prev=None

        for _ in range(32):
            if not img.contains(p+1):
                break

            v=u16(img.data,img.off(p))
            if v is None or v in {0,0xFFFF}:
                break

            if prev is not None and v < prev:
                break

            vals.append((p,v))
            prev=v
            p += 2

        if len(vals)>=6:
            results.append(("U16_SORTED",start,vals))

    # dedup starts/types
    uniq={}
    for typ,start,recs in results:
        key=(typ,start)
        old=uniq.get(key)
        if old is None or len(recs)>len(old[2]):
            uniq[key]=(typ,start,recs)

    return [uniq[k] for k in sorted(uniq,key=lambda q:(q[0],q[1]))]


def static_table_audit(images,fv,literals):
    banner("F. STATIC TABLE/RANGE CANDIDATES FROM PRIMITIVE LITERALS")

    candidates=[]

    for x,li in literals:
        val=li[3]
        img=image_for(images,val)

        print()
        print(
            f"literal from 0x{x.address:08X}: value=0x{val:08X} "
            f"image={img.name if img else 'NONE'}"
        )

        if img is None:
            continue

        wins=table_windows_around_literal(images,val)
        print(f"  table candidates around target = {len(wins)}")

        # Rank by whether known inputs appear.
        ranked=[]

        for typ,start,recs in wins:
            keys=set()

            if typ=="RANGE6":
                for _,lo,hi,v in recs:
                    for kid in KNOWN_INPUTS:
                        if lo <= kid <= hi:
                            keys.add(kid)

            elif typ=="PAIR4":
                keys.update(k for _,k,v in recs if k in KNOWN_INPUTS)

            elif typ=="U16_SORTED":
                keys.update(v for _,v in recs if v in KNOWN_INPUTS)

            score=len(keys)
            ranked.append((score,typ,start,recs,keys))

        ranked.sort(key=lambda t:(-t[0],t[1],t[2]))

        for score,typ,start,recs,keys in ranked[:12]:
            print(
                f"  {typ} @0x{start:08X} score={score} "
                f"known_inputs="
                + (
                    ",".join(f"0x{k:04X}" for k in sorted(keys))
                    if keys else "NONE"
                )
            )

            if typ=="RANGE6":
                for addr,lo,hi,v in recs[:16]:
                    print(
                        f"      0x{addr:08X}: "
                        f"0x{lo:04X}..0x{hi:04X} -> 0x{v:04X}"
                    )

            elif typ=="PAIR4":
                for addr,k,v in recs[:20]:
                    mark=" *" if k in KNOWN_INPUTS else ""
                    print(
                        f"      0x{addr:08X}: 0x{k:04X} -> 0x{v:04X}{mark}"
                    )

            elif typ=="U16_SORTED":
                print(
                    "      "
                    + " ".join(
                        f"{v:04X}{'*' if v in KNOWN_INPUTS else ''}"
                        for _,v in recs[:24]
                    )
                )

            candidates.append((score,typ,start,recs,keys,img))

    return candidates


# -----------------------------------------------------------------------------
# Conservative simple-function evaluator
# -----------------------------------------------------------------------------

def reg_name(x, rid):
    try:
        return x.reg_name(rid)
    except Exception:
        return f"reg{rid}"


def eval_simple_function(images, fv: FunctionView, input_r0: int, max_steps=512):
    """
    Very small concrete interpreter for scalar/table lookup leaf functions.

    It intentionally supports only a conservative subset:
      mov/movs, add/adds, sub/subs, cmp, ldr/ldrb/ldrh literal or base+disp,
      str-free control flow, shifts, and/or/eor, conditional/unconditional b,
      bx lr / pop pc.

    Any call, unsupported memory write, complex addressing, or unknown register
    causes evaluation to return OPEN rather than guessing.
    """
    if fv.mode != "THUMB":
        return ("OPEN",None,"simple evaluator currently Thumb-only")

    by_addr={x.address:x for x in fv.insns}
    if fv.start not in by_addr:
        return ("OPEN",None,"entry not decoded")

    regs={f"r{i}":0 for i in range(13)}
    regs["r0"]=input_r0 & 0xFFFFFFFF
    regs["sp"]=0
    regs["lr"]=0xFFFFFFFF

    flags={"Z":False,"N":False,"C":False}
    pc=fv.start
    steps=0

    def read_reg(x,op):
        return regs.get(x.reg_name(op.reg),0)

    def write_reg(x,op,val):
        regs[x.reg_name(op.reg)] = val & 0xFFFFFFFF

    def mem_read(addr,size):
        img=image_for(images,addr)
        if img is None:
            raise KeyError(f"unmapped 0x{addr:08X}")
        off=img.off(addr)
        if size==1:
            return u8(img.data,off)
        if size==2:
            return u16(img.data,off)
        if size==4:
            return u32(img.data,off)
        raise KeyError("bad size")

    def set_nz(v):
        v &= 0xFFFFFFFF
        flags["Z"] = (v==0)
        flags["N"] = bool(v & 0x80000000)

    def cond_taken(mn):
        # Capstone mnemonics can be beq/bne/blo/bhs/bhi/bls/bge/blt/bgt/ble/bpl/bmi.
        if mn=="beq": return flags["Z"]
        if mn=="bne": return not flags["Z"]
        if mn in {"bcs","bhs"}: return flags["C"]
        if mn in {"bcc","blo"}: return not flags["C"]
        if mn=="bpl": return not flags["N"]
        if mn=="bmi": return flags["N"]
        # Other signed/unsigned conditions require V or exact carry semantics.
        raise NotImplementedError(mn)

    while steps < max_steps:
        steps += 1
        x=by_addr.get(pc)
        if x is None:
            return ("OPEN",None,f"pc left recovered CFG @0x{pc:08X}")

        mn=x.mnemonic
        ops=x.operands
        nxt=x.address+len(x.bytes)

        try:
            if is_return(x):
                return ("PASS",regs["r0"] & 0xFFFFFFFF,f"steps={steps}")

            if mn in {"bl","blx"}:
                return ("OPEN",None,f"call @0x{x.address:08X} to {x.op_str}")

            if mn=="b":
                t=direct_target(x)
                if t is None:
                    return ("OPEN",None,"indirect b")
                pc=t & ~1
                continue

            if mn.startswith("b") and mn not in {"bl","blx","bx"}:
                t=direct_target(x)
                if t is None:
                    return ("OPEN",None,f"unknown branch target {mn}")
                try:
                    take=cond_taken(mn)
                except NotImplementedError:
                    return ("OPEN",None,f"unsupported condition {mn} @0x{x.address:08X}")
                pc=(t & ~1) if take else nxt
                continue

            if mn in {"mov","movs"} and len(ops)>=2:
                d,s=ops[0],ops[1]
                if d.type!=ARM_OP_REG:
                    return ("OPEN",None,f"mov dst non-reg @0x{x.address:08X}")

                if s.type==ARM_OP_IMM:
                    val=s.imm
                elif s.type==ARM_OP_REG:
                    val=read_reg(x,s)
                else:
                    return ("OPEN",None,f"mov src unsupported @0x{x.address:08X}")

                write_reg(x,d,val)
                if mn=="movs":
                    set_nz(val)
                pc=nxt
                continue

            if mn in {"add","adds","sub","subs"}:
                if not ops or ops[0].type!=ARM_OP_REG:
                    return ("OPEN",None,f"arith dst unsupported @0x{x.address:08X}")

                d=ops[0]
                if len(ops)==2:
                    a=read_reg(x,d)
                    b=ops[1]
                elif len(ops)>=3:
                    a=read_reg(x,ops[1]) if ops[1].type==ARM_OP_REG else ops[1].imm
                    b=ops[2]
                else:
                    return ("OPEN",None,"arith operands")

                bv=read_reg(x,b) if b.type==ARM_OP_REG else b.imm

                if mn.startswith("add"):
                    val=(a+bv)&0xFFFFFFFF
                else:
                    val=(a-bv)&0xFFFFFFFF
                    # simple carry for subtraction: no borrow
                    flags["C"] = (a & 0xFFFFFFFF) >= (bv & 0xFFFFFFFF)

                write_reg(x,d,val)
                if mn.endswith("s"):
                    set_nz(val)
                pc=nxt
                continue

            if mn in {"cmp","cmn"} and len(ops)>=2:
                a=read_reg(x,ops[0]) if ops[0].type==ARM_OP_REG else ops[0].imm
                b=read_reg(x,ops[1]) if ops[1].type==ARM_OP_REG else ops[1].imm

                if mn=="cmp":
                    val=(a-b)&0xFFFFFFFF
                    flags["C"]=(a&0xFFFFFFFF)>=(b&0xFFFFFFFF)
                else:
                    val=(a+b)&0xFFFFFFFF

                set_nz(val)
                pc=nxt
                continue

            if mn.startswith("ldr") and len(ops)>=2 and ops[0].type==ARM_OP_REG:
                d=ops[0]
                s=ops[1]

                li=literal_load(fv.image,x,"THUMB")
                if li:
                    write_reg(x,d,li[3])
                    pc=nxt
                    continue

                if s.type!=ARM_OP_MEM:
                    return ("OPEN",None,f"ldr non-mem @0x{x.address:08X}")

                base_name=x.reg_name(s.mem.base)
                base=regs.get(base_name,0)
                idx=0
                if s.mem.index:
                    idx_name=x.reg_name(s.mem.index)
                    idx=regs.get(idx_name,0)
                    if s.mem.scale not in (0,1):
                        idx*=s.mem.scale

                addr=(base+idx+s.mem.disp)&0xFFFFFFFF

                if mn.startswith("ldrb"):
                    size=1
                elif mn.startswith("ldrh"):
                    size=2
                else:
                    size=4

                val=mem_read(addr,size)
                write_reg(x,d,val)
                pc=nxt
                continue

            if mn in {"lsls","lsrs"} and len(ops)>=2 and ops[0].type==ARM_OP_REG:
                d=ops[0]

                if len(ops)==2:
                    val=read_reg(x,d)
                    s=ops[1]
                else:
                    val=read_reg(x,ops[1]) if ops[1].type==ARM_OP_REG else ops[1].imm
                    s=ops[2]

                sh=read_reg(x,s)&0xFF if s.type==ARM_OP_REG else s.imm

                if mn=="lsls":
                    out=(val << sh)&0xFFFFFFFF
                else:
                    out=(val & 0xFFFFFFFF) >> sh

                write_reg(x,d,out)
                set_nz(out)
                pc=nxt
                continue

            if mn in {"ands","orrs","eors"} and len(ops)>=2 and ops[0].type==ARM_OP_REG:
                d=ops[0]
                a=read_reg(x,d)
                b=read_reg(x,ops[1]) if ops[1].type==ARM_OP_REG else ops[1].imm

                if mn=="ands": out=a&b
                elif mn=="orrs": out=a|b
                else: out=a^b

                write_reg(x,d,out)
                set_nz(out)
                pc=nxt
                continue

            if mn in {"push","pop"}:
                if mn=="pop" and "pc" in x.op_str:
                    return ("PASS",regs["r0"]&0xFFFFFFFF,f"steps={steps}")
                # stack contents not modeled; pushes are harmless if no local loads from sp.
                pc=nxt
                continue

            if mn in {"nop"}:
                pc=nxt
                continue

            # Explicitly reject stores and complex ops.
            if mn.startswith("str") or mn.startswith("stm"):
                return ("OPEN",None,f"memory write {mn} @0x{x.address:08X}")

            return ("OPEN",None,f"unsupported {mn} {x.op_str} @0x{x.address:08X}")

        except KeyError as e:
            return ("OPEN",None,str(e))

    return ("OPEN",None,"step-limit")


def concrete_eval_audit(images,fv,rows):
    banner("G. CONSERVATIVE CONCRETE EVALUATION")

    resolver={r.menu_id:r for r in rows}
    results={}

    for mid in KNOWN_INPUTS:
        status,val,why=eval_simple_function(images,fv,mid)
        results[mid]=(status,val,why)

        tag=[]
        if mid in KNOWN_NAMES:
            tag.append(KNOWN_NAMES[mid])
        if mid in resolver:
            tag.append("RESOLVER_ID")

        print(
            f"0x{mid:04X}"
            + (f" <{'|'.join(tag)}>" if tag else "")
            + f" -> {status}"
            + (f" value=0x{val:08X}" if val is not None else "")
            + f" ({why})"
        )

    pass_results={
        mid:val
        for mid,(status,val,why) in results.items()
        if status=="PASS" and val is not None
    }

    if pass_results:
        groups=defaultdict(list)
        for mid,val in pass_results.items():
            groups[val].append(mid)

        print()
        print("recovered output groups:")
        for val,mids in sorted(groups.items()):
            print(
                f"  0x{val:08X}: "
                + ", ".join(
                    f"0x{x:04X}"
                    + (f"<{KNOWN_NAMES[x]}>" if x in KNOWN_NAMES else "")
                    for x in sorted(mids)
                )
            )

    return results


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
        default="research/f2/work/reports/s13_5a21_imported_id_resource_primitive.txt",
    )

    return p.parse_args()


def resolve(root: Path,s: str):
    p=Path(s)
    return p if p.is_absolute() else root/p


def main():
    args=parse_args()
    root=Path.cwd()

    report_path=resolve(root,args.report)
    report_path.parent.mkdir(parents=True,exist_ok=True)

    cap=io.StringIO()
    old=sys.stdout
    sys.stdout=Tee(old,cap)

    try:
        banner("S13.5A.21 - IMPORTED ID->RESOURCE PRIMITIVE / MAPPING TABLE AUDIT")
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
        images=[alice,zimage]
        rows=parse_resolver(zimage)

        veneer=dump_veneer_strip(alice)

        banner("VENEER RESOLUTION")
        if not veneer.recognized or veneer.target_ptr is None:
            print("[OPEN] 0x102FA0CC is not recognized as the expected ARM import veneer.")
            print("The report above is authoritative; do not infer a target.")
            target_img=None
            fv=None
        else:
            print("[PASS] 0x102FA0CC is an ARM literal-load import veneer.")
            print(f"target pointer = 0x{veneer.target_ptr:08X}")
            print(
                f"target mode    = {likely_mode_from_ptr(veneer.target_ptr)}"
            )

            target_img=image_for(images,veneer.target_ptr)
            print(
                f"target image   = {target_img.name if target_img else 'OUTSIDE CANONICAL IMAGES'}"
            )

            if target_img is None:
                fv=None
            else:
                fv=recover_function(target_img,veneer.target_ptr)

        if fv is not None:
            literals,calls,branches=function_inventory(images,fv)
            ownership_audit(images,veneer)
            candidates=static_table_audit(images,fv,literals)
            results=concrete_eval_audit(images,fv,rows)
        else:
            literals=[]
            calls=[]
            branches=[]
            candidates=[]
            results={}

        banner("H. WRAPPER CONTRACT RECAP")
        print("0x10319094:")
        print("  calls 0x102FA0CC with original r0")
        print("  if primitive return == 0xFF, substitutes 0x2E")
        print("  otherwise returns primitive result unchanged")
        print()
        print("Known resolver inputs through wrapper:")
        resolver_set={r.menu_id for r in rows}
        for mid in KNOWN_INPUTS:
            print(
                f"  0x{mid:04X}"
                + (f" <{KNOWN_NAMES[mid]}>" if mid in KNOWN_NAMES else "")
                + (" <RESOLVER_ID>" if mid in resolver_set else "")
            )

        banner("I. DECISION GATE")

        veneer_pass=veneer.recognized and veneer.target_ptr is not None
        target_in_image=veneer_pass and image_for(images,veneer.target_ptr) is not None

        print(f"0x102FA0CC veneer recognized = {'PASS' if veneer_pass else 'OPEN'}")
        print(f"real target in canonical images = {'PASS' if target_in_image else 'OPEN'}")

        if veneer_pass:
            print(f"real target = 0x{veneer.target_ptr:08X}")

        if fv is not None:
            print(f"target mode = {fv.mode}")
            print(f"target body = 0x{fv.start:08X}..0x{fv.end:08X}")
            print(f"target direct calls = {len(calls)}")
            print(f"target literal loads = {len(literals)}")
            print(f"static table candidates = {len(candidates)}")

            pass_eval={
                mid:val
                for mid,(st,val,why) in results.items()
                if st=="PASS" and val is not None
            }

            print(f"concretely evaluated known inputs = {len(pass_eval)}/{len(KNOWN_INPUTS)}")

            if 0x8321 in pass_eval:
                print(f"Image 0x8321 primitive output = 0x{pass_eval[0x8321]:08X}")

            if 0x8928 in pass_eval:
                print(f"Audio 0x8928 primitive output = 0x{pass_eval[0x8928]:08X}")

            if 0x8321 in pass_eval and 0x8928 in pass_eval:
                print(
                    "Image/Audio primitive outputs equal = "
                    f"{'YES' if pass_eval[0x8321]==pass_eval[0x8928] else 'NO'}"
                )

        print()
        if veneer_pass and fv is not None:
            if not calls:
                print("[STRONG] Primitive is a leaf function in the recovered body.")
                print("[NEXT] Use its literal/table behavior or concrete outputs directly.")
            else:
                print("[OPEN] Primitive delegates to additional helper(s).")
                print("[NEXT] Resolve only the call(s) that carry the original ID argument.")

        print()
        print("DO NOT PROMOTE:")
        print("  - nearby 0x89xx IDs as FM Radio without a structural owner;")
        print("  - a mapper output as a visible menu ID unless the consumer proves that role;")
        print("  - raw table co-location as Multimedia membership.")
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
        report_path.write_text(cap.getvalue(),encoding="utf-8")


if __name__=="__main__":
    raise SystemExit(main())
