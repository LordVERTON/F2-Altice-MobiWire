#!/usr/bin/env python3
"""
S13.5A.19 - IMAGE RESOURCE TABLE / KNOWN-ID CONSUMER CONTRACT AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.18 did NOT recover plaintext visible labels, but found three useful
static anchors:

  - ALICE loads IMAGE_B 0x8321 in functions near 0x1034C208 / 0x1034C2C4.
  - ALICE loads AUDIO 0x8928 in function 0x103660C8.
  - ZIMAGE loads AUDIO 0x8928 repeatedly in function 0xF02B5C60.
  - ZIMAGE 0xF03B3870 looks structurally like records beginning with:
        {0x8313, 0x0000, 0xF03B388C}
        {0x8312, 0x0000, 0xF03B38D8}
    and ALICE genuinely loads pointer 0xF03B3870 at 0x10348812.

This pass classifies that structure and the consumer contracts of the known IDs.

Questions:
  1. What function owns/uses pointer F03B3870?
  2. Is F03B38xx a record table, and what do its pointers target?
  3. Which IDs found there are resolver IDs?
  4. How are 0x8321 and 0x8928 used by real code?
  5. Do Image and Audio IDs flow through any shared helper/API?
  6. Is there a stronger path toward an FM ID or Multimedia parent?

No raw co-location alone is promoted as menu membership.
No patch is generated.

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

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

RESOLVER_BASE = 0xF0345E68
RESOLVER_COUNT = 58
RESOLVER_STRIDE = 8

STRUCT_BASE = 0xF03B3870
STRUCT_END = 0xF03B3920

OWNER_XREF = 0x10348812
OWNER_LITERAL = 0x1034881C

IMAGE_B_XREFS = [0x1034C224, 0x1034C32C]
AUDIO_ALICE_XREFS = [0x10366100, 0x10366122, 0x10366136]
AUDIO_ZIMAGE_XREFS = [
    0xF02B5CA2, 0xF02B5CA6, 0xF02B5CAC, 0xF02B5CB6, 0xF02B5CC8,
    0xF02B5CD6, 0xF02B5CDC, 0xF02B5CE2, 0xF02B5CFC, 0xF02B5D14,
    0xF02B5D28,
]

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
class Record8:
    addr: int
    menu_id: int
    field2: int
    ptr: int


def banner(s):
    print()
    print("=" * 136)
    print(s)
    print("=" * 136)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u16(data, off):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
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
    return [x for x in md.disasm(img.data[img.off(start):img.off(end)], start) if x.address < end]


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


def enclosing_function(img: Image, target: int, back=0x500, forward=0x900):
    lo = max(img.base, target-back) & ~1
    candidates = []

    for a in range(lo, target+1, 2):
        x = decode1(img, a, "THUMB")
        if not is_prologue(x):
            continue

        xs = dis(img, a, min(img.end, a+forward), "THUMB")
        if any(z.address == target for z in xs):
            candidates.append(a)

    if not candidates:
        return None, None

    start = candidates[-1]
    xs = dis(img, start, min(img.end, start+forward), "THUMB")

    end = None
    passed_target = False
    for x in xs:
        if x.address >= target:
            passed_target = True
        if passed_target and is_return(x):
            end = x.address + len(x.bytes)
            break

    if end is None:
        end = min(img.end, start+0x180)

    return start, end


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


def resolver_map(rows):
    return {r.menu_id:r for r in rows}


def print_resolver_subset(rows):
    banner("B. RESOLVER CONTEXT AROUND IMAGE / AUDIO RANGES")

    interesting = []
    for r in rows:
        if 0x8300 <= r.menu_id <= 0x8340 or 0x8900 <= r.menu_id <= 0x8940:
            interesting.append(r)

    print(f"interesting resolver rows = {len(interesting)}")
    for r in interesting:
        tag = f" <{KNOWN_IDS[r.menu_id]}>" if r.menu_id in KNOWN_IDS else ""
        print(
            f"  row#{r.index:02d} @0x{r.addr:08X}: "
            f"id=0x{r.menu_id:04X}{tag} field2=0x{r.field2:04X} "
            f"callback=0x{r.callback_ptr:08X}"
        )


def words32_region(img: Image, start: int, end: int):
    print(f"32-bit words {img.name} 0x{start:08X}..0x{end:08X}")
    for addr in range(start, end, 4):
        if not img.contains(addr):
            continue
        w = u32(img.data, img.off(addr))
        print(f"  0x{addr:08X}: 0x{w:08X}")


def u16_region(img: Image, start: int, end: int, rmap):
    print(f"u16 region {img.name} 0x{start:08X}..0x{end:08X}")
    for addr in range(start, end, 2):
        if not img.contains(addr):
            continue
        v = u16(img.data, img.off(addr))
        tags = []
        if v in KNOWN_IDS:
            tags.append(KNOWN_IDS[v])
        if v in rmap:
            tags.append("RESOLVER_ID")
        tag = f" <{'|'.join(tags)}>" if tags else ""
        print(f"  0x{addr:08X}: 0x{v:04X}{tag}")


def detect_record8_runs(img: Image, start: int, end: int):
    """
    Find contiguous 8-byte records:
      u16 id
      u16 field
      u32 ptr inside ALICE/ZIMAGE runtime space

    Start on 2-byte boundaries because embedded tables may not be 4-byte aligned.
    """
    results = []

    for a in range(start, end-8+1, 2):
        if not img.contains(a):
            continue

        recs = []
        p = a

        while p+8 <= end and img.contains(p+7):
            off = img.off(p)
            mid = u16(img.data, off)
            fld = u16(img.data, off+2)
            ptr = u32(img.data, off+4)

            if mid is None or fld is None or ptr is None:
                break

            # ID range deliberately broad enough for application/menu/resource IDs.
            if not (0x1000 <= mid <= 0xBFFF):
                break

            # Pointer must look like canonical ALICE/ZIMAGE or known F0 region.
            if not (
                ALICE_BASE <= (ptr & ~1) < ALICE_BASE+ALICE_SIZE
                or ZIMAGE_BASE <= (ptr & ~1) < ZIMAGE_BASE+ZIMAGE_SIZE
            ):
                break

            recs.append(Record8(p, mid, fld, ptr))
            p += 8

        if recs:
            results.append((a, recs))

    # Keep maximal/non-duplicate runs.
    maximal = []
    for start_addr, recs in results:
        if any(
            other_start < start_addr
            and other_start + 8*len(other_recs) >= start_addr + 8*len(recs)
            for other_start, other_recs in results
        ):
            continue
        maximal.append((start_addr, recs))

    return maximal


def parse_u16_terminated(img: Image, ptr: int, max_items=64):
    a = ptr & ~1
    if not img.contains(a):
        return None

    vals = []
    for i in range(max_items):
        off = img.off(a+i*2)
        v = u16(img.data, off)
        if v is None:
            break
        vals.append(v)
        if v == 0:
            break

    return vals


def reverse_pointer_refs(images, target: int):
    out = []
    pat = struct.pack("<I", target & 0xFFFFFFFF)

    for img in images:
        for off in all_hits(img.data, pat):
            out.append((img, img.base+off))

    return out


def real_literal_xrefs_to_word(img: Image, word_addr: int):
    out = []

    for a in range(max(img.base,word_addr-0x500)&~1, word_addr+1, 2):
        x = decode1(img, a, "THUMB")
        li = literal_load(img, x, "THUMB") if x else None
        if li and li[2] == word_addr:
            out.append(("THUMB",x,li[3]))

    for a in range(max(img.base,word_addr-0x1000)&~3, word_addr+1, 4):
        x = decode1(img, a, "ARM")
        li = literal_load(img, x, "ARM") if x else None
        if li and li[2] == word_addr:
            out.append(("ARM",x,li[3]))

    uniq = {(m,x.address):(m,x,v) for m,x,v in out}
    return [uniq[k] for k in sorted(uniq)]


def owner_function_audit(alice: Image):
    banner("C. OWNER FUNCTION OF POINTER F03B3870")

    start,end = enclosing_function(alice, OWNER_XREF)

    print(f"anchor xref       = 0x{OWNER_XREF:08X}")
    print(f"literal word      = 0x{OWNER_LITERAL:08X}")
    print(f"literal value     = 0x{u32(alice.data,alice.off(OWNER_LITERAL)):08X}")
    print(
        f"enclosing function= "
        f"{('0x%08X..0x%08X'%(start,end)) if start is not None else 'UNKNOWN'}"
    )

    lo = start if start is not None else max(alice.base, OWNER_XREF-0x30)
    hi = end if end is not None else min(alice.end, OWNER_XREF+0x50)

    print_region(alice,lo,hi,"THUMB",{OWNER_XREF})

    # Trace the destination register loaded at OWNER_XREF until overwrite/call/return.
    x = decode1(alice,OWNER_XREF,"THUMB")
    li = literal_load(alice,x,"THUMB") if x else None
    if not li:
        print("[OPEN] OWNER_XREF is not recognized as a literal load")
        return

    reg_id = li[1]
    reg_name = li[0]

    print()
    print(f"loaded pointer register = {reg_name}")

    xs = dis(alice,OWNER_XREF,hi,"THUMB")
    aliases={reg_id}

    for z in xs[1:]:
        uses=[]
        writes_dst = z.operands and z.operands[0].type==ARM_OP_REG

        # Alias propagation.
        if z.mnemonic in {"mov","movs"} and len(z.operands)>=2:
            d,s=z.operands[0],z.operands[1]
            if d.type==ARM_OP_REG and s.type==ARM_OP_REG and s.reg in aliases:
                aliases.add(d.reg)
                uses.append(f"alias->{z.reg_name(d.reg)}")

        for op in z.operands:
            if op.type==ARM_OP_REG and op.reg in aliases:
                uses.append(f"reg-use:{z.reg_name(op.reg)}")
            elif op.type==ARM_OP_MEM:
                if op.mem.base in aliases:
                    uses.append(f"mem-base:{z.reg_name(op.mem.base)}")
                if op.mem.index in aliases:
                    uses.append(f"mem-index:{z.reg_name(op.mem.index)}")

        if uses:
            print(f"  {fmt(z)} ; {', '.join(sorted(set(uses)))}")

        if z.mnemonic in {"bl","blx"}:
            # r0-r3 clobbered; preserve only callee-saved aliases.
            aliases = {
                r for r in aliases
                if z.reg_name(r) not in {"r0","r1","r2","r3","r12","ip","lr"}
            }

        if writes_dst and z.operands[0].reg in aliases:
            # If it was not an alias-preserving mov, consider overwritten.
            if not (
                z.mnemonic in {"mov","movs"}
                and len(z.operands)>=2
                and z.operands[1].type==ARM_OP_REG
                and z.operands[1].reg in aliases
            ):
                aliases.discard(z.operands[0].reg)

        if is_return(z):
            break


def record_table_audit(images, zimage: Image, rows):
    banner("D. F03B38xx STRUCTURED-DATA AUDIT")

    rmap=resolver_map(rows)

    print("Raw u16 view:")
    u16_region(zimage,STRUCT_BASE,STRUCT_END,rmap)

    print()
    runs=detect_record8_runs(zimage,STRUCT_BASE,STRUCT_END)
    print(f"plausible contiguous 8-byte record runs = {len(runs)}")

    for start,recs in runs:
        print()
        print(f"RUN @0x{start:08X}, records={len(recs)}")

        for rec in recs:
            tags=[]
            if rec.menu_id in KNOWN_IDS:
                tags.append(KNOWN_IDS[rec.menu_id])
            if rec.menu_id in rmap:
                tags.append("RESOLVER_ID")
            tag=f" <{'|'.join(tags)}>" if tags else ""

            print(
                f"  0x{rec.addr:08X}: "
                f"id=0x{rec.menu_id:04X}{tag} "
                f"field=0x{rec.field2:04X} "
                f"ptr=0x{rec.ptr:08X}"
            )

            target_img=image_for(images,rec.ptr)
            if target_img is None:
                print("    target: outside canonical images")
                continue

            vals=parse_u16_terminated(target_img,rec.ptr)
            if vals is None:
                print("    target: unreadable")
                continue

            print(
                "    target u16[]: "
                + " ".join(
                    f"{v:04X}"
                    + (
                        f"<{KNOWN_IDS[v]}>"
                        if v in KNOWN_IDS
                        else ("<RES>" if v in rmap else "")
                    )
                    for v in vals
                )
            )

            resolver_members=[v for v in vals if v in rmap]
            if resolver_members:
                print(
                    "    resolver members: "
                    + ", ".join(f"0x{x:04X}" for x in resolver_members)
                )

            refs=reverse_pointer_refs(images,rec.ptr)
            print(f"    reverse raw ptr refs to target = {len(refs)}")
            for ref_img,waddr in refs[:20]:
                lx=real_literal_xrefs_to_word(ref_img,waddr)
                print(
                    f"      {ref_img.name} word@0x{waddr:08X}, "
                    f"real literal xrefs={len(lx)}"
                )
                for mode,x,val in lx[:10]:
                    print(f"        {mode} {fmt(x)}")

    # Always decode the specific A.18 interpretation, even if run detector
    # decides it is too short/overlapping.
    print()
    print("Specific records at A.18 anchor:")
    for addr in (0xF03B3870,0xF03B3878):
        off=zimage.off(addr)
        rec=Record8(
            addr=addr,
            menu_id=u16(zimage.data,off),
            field2=u16(zimage.data,off+2),
            ptr=u32(zimage.data,off+4),
        )
        print(
            f"  {addr:08X}: id=0x{rec.menu_id:04X} "
            f"field=0x{rec.field2:04X} ptr=0x{rec.ptr:08X}"
        )
        timg=image_for(images,rec.ptr)
        if timg:
            vals=parse_u16_terminated(timg,rec.ptr)
            print(
                "    target u16[]: "
                + (" ".join(f"{x:04X}" for x in vals) if vals else "NONE")
            )


def find_literal_xrefs_for_value(img: Image, value: int):
    out=[]
    for off in all_hits(img.data,struct.pack("<I",value&0xFFFFFFFF)):
        word=img.base+off
        for mode,x,val in real_literal_xrefs_to_word(img,word):
            if val==value:
                out.append((mode,x,word))

    uniq={(m,x.address,w):(m,x,w) for m,x,w in out}
    return [uniq[k] for k in sorted(uniq)]


def track_loaded_constant(img: Image, x, value: int, function_end: int):
    li=literal_load(img,x,"THUMB")
    if not li:
        return []

    rid=li[1]
    aliases={rid}
    events=[]

    xs=dis(img,x.address,function_end,"THUMB")

    for z in xs[1:]:
        if is_return(z):
            events.append(("RETURN",z,""))
            break

        # alias propagation
        if z.mnemonic in {"mov","movs"} and len(z.operands)>=2:
            d,s=z.operands[0],z.operands[1]
            if d.type==ARM_OP_REG and s.type==ARM_OP_REG and s.reg in aliases:
                aliases.add(d.reg)
                events.append(("ALIAS",z,f"{z.reg_name(d.reg)} <- known ID"))

        # compare
        if z.mnemonic.startswith("cmp"):
            if any(op.type==ARM_OP_REG and op.reg in aliases for op in z.operands):
                events.append(("COMPARE",z,z.op_str))

        # store
        if z.mnemonic.startswith("str") and z.operands:
            if z.operands[0].type==ARM_OP_REG and z.operands[0].reg in aliases:
                events.append(("STORE",z,z.op_str))

        # memory index/base
        for op in z.operands:
            if op.type==ARM_OP_MEM:
                if op.mem.base in aliases:
                    events.append(("MEM_BASE",z,z.op_str))
                if op.mem.index in aliases:
                    events.append(("MEM_INDEX",z,z.op_str))

        # calls
        if z.mnemonic in {"bl","blx"}:
            target=direct_target(z)

            # Determine whether r0/r1/r2/r3 currently carries known ID.
            arg_regs=[]
            for rn in ("r0","r1","r2","r3"):
                ridn=None
                for a in aliases:
                    if z.reg_name(a)==rn:
                        ridn=a
                        break
                if ridn is not None:
                    arg_regs.append(rn)

            if arg_regs:
                events.append(
                    ("CALL_WITH_ID",z,
                     f"args={','.join(arg_regs)} "
                     f"target={('0x%08X'%target) if target is not None else z.op_str}")
                )
            else:
                events.append(
                    ("CALL_BOUNDARY",z,
                     f"target={('0x%08X'%target) if target is not None else z.op_str}")
                )

            aliases={
                a for a in aliases
                if z.reg_name(a) not in {"r0","r1","r2","r3","r12","ip","lr"}
            }

        # invalidate destination register on generic writes
        if z.operands and z.operands[0].type==ARM_OP_REG:
            dst=z.operands[0].reg
            if dst in aliases:
                preserve=(
                    z.mnemonic in {"mov","movs"}
                    and len(z.operands)>=2
                    and z.operands[1].type==ARM_OP_REG
                    and z.operands[1].reg in aliases
                )
                if not preserve:
                    aliases.discard(dst)

        if not aliases:
            # keep a few events after first call impossible? no: stop to avoid noise
            if any(k=="CALL_WITH_ID" for k,_,_ in events):
                break

    return events


def consumer_contract_audit(images):
    banner("E. KNOWN-ID CONSUMER CONTRACTS")

    call_targets=defaultdict(set)

    anchor_groups=[
        ("IMAGE_B_ALICE",0x8321,IMAGE_B_XREFS),
        ("AUDIO_ALICE",0x8928,AUDIO_ALICE_XREFS),
        ("AUDIO_ZIMAGE",0x8928,AUDIO_ZIMAGE_XREFS),
    ]

    for label,value,anchors in anchor_groups:
        print()
        print("-"*136)
        print(f"{label} value=0x{value:04X}")

        by_func=defaultdict(list)

        for a in anchors:
            img=image_for(images,a)
            if img is None:
                print(f"  anchor 0x{a:08X}: outside images")
                continue

            fs,fe=enclosing_function(img,a)
            by_func[(img.name,fs,fe)].append(a)

        for (img_name,fs,fe),func_anchors in sorted(by_func.items(),key=lambda q:(q[0][0],q[0][1] or 0)):
            img=next(i for i in images if i.name==img_name)

            print()
            print(
                f"FUNCTION {img_name} "
                f"{('0x%08X..0x%08X'%(fs,fe)) if fs is not None else 'UNKNOWN'}"
            )

            lo=fs if fs is not None else max(img.base,min(func_anchors)-0x30)
            hi=fe if fe is not None else min(img.end,max(func_anchors)+0x80)

            print_region(img,lo,hi,"THUMB",set(func_anchors))

            for a in sorted(func_anchors):
                x=decode1(img,a,"THUMB")
                print()
                print(f"  TRACE from 0x{a:08X}: {fmt(x) if x else 'decode fail'}")

                events=track_loaded_constant(img,x,value,hi) if x else []

                if not events:
                    print("    no tracked consumer event")
                    continue

                for kind,z,desc in events:
                    print(f"    {kind:<14} {fmt(z)}" + (f" | {desc}" if desc else ""))

                    if kind=="CALL_WITH_ID":
                        t=direct_target(z)
                        if t is not None:
                            call_targets[label].add(t & ~1)

    banner("F. IMAGE / AUDIO HELPER-INTERSECTION")
    groups=sorted(call_targets)

    for g in groups:
        vals=sorted(call_targets[g])
        print(
            f"{g:<18}: "
            + (", ".join(f"0x{x:08X}" for x in vals) if vals else "NONE")
        )

    image_targets=call_targets.get("IMAGE_B_ALICE",set())
    audio_targets=(
        call_targets.get("AUDIO_ALICE",set())
        | call_targets.get("AUDIO_ZIMAGE",set())
    )

    shared=sorted(image_targets & audio_targets)

    print()
    print(
        "shared direct helper targets carrying known ID = "
        + (", ".join(f"0x{x:08X}" for x in shared) if shared else "NONE")
    )

    return call_targets,shared


def scan_related_ids_from_struct(zimage: Image, rows):
    banner("G. F03B38xx IDS -> RESOLVER / CALLBACK MAP")

    rmap=resolver_map(rows)
    vals=[]

    for addr in range(STRUCT_BASE,STRUCT_END,2):
        if not zimage.contains(addr):
            continue
        v=u16(zimage.data,zimage.off(addr))
        if 0x8000 <= v <= 0x8FFF:
            vals.append((addr,v))

    seen=set()

    for addr,v in vals:
        if v in seen:
            continue
        seen.add(v)

        r=rmap.get(v)
        if r:
            print(
                f"id=0x{v:04X} first@0x{addr:08X}: "
                f"resolver row@0x{r.addr:08X} callback=0x{r.callback_ptr:08X}"
            )
        else:
            print(f"id=0x{v:04X} first@0x{addr:08X}: no resolver row")


def parse_args():
    p=argparse.ArgumentParser()
    p.add_argument("--alice",default="research/f2/work/extracted/altice_alice/alice-py.bin")
    p.add_argument("--zimage",default="research/f2/work/extracted/altice_platform/zimage.bin")
    p.add_argument("--report",default="research/f2/work/reports/s13_5a19_image_resource_table_known_id_consumers.txt")
    return p.parse_args()


def resolve(root: Path,s: str):
    p=Path(s)
    return p if p.is_absolute() else root/p


def main():
    args=parse_args()
    root=Path.cwd()

    report_path=resolve(root,args.report)
    report_path.parent.mkdir(parents=True,exist_ok=True)

    capture=io.StringIO()
    old=sys.stdout
    sys.stdout=Tee(old,capture)

    try:
        banner("S13.5A.19 - IMAGE RESOURCE TABLE / KNOWN-ID CONSUMER CONTRACT AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice=verify(
            resolve(root,args.alice),"ALICE",ALICE_BASE,ALICE_SIZE,ALICE_SHA256
        )
        zimage=verify(
            resolve(root,args.zimage),"ZIMAGE",ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA256
        )
        images=[alice,zimage]

        rows=parse_resolver(zimage)

        print_resolver_subset(rows)
        owner_function_audit(alice)
        record_table_audit(images,zimage,rows)
        call_targets,shared=consumer_contract_audit(images)
        scan_related_ids_from_struct(zimage,rows)

        banner("H. DECISION GATE")

        # Specific structure facts from raw words.
        off=zimage.off(STRUCT_BASE)
        rec1=Record8(
            STRUCT_BASE,
            u16(zimage.data,off),
            u16(zimage.data,off+2),
            u32(zimage.data,off+4),
        )
        rec2=Record8(
            STRUCT_BASE+8,
            u16(zimage.data,off+8),
            u16(zimage.data,off+10),
            u32(zimage.data,off+12),
        )

        owner_literal_ok = (
            u32(alice.data,alice.off(OWNER_LITERAL)) == STRUCT_BASE
        )

        print(f"F03B3870 first record id           = 0x{rec1.menu_id:04X}")
        print(f"F03B3870 first record field        = 0x{rec1.field2:04X}")
        print(f"F03B3870 first record ptr          = 0x{rec1.ptr:08X}")
        print(f"F03B3878 second record id          = 0x{rec2.menu_id:04X}")
        print(f"F03B3878 second record field       = 0x{rec2.field2:04X}")
        print(f"F03B3878 second record ptr         = 0x{rec2.ptr:08X}")
        print(f"ALICE literal 1034881C==F03B3870  = {'PASS' if owner_literal_ok else 'FAIL'}")
        print(
            "Image/Audio shared helper targets      = "
            + (", ".join(f"0x{x:08X}" for x in shared) if shared else "NONE")
        )
        print()

        if owner_literal_ok:
            print("[PASS] F03B3870 has a genuine ALICE code owner/reference.")
        else:
            print("[OPEN] F03B3870 owner literal invariant failed.")

        if rec1.menu_id==0x8313 and rec1.field2==0 and image_for(images,rec1.ptr):
            print(
                "[PASS] First 8-byte record is structurally consistent with "
                "{id=0x8313, field=0, in-image pointer}."
            )
            print(
                "Semantic name remains UNKNOWN until owner-function behavior "
                "or parallel records prove the table contract."
            )

        if shared:
            print()
            print(
                "[STRONG LEAD] Image and Audio constants are passed through at least one "
                "shared direct helper/API."
            )
            print(
                "[NEXT] Resolve only those shared helper target(s), then recover sibling "
                "IDs handled by the same API."
            )
        else:
            print()
            print(
                "[NEXT] Use the strongest consumer contract above: classify the owner of "
                "0x8321 and the F03B3870 record table before looking for FM."
            )

        print()
        print("DO NOT PROMOTE:")
        print("  F03B38xx as Multimedia children[] solely from raw u16 layout")
        print("  nearby 0x83xx values as siblings solely by co-location")
        print("  0x8928 membership solely from shared resource helpers")
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
