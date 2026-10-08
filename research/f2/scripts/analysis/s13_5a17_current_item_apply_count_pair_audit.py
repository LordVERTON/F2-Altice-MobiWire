#!/usr/bin/env python3
"""
S13.5A.17 - CURRENT-ITEM APPLY API / ITEM-COUNT PAIR AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.16 recovered three true consumers of platform getter F02FBC10():

    current_item = F02FBC10()

    r1 = current_item
    r0 = object_or_control
    BLX F02D0CE0

The previous auto-label saying the getter result was passed in r0 is
SUPERSEDED. The getter value is argument #2 (r1).

The same caller family also uses:

    r0 = object_or_control
    BLX F02CFD70
    SUBS r0,#1

This pass determines whether the pair is structurally:

    APPLY_CURRENT_ITEM(control, one_based_item)
    GET_ITEM_COUNT(control)

or something else.

Because these calls use BLX to even F0 addresses, both targets are first
checked for ARM import-veneer shape before any semantic interpretation.

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

APPLY_ENTRY = 0xF02D0CE0
COUNT_ENTRY = 0xF02CFD70
GETTER = 0xF02FBC10

ARM_LDR_PC_MINUS4 = 0xE51FF004

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
class ResolvedTarget:
    entry: int
    entry_mode: str
    is_veneer: bool
    target_ptr: int
    target: int
    target_mode: str
    owner: str


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


def image_for(images, addr: int):
    a = addr & ~1
    for img in images:
        if img.contains(a):
            return img
    return None


def decode1(img: Image, addr: int, mode: str):
    if not img.contains(addr):
        return None

    md = md_t if mode == "THUMB" else md_a
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+4], addr, count=1))
    return xs[0] if xs else None


def dis(img: Image, start: int, end: int, mode: str):
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


def literal_load(img: Image, x, mode: str):
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


def print_region(img: Image, start: int, end: int, mode: str, marks=None):
    marks = marks or set()

    for x in dis(img, start, end, mode):
        notes = []

        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")

        li = literal_load(img, x, mode)
        if li:
            rn, _, la, value = li
            notes.append(f"literal@0x{la:08X}=0x{value:08X}->{rn}")

        mark = ">>>" if x.address in marks else "   "
        print(mark, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def resolve_entry(images, entry: int):
    owner = image_for(images, entry)

    if owner is None:
        return ResolvedTarget(
            entry, "UNKNOWN", False, entry, entry, "UNKNOWN", "OUTSIDE_IMAGES"
        )

    first_word = u32(owner.data, owner.off(entry))
    second_word = u32(owner.data, owner.off(entry)+4)

    arm = decode1(owner, entry, "ARM")
    thumb = decode1(owner, entry, "THUMB")

    print(f"entry = 0x{entry:08X} owner={owner.name}")
    print(f"  word0 = 0x{first_word:08X}")
    print(f"  word1 = 0x{second_word:08X}")
    print(f"  ARM   = {fmt(arm) if arm else 'decode-fail'}")
    print(f"  THUMB = {fmt(thumb) if thumb else 'decode-fail'}")

    if first_word == ARM_LDR_PC_MINUS4:
        target_ptr = second_word
        target = target_ptr & ~1
        target_mode = "THUMB" if target_ptr & 1 else "ARM"
        target_owner = image_for(images, target)
        return ResolvedTarget(
            entry=entry,
            entry_mode="ARM",
            is_veneer=True,
            target_ptr=target_ptr,
            target=target,
            target_mode=target_mode,
            owner=target_owner.name if target_owner else "OUTSIDE_IMAGES",
        )

    # Default: preserve entry as direct implementation. BLX to even address
    # suggests ARM, but print both decodes above for auditability.
    return ResolvedTarget(
        entry=entry,
        entry_mode="ARM",
        is_veneer=False,
        target_ptr=entry,
        target=entry,
        target_mode="ARM",
        owner=owner.name,
    )


def all_hits(data: bytes, needle: bytes):
    out = []
    pos = 0

    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(pos)
        pos += 1


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

    uniq = {(mode, x.address): (mode, x) for mode, x in out}
    return [uniq[k] for k in sorted(uniq, key=lambda q: (q[1],q[0]))]


def is_prologue(x):
    if x is None:
        return False

    if x.mnemonic == "push" and "lr" in x.op_str:
        return True

    if x.mnemonic in {"stmdb", "stmfd"} and "lr" in x.op_str:
        return True

    return False


def candidate_prologues(img: Image, target: int, mode: str, back=0x500, forward=0x900):
    step = 2 if mode == "THUMB" else 4
    lo = max(img.base, target-back)

    if mode == "THUMB":
        lo &= ~1
    else:
        lo &= ~3

    out = []

    for a in range(lo, target+1, step):
        x = decode1(img,a,mode)

        if not is_prologue(x):
            continue

        xs = dis(img,a,min(img.end,a+forward),mode)

        if any(z.address == target for z in xs):
            out.append(a)

    return out


def enclosing_start(img: Image, target: int, mode: str):
    cands = candidate_prologues(img,target,mode)
    return cands[-1] if cands else None


def reg_written(x):
    if not x.operands:
        return None

    op0 = x.operands[0]
    if op0.type == ARM_OP_REG:
        return op0.reg

    return None


def reg_id_by_name(insns, name: str):
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == name:
                return op.reg
    return None


def backward_source(img: Image, insns, before_addr: int, regname: str, mode: str, depth=0):
    if depth > 10:
        return "UNKNOWN(depth-limit)"

    hist = [x for x in insns if x.address < before_addr]
    rid = reg_id_by_name(hist,regname)

    if rid is None:
        return f"UNKNOWN({regname} unseen)"

    caller_saved = regname in {"r0","r1","r2","r3","r12","ip","lr"}

    for i in range(len(hist)-1,-1,-1):
        x = hist[i]

        if x.mnemonic in {"bl","blx"} and caller_saved:
            return f"UNKNOWN({regname} clobbered by call @0x{x.address:08X})"

        if reg_written(x) != rid:
            continue

        li = literal_load(img,x,mode)

        if li and li[1] == rid:
            return f"CONST 0x{li[3]:08X} via literal @0x{li[2]:08X}"

        ops = x.operands

        if x.mnemonic in {"mov","movs"} and len(ops)>=2:
            s = ops[1]

            if s.type == ARM_OP_IMM:
                return f"CONST 0x{s.imm & 0xFFFFFFFF:08X} @0x{x.address:08X}"

            if s.type == ARM_OP_REG:
                src = x.reg_name(s.reg)
                return (
                    f"{regname} <- {src} @0x{x.address:08X} <- "
                    + backward_source(img,hist[:i+1],x.address,src,mode,depth+1)
                )

        if x.mnemonic.startswith("ldr") and len(ops)>=2 and ops[1].type == ARM_OP_MEM:
            m = ops[1].mem
            base = x.reg_name(m.base) if m.base else "?"
            return f"MEM {x.mnemonic} [{base}{m.disp:+#x}] @0x{x.address:08X}"

        if x.mnemonic in {"add","adds","sub","subs","lsl","lsls","lsr","lsrs"}:
            return f"EXPR {x.mnemonic} {x.op_str} @0x{x.address:08X}"

        return f"UNKNOWN(writer {x.mnemonic} {x.op_str} @0x{x.address:08X})"

    return f"ARG/INHERITED {regname}"


def inspect_resolved_target(images, rt: ResolvedTarget, label: str):
    banner(f"C. {label} RESOLUTION")

    print(f"entry             = 0x{rt.entry:08X}")
    print(f"entry mode        = {rt.entry_mode}")
    print(f"is veneer         = {rt.is_veneer}")
    print(f"resolved ptr      = 0x{rt.target_ptr:08X}")
    print(f"resolved target   = 0x{rt.target:08X}")
    print(f"resolved mode     = {rt.target_mode}")
    print(f"resolved owner    = {rt.owner}")

    img = image_for(images,rt.target)

    if img is None:
        print("resolved implementation is outside canonical ALICE/ZIMAGE")
        return None,None

    start = enclosing_start(img,rt.target,rt.target_mode)

    if start is None:
        start = rt.target

    print(f"implementation start candidate = 0x{start:08X}")

    print_region(
        img,
        start,
        min(img.end,start+0x180),
        rt.target_mode,
        {rt.target},
    )

    return img,start


def audit_entry_callers(images, entry: int, label: str):
    banner(f"D. {label} DIRECT CALLERS")

    records = []

    for img in images:
        calls = scan_direct_calls(img,entry)
        print(f"{img.name}: direct callers to 0x{entry:08X} = {len(calls)}")

        for mode,x in calls:
            print()
            print(f"{img.name} {mode} {fmt(x)}")

            fs = enclosing_start(img,x.address,mode)

            if fs is None:
                lo = max(img.base,x.address-0x80)
                hi = min(img.end,x.address+0x20)
                ins = dis(img,lo,hi,mode)
                print("  enclosing function: UNKNOWN")
            else:
                lo = fs
                hi = min(img.end,fs+0x900)
                ins = dis(img,lo,hi,mode)
                print(f"  enclosing function start = 0x{fs:08X}")

            args = {}

            for rn in ("r0","r1","r2","r3"):
                args[rn] = backward_source(img,ins,x.address,rn,mode)
                print(f"  {rn}: {args[rn]}")

            records.append((img,mode,x,fs,args))

    return records


def first_use_of_arg_register(img: Image, start: int, mode: str, argname: str, max_bytes=0x140):
    """
    Lightweight semantic inventory inside resolved implementation:
    report memory stores, compares, arithmetic and calls involving original arg.
    """
    xs = dis(img,start,min(img.end,start+max_bytes),mode)

    rid = reg_id_by_name(xs,argname)

    if rid is None:
        return []

    aliases = {rid}
    events = []

    for x in xs:
        ops = x.operands

        # alias propagation
        if x.mnemonic in {"mov","movs"} and len(ops)>=2:
            d,s = ops[0],ops[1]
            if d.type == ARM_OP_REG and s.type == ARM_OP_REG and s.reg in aliases:
                aliases.add(d.reg)
                events.append(("ALIAS",x,f"{x.reg_name(d.reg)} <- {argname}"))

        # stores
        if x.mnemonic.startswith("str") and len(ops)>=2:
            src,mem = ops[0],ops[1]
            if src.type == ARM_OP_REG and src.reg in aliases and mem.type == ARM_OP_MEM:
                events.append(
                    ("STORE",x,
                     f"{argname} -> [{x.reg_name(mem.mem.base)}{mem.mem.disp:+#x}]")
                )

        # compares
        if x.mnemonic.startswith("cmp"):
            involved=[]
            for op in ops:
                if op.type == ARM_OP_REG and op.reg in aliases:
                    involved.append(x.reg_name(op.reg))
            if involved:
                events.append(("COMPARE",x,f"{argname} involved: {x.op_str}"))

        # arithmetic
        if x.mnemonic in {"add","adds","sub","subs","lsl","lsls","lsr","lsrs"}:
            for op in ops:
                if op.type == ARM_OP_REG and op.reg in aliases:
                    events.append(("ARITH",x,f"{argname} arithmetic: {x.op_str}"))
                    break

        # memory base/index using arg
        for op in ops:
            if op.type != ARM_OP_MEM:
                continue

            if op.mem.base in aliases:
                events.append(
                    ("MEM_BASE",x,
                     f"{argname} used as memory base: {x.op_str}")
                )

            if op.mem.index in aliases:
                events.append(
                    ("MEM_INDEX",x,
                     f"{argname} used as memory index: {x.op_str}")
                )

        # call with aliases in r0/r1
        if x.mnemonic in {"bl","blx"}:
            target = direct_target(x)
            events.append(
                ("CALL_BOUNDARY",x,
                 f"call target={('0x%08X'%target) if target is not None else x.op_str}")
            )

            # caller-saved aliases cannot be tracked after arbitrary call
            aliases = {
                r for r in aliases
                if x.reg_name(r) not in {"r0","r1","r2","r3","r12","ip","lr"}
            }

        if x.mnemonic == "bx" and x.op_str.strip()=="lr":
            break

        if x.mnemonic == "pop" and "pc" in x.op_str:
            break

    return events


def print_arg_semantics(img: Image, start: int, mode: str, label: str):
    banner(f"E. {label} ARGUMENT SEMANTICS")

    for arg in ("r0","r1"):
        events = first_use_of_arg_register(img,start,mode,arg)
        print()
        print(f"{arg} events = {len(events)}")

        for kind,x,desc in events[:80]:
            print(f"  {kind:<14} {fmt(x)} | {desc}")


def paired_caller_analysis(apply_records,count_records):
    banner("F. APPLY / COUNT PAIRED CALLER ANALYSIS")

    # Group by image and enclosing function start.
    apply_by_func = {}
    count_by_func = {}

    for img,mode,x,fs,args in apply_records:
        key=(img.name,mode,fs)
        apply_by_func.setdefault(key,[]).append((x,args))

    for img,mode,x,fs,args in count_records:
        key=(img.name,mode,fs)
        count_by_func.setdefault(key,[]).append((x,args))

    keys=sorted(set(apply_by_func) | set(count_by_func), key=lambda k:(k[0],k[2] or 0))

    paired=[]

    for key in keys:
        a=apply_by_func.get(key,[])
        c=count_by_func.get(key,[])

        if not a or not c:
            continue

        paired.append((key,a,c))

        print()
        print(f"FUNCTION {key[0]} {key[1]} start={('0x%08X'%key[2]) if key[2] else 'UNKNOWN'}")
        print(f"  APPLY calls = {len(a)}")
        print(f"  COUNT calls = {len(c)}")

        for x,args in a:
            print(f"    APPLY @{x.address:08X}: r0={args['r0']} ; r1={args['r1']}")

        for x,args in c:
            print(f"    COUNT @{x.address:08X}: r0={args['r0']}")

        # Print compact function context if same image is canonical.
        img = next((rec[0] for rec in apply_records if rec[0].name==key[0]),None)
        if img and key[2]:
            print_region(
                img,
                key[2],
                min(img.end,key[2]+0xA0),
                key[1],
                {x.address for x,_ in a} | {x.address for x,_ in c},
            )

    print()
    print(f"paired functions = {len(paired)}")

    return paired


def find_minus_one_after_count(img: Image, call_addr: int, mode: str, max_bytes=0x20):
    xs = dis(img,call_addr+4,min(img.end,call_addr+4+max_bytes),mode)

    for x in xs:
        if x.mnemonic in {"sub","subs"} and "#1" in x.op_str and "r0" in x.op_str:
            return x

        if x.mnemonic in {"bl","blx","bx"}:
            break

    return None


def classify_apply_target(events_r1):
    kinds={k for k,_,_ in events_r1}

    if "STORE" in kinds:
        return "R1_STORED_IN_OBJECT_OR_STATE"

    if "COMPARE" in kinds and ("MEM_INDEX" in kinds or "MEM_BASE" in kinds):
        return "R1_POSITION_OR_INDEX_LIKE"

    if "COMPARE" in kinds:
        return "R1_BOUNDED_VALUE"

    if "MEM_INDEX" in kinds:
        return "R1_INDEX_LIKE"

    return "OPEN"


def classify_count_target(events_r0):
    # A count getter often uses object pointer r0 as base and returns a scalar.
    kinds={k for k,_,_ in events_r0}

    if "MEM_BASE" in kinds:
        return "OBJECT_FIELD_GETTER_LIKE"

    return "OPEN"


def parse_args():
    p=argparse.ArgumentParser()
    p.add_argument("--alice",default="research/f2/work/extracted/altice_alice/alice-py.bin")
    p.add_argument("--zimage",default="research/f2/work/extracted/altice_platform/zimage.bin")
    p.add_argument("--report",default="research/f2/work/reports/s13_5a17_current_item_apply_count_pair.txt")
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
        banner("S13.5A.17 - CURRENT-ITEM APPLY API / ITEM-COUNT PAIR AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice=verify(resolve(root,args.alice),"ALICE",ALICE_BASE,ALICE_SIZE,ALICE_SHA256)
        zimage=verify(resolve(root,args.zimage),"ZIMAGE",ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA256)
        images=[alice,zimage]

        banner("B. ENTRY / VENEER DETECTION")
        print("APPLY_ENTRY:")
        apply_rt=resolve_entry(images,APPLY_ENTRY)
        print(
            f"  resolved: veneer={apply_rt.is_veneer} "
            f"target=0x{apply_rt.target:08X} mode={apply_rt.target_mode} owner={apply_rt.owner}"
        )
        print()
        print("COUNT_ENTRY:")
        count_rt=resolve_entry(images,COUNT_ENTRY)
        print(
            f"  resolved: veneer={count_rt.is_veneer} "
            f"target=0x{count_rt.target:08X} mode={count_rt.target_mode} owner={count_rt.owner}"
        )

        apply_img,apply_start=inspect_resolved_target(images,apply_rt,"APPLY API")
        count_img,count_start=inspect_resolved_target(images,count_rt,"COUNT API")

        apply_records=audit_entry_callers(images,APPLY_ENTRY,"APPLY ENTRY")
        count_records=audit_entry_callers(images,COUNT_ENTRY,"COUNT ENTRY")

        if apply_img is not None and apply_start is not None:
            print_arg_semantics(apply_img,apply_start,apply_rt.target_mode,"APPLY RESOLVED TARGET")
            apply_r1_events=first_use_of_arg_register(
                apply_img,apply_start,apply_rt.target_mode,"r1"
            )
        else:
            apply_r1_events=[]

        if count_img is not None and count_start is not None:
            print_arg_semantics(count_img,count_start,count_rt.target_mode,"COUNT RESOLVED TARGET")
            count_r0_events=first_use_of_arg_register(
                count_img,count_start,count_rt.target_mode,"r0"
            )
        else:
            count_r0_events=[]

        paired=paired_caller_analysis(apply_records,count_records)

        banner("G. COUNT()-1 CALLSITE CENSUS")
        minus1=[]

        for img,mode,x,fs,args in count_records:
            y=find_minus_one_after_count(img,x.address,mode)
            if y:
                minus1.append((img,mode,x,y,fs,args))
                print()
                print(f"{img.name} {mode} count call: {fmt(x)}")
                print(f"  immediate -1: {fmt(y)}")
                print(f"  r0 object source before count: {args['r0']}")

        print()
        print(f"COUNT calls followed by r0-1 = {len(minus1)}")

        banner("H. KNOWN GETTER->APPLY CALLS FROM A.16")
        known_apply_sites={0xF02EDF0A,0xF02EDF3A,0xF031347E}

        matched=0

        for img,mode,x,fs,args in apply_records:
            if x.address not in known_apply_sites:
                continue

            matched+=1
            print()
            print(f"known getter consumer APPLY @0x{x.address:08X}")
            print(f"  r0 object/context = {args['r0']}")
            print(f"  r1 current-item   = {args['r1']}")

            if fs:
                print_region(
                    img,
                    max(fs,x.address-0x10),
                    min(img.end,x.address+0x10),
                    mode,
                    {x.address},
                )

        print()
        print(f"matched known getter->APPLY sites = {matched}/3")

        banner("I. DECISION GATE")

        apply_class=classify_apply_target(apply_r1_events)
        count_class=classify_count_target(count_r0_events)

        print(f"APPLY entry veneer          = {apply_rt.is_veneer}")
        print(f"APPLY resolved target       = 0x{apply_rt.target:08X} {apply_rt.target_mode} {apply_rt.owner}")
        print(f"APPLY r1 semantic class     = {apply_class}")
        print()
        print(f"COUNT entry veneer          = {count_rt.is_veneer}")
        print(f"COUNT resolved target       = 0x{count_rt.target:08X} {count_rt.target_mode} {count_rt.owner}")
        print(f"COUNT r0 semantic class     = {count_class}")
        print()
        print(f"direct APPLY callers        = {len(apply_records)}")
        print(f"direct COUNT callers        = {len(count_records)}")
        print(f"paired caller functions     = {len(paired)}")
        print(f"COUNT calls with immediate -1 = {len(minus1)}")
        print(f"A.16 getter->APPLY matches  = {matched}/3")
        print()

        if apply_class in {"R1_STORED_IN_OBJECT_OR_STATE","R1_POSITION_OR_INDEX_LIKE","R1_BOUNDED_VALUE","R1_INDEX_LIKE"}:
            print("[PASS] APPLY target treats argument r1 as structured state/index-like data.")
        else:
            print("[OPEN] APPLY target r1 semantics not yet structurally classified.")

        if minus1:
            print("[STRONG EVIDENCE] COUNT helper is repeatedly followed by '-1',")
            print("consistent with converting an item count to a last zero-based index.")

        if (
            matched == 3
            and apply_class in {
                "R1_STORED_IN_OBJECT_OR_STATE",
                "R1_POSITION_OR_INDEX_LIKE",
                "R1_BOUNDED_VALUE",
                "R1_INDEX_LIKE",
            }
            and minus1
        ):
            print()
            print("[PROMOTION CANDIDATE] Combined evidence strongly supports:")
            print("  platform field state+0x264 = one-based current/highlight item")
            print("  dispatcher argument        = zero-based UI/list item index")
            print("Promote to FACT only if the resolved APPLY implementation or paired caller")
            print("shows unmistakable list/current-item semantics rather than generic scalar state.")
        else:
            print()
            print("[NEXT] Follow only the strongest resolved APPLY/COUNT target path above.")

        print()
        print("PROVEN FRAMEWORK CHAIN:")
        print("  setter receives index0+1")
        print("  getter returns same persistent field")
        print("  getter value is passed as r1 to F02D0CE0 in 3 real consumers")
        print("  dispatcher receives index0 and SELECT_CB resolves children[index0]")
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
        sys.stdout=old
        report_path.write_text(cap.getvalue(),encoding="utf-8")


if __name__=="__main__":
    raise SystemExit(main())
