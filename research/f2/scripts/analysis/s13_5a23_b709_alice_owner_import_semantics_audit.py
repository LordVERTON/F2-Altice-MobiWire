#!/usr/bin/env python3
"""
S13.5A.23 - B709 ALICE OWNER / IMPORT VENEER SEMANTICS AUDIT

STRICTLY OFFLINE / READ-ONLY.

This pass follows the strongest new evidence from S13.5A.22:

  0x10313998:
      r5 = 0xB709
      r0 = r5
      blx 0x102FC51C
      r6 = r0

      r0 = r5
      r1 = sp+4
      blx 0x102FC3CC

      for i in range(r6):
          child = *(u16 *)(sp+4 + 2*i)
          r0 = child
          r1 = 8
          blx 0x102FC20C
          F00B7994[i] = r0

A.22 also incorrectly reported the B709 root-category mapper as OPEN because
its function recovery stopped at the early failure return at 0xF02F9D56.
A.21 already showed the valid branch continuing through 0xF02F9D5C..0xF02F9D92.

Goals:
  A. validate canonical ALICE/ZIMAGE;
  B. re-prove the complete 0xF02F9D34 function using its known full range;
  C. decode the exact ARM import veneers:
       0x102FC51C
       0x102FC3CC
       0x102FC20C
  D. resolve each real target and disassemble its complete reachable body;
  E. classify 0x102FC51C as COUNT-like / other;
  F. classify 0x102FC3CC as ENUM_CHILD_IDS-like / other;
  G. classify 0x102FC20C(child_id, 8) and determine what field/value is produced;
  H. prove the 0x10313998 B709 owner contract from data flow;
  I. census all callers of those three veneers and recover constant arguments;
  J. inspect F00B7994 writers/readers to determine what the per-B709-child
     transformed values are used for;
  K. decision gate.

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

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

ROOT_ID = 0xB709
ROOT_MAPPER = 0xF02F9D34
GET_PARENT_ID = 0xF02FBC24
PARENT_TO_INDEX = 0xF02E01B0
INDEX_TO_ID = 0xF02FEFB4
REGISTRY_GLOBAL = 0xF007F044
LOOKUP_GLOBAL = 0xF007F048

OWNER = 0x10313998
VENEER_A = 0x102FC51C
VENEER_B = 0x102FC3CC
VENEER_C = 0x102FC20C
OUTPUT_ARRAY = 0xF00B7994

# Known public provider targets for comparison.
KNOWN_GET_CHILD_COUNT = 0xF02D8870
KNOWN_ENUM_CHILD_IDS = 0xF032ACDC
KNOWN_GET_CHILD_META = 0xF02F9CCC

KNOWN_TARGET_LABELS = {
    KNOWN_GET_CHILD_COUNT: "GET_CHILD_COUNT",
    KNOWN_ENUM_CHILD_IDS: "ENUM_CHILD_IDS",
    KNOWN_GET_CHILD_META: "GET_CHILD_META",
    GET_PARENT_ID: "GET_PARENT_ID",
    PARENT_TO_INDEX: "PARENT_TO_INDEX",
    INDEX_TO_ID: "INDEX_TO_ID",
}

md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md_t.detail = True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md_a.detail = True


class Tee:
    def __init__(self,*streams):
        self.streams=streams
    def write(self,s):
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

    def contains(self, addr:int):
        a=addr & ~1
        return self.base <= a < self.end

    def off(self, addr:int):
        return (addr & ~1) - self.base


@dataclass
class Veneer:
    addr:int
    recognized:bool
    literal_addr:int|None
    target_ptr:int|None


@dataclass
class Func:
    image:Image
    start:int
    end:int
    mode:str
    insns:list


def banner(s):
    print()
    print("="*144)
    print(s)
    print("="*144)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u16(data,off):
    if off<0 or off+2>len(data):
        return None
    return struct.unpack_from("<H",data,off)[0]


def u32(data,off):
    if off<0 or off+4>len(data):
        return None
    return struct.unpack_from("<I",data,off)[0]


def verify(path:Path,name,base,size,expected):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical {name}: {path}")
    data=path.read_bytes()
    got=sha256(data)
    print(f"{name} = {path}")
    print(f"  runtime base = 0x{base:08X}")
    print(f"  size         = 0x{len(data):X}")
    print(f"  sha256       = {got}")
    if len(data)!=size:
        raise SystemExit(f"ABORT: {name} size mismatch")
    if got.lower()!=expected.lower():
        raise SystemExit(f"ABORT: {name} SHA256 mismatch")
    print(f"[PASS] canonical {name}")
    return Image(name,data,base)


def image_for(images,addr):
    a=addr & ~1
    for img in images:
        if img.base<=a<img.end:
            return img
    return None


def decode1(img,addr,mode):
    a=(addr & ~1) if mode=="THUMB" else (addr & ~3)
    if not img.contains(a):
        return None
    md=md_t if mode=="THUMB" else md_a
    xs=list(md.disasm(img.data[img.off(a):img.off(a)+4],a,count=1))
    return xs[0] if xs else None


def dis(img,start,end,mode):
    start=(start&~1) if mode=="THUMB" else (start&~3)
    if not img.contains(start):
        return []
    md=md_t if mode=="THUMB" else md_a
    end=min(end,img.end)
    return [x for x in md.disasm(img.data[img.off(start):img.off(start)+(end-start)],start) if x.address<end]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<10} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b","bl","blx"} or not x.operands:
        return None
    op=x.operands[0]
    return (op.imm & 0xFFFFFFFF) if op.type==ARM_OP_IMM else None


def literal_load(img,x,mode):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands)<2:
        return None
    d,s=x.operands[0],x.operands[1]
    if d.type!=ARM_OP_REG or s.type!=ARM_OP_MEM or s.mem.base!=ARM_REG_PC:
        return None
    pc=((x.address+4)&~3) if mode=="THUMB" else x.address+8
    la=(pc+s.mem.disp)&0xFFFFFFFF
    if not img.contains(la):
        return None
    return x.reg_name(d.reg),d.reg,la,u32(img.data,img.off(la))


def print_region(img,start,end,mode,marks=None):
    marks=marks or set()
    for x in dis(img,start,end,mode):
        notes=[]
        t=direct_target(x)
        if t is not None:
            label=KNOWN_TARGET_LABELS.get(t&~1)
            notes.append(
                f"target=0x{t:08X}"
                + (f"<{label}>" if label else "")
            )
        li=literal_load(img,x,mode)
        if li:
            tags=[]
            if li[3]==ROOT_ID: tags.append("B709")
            if li[3]==REGISTRY_GLOBAL: tags.append("REGISTRY_GLOBAL")
            if li[3]==LOOKUP_GLOBAL: tags.append("LOOKUP_GLOBAL")
            if li[3]==OUTPUT_ARRAY: tags.append("OUTPUT_ARRAY")
            notes.append(
                f"literal@0x{li[2]:08X}=0x{li[3]:08X}->{li[0]}"
                + (f"<{'|'.join(tags)}>" if tags else "")
            )
        print(
            (">>> " if x.address in marks else "    ")
            + fmt(x)
            + ((" ; "+", ".join(notes)) if notes else "")
        )


def all_hits(data,needle):
    out=[]
    pos=0
    while True:
        pos=data.find(needle,pos)
        if pos<0:
            return out
        out.append(pos)
        pos+=1


def is_return(x):
    return bool(
        x and (
            (x.mnemonic=="bx" and x.op_str.strip()=="lr")
            or (x.mnemonic=="pop" and "pc" in x.op_str)
        )
    )


def is_cond_branch(x):
    return bool(
        x and x.mnemonic.startswith("b")
        and x.mnemonic not in {"b","bl","blx","bx"}
    )


def decode_arm_veneer(alice,addr):
    a=addr&~3
    x=decode1(alice,a,"ARM")
    if x is None:
        return Veneer(a,False,None,None)

    if (
        x.mnemonic=="ldr"
        and len(x.operands)>=2
        and x.operands[0].type==ARM_OP_REG
        and x.reg_name(x.operands[0].reg)=="pc"
        and x.operands[1].type==ARM_OP_MEM
        and x.operands[1].mem.base==ARM_REG_PC
    ):
        la=(x.address+8+x.operands[1].mem.disp)&0xFFFFFFFF
        if alice.contains(la):
            return Veneer(a,True,la,u32(alice.data,alice.off(la)))

    return Veneer(a,False,None,None)


def recover_cfg(img,ptr,max_bytes=0x600):
    mode="THUMB" if (ptr&1) else "ARM"
    start=(ptr&~1) if mode=="THUMB" else (ptr&~3)
    xs=dis(img,start,min(img.end,start+max_bytes),mode)
    by={x.address:x for x in xs}
    todo=deque([start])
    seen=set()

    while todo:
        a=todo.popleft()
        if a in seen:
            continue
        x=by.get(a)
        if x is None:
            continue
        seen.add(a)

        if is_return(x):
            continue

        nxt=x.address+len(x.bytes)
        t=direct_target(x)

        if x.mnemonic=="b" and t is not None:
            ta=(t&~1) if mode=="THUMB" else (t&~3)
            if start<=ta<start+max_bytes:
                todo.append(ta)
            continue

        if is_cond_branch(x):
            if t is not None:
                ta=(t&~1) if mode=="THUMB" else (t&~3)
                if start<=ta<start+max_bytes:
                    todo.append(ta)
            todo.append(nxt)
            continue

        # Calls fall through.
        todo.append(nxt)

    if not seen:
        return Func(img,start,start,mode,[])

    end=max(a+len(by[a].bytes) for a in seen)
    ins=[by[a] for a in sorted(seen)]
    return Func(img,start,end,mode,ins)


def scan_direct_calls(img,target):
    out=[]

    for off in range(0,len(img.data)-4,2):
        h1=u16(img.data,off)
        h2=u16(img.data,off+2)
        if h1 is None or h2 is None:
            continue
        if (h1&0xF800)!=0xF000 or (h2&0xC000)!=0xC000:
            continue
        xs=list(md_t.disasm(img.data[off:off+4],img.base+off,count=1))
        if not xs:
            continue
        x=xs[0]
        if x.mnemonic not in {"bl","blx"}:
            continue
        t=direct_target(x)
        if t is not None and (t&~1)==(target&~1):
            out.append(("THUMB",x))

    for off in range(0,len(img.data)-4,4):
        xs=list(md_a.disasm(img.data[off:off+4],img.base+off,count=1))
        if not xs:
            continue
        x=xs[0]
        if x.mnemonic not in {"bl","blx"}:
            continue
        t=direct_target(x)
        if t is not None and (t&~1)==(target&~1):
            out.append(("ARM",x))

    uniq={(m,x.address):(m,x) for m,x in out}
    return [uniq[k] for k in sorted(uniq,key=lambda q:(q[1],q[0]))]


def raw_pointer_refs(img,value):
    out=[]
    for v in {value&0xFFFFFFFF,(value|1)&0xFFFFFFFF}:
        pat=struct.pack("<I",v)
        for off in all_hits(img.data,pat):
            out.append((img.base+off,v))
    return sorted(set(out))


def real_literal_xrefs_to_word(img,word_addr):
    out=[]
    for a in range(max(img.base,word_addr-0x500)&~1,word_addr+1,2):
        x=decode1(img,a,"THUMB")
        li=literal_load(img,x,"THUMB") if x else None
        if li and li[2]==word_addr:
            out.append(("THUMB",x))
    for a in range(max(img.base,word_addr-0x1000)&~3,word_addr+1,4):
        x=decode1(img,a,"ARM")
        li=literal_load(img,x,"ARM") if x else None
        if li and li[2]==word_addr:
            out.append(("ARM",x))
    uniq={(m,x.address):(m,x) for m,x in out}
    return [uniq[k] for k in sorted(uniq)]


def enclosing_thumb_function(img,target,back=0x500,forward=0x900):
    lo=max(img.base,target-back)&~1
    starts=[]
    for a in range(lo,target+1,2):
        x=decode1(img,a,"THUMB")
        if x and x.mnemonic=="push" and "lr" in x.op_str:
            starts.append(a)
    if not starts:
        return target,min(img.end,target+0x100)
    # Choose nearest prologue from which linear decode reaches target.
    for start in reversed(starts):
        xs=dis(img,start,min(img.end,start+forward),"THUMB")
        if any(x.address==target for x in xs):
            # do not stop at early return; show a moderate window
            return start,min(img.end,start+0x180)
    return starts[-1],min(img.end,starts[-1]+0x180)


# -----------------------------------------------------------------------------
# Backward argument provenance
# -----------------------------------------------------------------------------

def reg_written(x):
    if not x.operands:
        return None
    return x.operands[0].reg if x.operands[0].type==ARM_OP_REG else None


def reg_id(insns,name):
    for x in insns:
        for op in x.operands:
            if op.type==ARM_OP_REG and x.reg_name(op.reg)==name:
                return op.reg
    return None


def back_const(img,insns,before,regname,depth=0):
    if depth>10:
        return ("UNKNOWN",None,"depth")
    hist=[x for x in insns if x.address<before]
    rid=reg_id(hist,regname)
    if rid is None:
        return ("UNKNOWN",None,f"{regname} unseen")

    caller_saved=regname in {"r0","r1","r2","r3","r12","ip","lr"}

    for i in range(len(hist)-1,-1,-1):
        x=hist[i]

        if x.mnemonic in {"bl","blx"} and caller_saved:
            return ("UNKNOWN",None,f"{regname} clobbered by call@0x{x.address:08X}")

        if reg_written(x)!=rid:
            continue

        li=literal_load(img,x,"THUMB")
        if li and li[1]==rid:
            return ("CONST",li[3],f"literal@0x{li[2]:08X}")

        ops=x.operands

        if x.mnemonic in {"mov","movs"} and len(ops)>=2:
            s=ops[1]
            if s.type==ARM_OP_IMM:
                return ("CONST",s.imm&0xFFFFFFFF,f"{x.mnemonic}@0x{x.address:08X}")
            if s.type==ARM_OP_REG:
                src=x.reg_name(s.reg)
                k,v,d=back_const(img,hist[:i+1],x.address,src,depth+1)
                return (k,v,f"{regname}<-{src}@0x{x.address:08X} <- {d}")

        if x.mnemonic in {"add","adds","sub","subs"}:
            # Stack-relative outputs are useful even when not numeric constants.
            if "sp" in x.op_str:
                return ("STACK_PTR",None,f"{x.mnemonic} {x.op_str}@0x{x.address:08X}")
            return ("EXPR",None,f"{x.mnemonic} {x.op_str}@0x{x.address:08X}")

        if x.mnemonic.startswith("ldr"):
            return ("MEM",None,f"{x.mnemonic} {x.op_str}@0x{x.address:08X}")

        return ("UNKNOWN",None,f"writer {x.mnemonic} {x.op_str}@0x{x.address:08X}")

    return ("ARG",None,regname)


# -----------------------------------------------------------------------------
# Semantic classifiers
# -----------------------------------------------------------------------------

def function_features(func):
    calls=[]
    literals=[]
    memops=[]

    for x in func.insns:
        t=direct_target(x)
        if x.mnemonic in {"bl","blx"} and t is not None:
            calls.append((x,t&~1))
        li=literal_load(func.image,x,func.mode)
        if li:
            literals.append((x,li))
        if any(op.type==ARM_OP_MEM for op in x.operands):
            memops.append(x)

    return calls,literals,memops


def classify_target(func):
    calls,lits,memops=function_features(func)
    call_targets={t for _,t in calls}
    lit_values={li[3] for _,li in lits}

    count_score=0
    enum_score=0
    meta_score=0

    if PARENT_TO_INDEX in call_targets:
        count_score += 2
        enum_score += 2
        meta_score += 1

    if REGISTRY_GLOBAL in lit_values:
        count_score += 2
        enum_score += 2
        meta_score += 2

    # Count providers generally read record +2 and return a scalar.
    if any(
        x.mnemonic=="ldrh" and "#2" in x.op_str
        for x in memops
    ):
        count_score += 2

    # Enum providers generally load +0xC child pointer and copy/iterate u16s.
    if any(
        x.mnemonic=="ldr" and "#0xc" in x.op_str.lower()
        for x in memops
    ):
        enum_score += 3

    if sum(1 for x in memops if x.mnemonic=="ldrh") >= 2:
        enum_score += 1
        meta_score += 1

    # A two-argument selector/meta routine often branches on r1 / uses it as
    # selector; heuristic only.
    if any(
        x.mnemonic.startswith("cmp") and ("r1" in x.op_str or "#8" in x.op_str)
        for x in func.insns
    ):
        meta_score += 2

    scores={
        "COUNT_LIKE":count_score,
        "ENUM_LIKE":enum_score,
        "META_OR_SELECTOR_LIKE":meta_score,
    }

    best=max(scores,key=scores.get)
    return best,scores,calls,lits


def print_func(func,mark_start=True):
    print(f"image = {func.image.name}")
    print(f"mode  = {func.mode}")
    print(f"body  = 0x{func.start:08X}..0x{func.end:08X}")
    print(f"reachable instructions = {len(func.insns)}")
    print()
    marks={func.start} if mark_start else set()
    # Print actual reachable instructions, preserving CFG holes.
    for x in func.insns:
        notes=[]
        t=direct_target(x)
        if t is not None:
            label=KNOWN_TARGET_LABELS.get(t&~1)
            notes.append(
                f"target=0x{t:08X}"
                + (f"<{label}>" if label else "")
            )
        li=literal_load(func.image,x,func.mode)
        if li:
            tags=[]
            if li[3]==REGISTRY_GLOBAL: tags.append("REGISTRY_GLOBAL")
            if li[3]==LOOKUP_GLOBAL: tags.append("LOOKUP_GLOBAL")
            if li[3]==ROOT_ID: tags.append("B709")
            notes.append(
                f"literal@0x{li[2]:08X}=0x{li[3]:08X}"
                + (f"<{'|'.join(tags)}>" if tags else "")
            )
        print(
            (">>> " if x.address in marks else "    ")
            + fmt(x)
            + ((" ; "+", ".join(notes)) if notes else "")
        )


# -----------------------------------------------------------------------------
# Audits
# -----------------------------------------------------------------------------

def root_mapper_full_audit(zimage):
    banner("B. ROOT MAPPER COMPLETE-RANGE CORRECTION")

    print("A.22 stopped at the early failure return 0xF02F9D56.")
    print("Use the already-proven full range from A.21:")
    print("  0xF02F9D34..0xF02F9D94")
    print()

    print_region(
        zimage,0xF02F9D34,0xF02F9D94,"THUMB",
        {
            0xF02F9D38,0xF02F9D3C,0xF02F9D44,0xF02F9D4C,
            0xF02F9D54,0xF02F9D5C,0xF02F9D64,0xF02F9D6E,
            0xF02F9D72,0xF02F9D80,0xF02F9D8A,0xF02F9D90,
        }
    )

    xs=dis(zimage,0xF02F9D34,0xF02F9D94,"THUMB")
    addrs={x.address:x for x in xs}

    checks={
        "GET_PARENT_ID at entry": direct_target(addrs.get(0xF02F9D38))==GET_PARENT_ID,
        "root literal B709": (
            literal_load(zimage,addrs.get(0xF02F9D3C),"THUMB") or (None,None,None,None)
        )[3]==ROOT_ID,
        "failure return FF": (
            addrs.get(0xF02F9D54) is not None
            and addrs[0xF02F9D54].mnemonic in {"mov","movs"}
        ),
        "registry global load in valid branch": (
            literal_load(zimage,addrs.get(0xF02F9D5C),"THUMB") or (None,None,None,None)
        )[3]==REGISTRY_GLOBAL,
        "PARENT_TO_INDEX(B709) call": direct_target(addrs.get(0xF02F9D64))==PARENT_TO_INDEX,
        "children pointer read +0xC": (
            addrs.get(0xF02F9D6E) is not None
            and addrs[0xF02F9D6E].mnemonic=="ldr"
            and "#0xc" in addrs[0xF02F9D6E].op_str.lower()
        ),
        "child u16 scan": addrs.get(0xF02F9D72) is not None and addrs[0xF02F9D72].mnemonic=="ldrh",
        "returns r4 index": (
            addrs.get(0xF02F9D90) is not None
            and addrs[0xF02F9D90].mnemonic in {"mov","movs"}
            and "r0, r4" in addrs[0xF02F9D90].op_str
        ),
    }

    print()
    for k,v in checks.items():
        print(f"{k:<46} = {'PASS' if v else 'OPEN'}")

    ok=all(checks.values())

    print()
    print(
        "[PASS] A.22 root-mapper OPEN is SUPERSEDED."
        if ok else
        "[OPEN] full-range verification still has missing markers."
    )

    return ok


def veneer_audit(alice,zimage,images):
    banner("C. B709 OWNER IMPORT VENEERS")

    resolved={}

    for label,addr in [
        ("A_COUNT_CANDIDATE",VENEER_A),
        ("B_ENUM_CANDIDATE",VENEER_B),
        ("C_CHILD_TRANSFORM",VENEER_C),
    ]:
        print()
        print(f"### {label} @0x{addr:08X}")

        # Raw pair + ARM decode.
        print(f"raw word[0] = 0x{u32(alice.data,alice.off(addr)):08X}")
        print(f"raw word[1] = 0x{u32(alice.data,alice.off(addr+4)):08X}")
        print_region(alice,addr,addr+8,"ARM",{addr})

        v=decode_arm_veneer(alice,addr)
        print(f"recognized = {v.recognized}")
        print(
            f"literal    = "
            + (f"0x{v.literal_addr:08X}" if v.literal_addr is not None else "NONE")
        )
        print(
            f"target_ptr = "
            + (f"0x{v.target_ptr:08X}" if v.target_ptr is not None else "NONE")
        )

        if not v.recognized or v.target_ptr is None:
            resolved[label]=(v,None,None)
            continue

        img=image_for(images,v.target_ptr)
        print(f"target image = {img.name if img else 'OUTSIDE CANONICAL IMAGES'}")

        if img is None:
            resolved[label]=(v,None,None)
            continue

        func=recover_cfg(img,v.target_ptr,0x700)
        print_func(func)
        kind,scores,calls,lits=classify_target(func)

        print()
        print(f"classifier = {kind}")
        for k,val in scores.items():
            print(f"  {k:<24} score={val}")

        exact=None
        tbase=v.target_ptr&~1
        if tbase==KNOWN_GET_CHILD_COUNT:
            exact="GET_CHILD_COUNT"
        elif tbase==KNOWN_ENUM_CHILD_IDS:
            exact="ENUM_CHILD_IDS"
        elif tbase==KNOWN_GET_CHILD_META:
            exact="GET_CHILD_META"

        if exact:
            print(f"[EXACT TARGET MATCH] {exact}")

        resolved[label]=(v,func,(kind,scores,exact))

    return resolved


def owner_audit(alice,resolved):
    banner("D. 0x10313998 B709 OWNER DATAFLOW")

    print_region(
        alice,0x10313998,0x103139D4,"THUMB",
        {
            0x1031399A,0x103139A2,0x103139AC,0x103139B6,
            0x103139BA,0x103139BE,0x103139C2,0x103139C4,
        }
    )

    xs=dis(alice,0x10313998,0x103139D4,"THUMB")
    by={x.address:x for x in xs}

    checks={
        "loads exact B709": (
            literal_load(alice,by.get(0x1031399A),"THUMB") or (None,None,None,None)
        )[3]==ROOT_ID,
        "calls veneer A with r0=B709": direct_target(by.get(0x103139A2))==VENEER_A,
        "stores veneer-A return as loop bound": (
            by.get(0x103139A6) is not None
            and by[0x103139A6].mnemonic in {"mov","movs"}
            and "r6, r0" in by[0x103139A6].op_str
        ),
        "calls veneer B with r0=B709 and stack output": direct_target(by.get(0x103139AC))==VENEER_B,
        "loads u16 child from output buffer": (
            by.get(0x103139B6) is not None and by[0x103139B6].mnemonic=="ldrh"
        ),
        "passes selector 8 to veneer C": (
            by.get(0x103139B8) is not None
            and by[0x103139B8].mnemonic in {"mov","movs"}
            and "#8" in by[0x103139B8].op_str
            and direct_target(by.get(0x103139BA))==VENEER_C
        ),
        "writes transformed u16 to F00B7994[i]": (
            (literal_load(alice,by.get(0x103139BE),"THUMB") or (None,None,None,None))[3]==OUTPUT_ARRAY
            and by.get(0x103139C2) is not None
            and by[0x103139C2].mnemonic=="strh"
        ),
        "loop bound compares i vs veneer-A return": (
            by.get(0x103139C4) is not None
            and by[0x103139C4].mnemonic=="cmp"
            and "r4, r6" in by[0x103139C4].op_str
        ),
    }

    print()
    for k,v in checks.items():
        print(f"{k:<54} = {'PASS' if v else 'OPEN'}")

    ok=all(checks.values())

    if ok:
        print()
        print("[FACT] 0x10313998 is a B709-child materialization/transform owner:")
        print("  N = veneer_A(B709)")
        print("  veneer_B(B709, u16_buffer)")
        print("  for i in [0,N):")
        print("      child_id = u16_buffer[i]")
        print("      F00B7994[i] = veneer_C(child_id, 8)")

    # Semantic synthesis based on resolved target classifiers.
    print()
    a=resolved.get("A_COUNT_CANDIDATE")
    b=resolved.get("B_ENUM_CANDIDATE")
    c=resolved.get("C_CHILD_TRANSFORM")

    for lbl,val in [("A",a),("B",b),("C",c)]:
        if val and val[2]:
            kind,scores,exact=val[2]
            print(f"veneer {lbl}: {exact or kind}")

    return ok


def callers_and_args(alice,resolved):
    banner("E. VENEER CALLER / ARGUMENT CENSUS")

    for label,addr in [
        ("A",VENEER_A),("B",VENEER_B),("C",VENEER_C)
    ]:
        print()
        print(f"### veneer {label} 0x{addr:08X}")
        calls=scan_direct_calls(alice,addr)
        print(f"direct ALICE callers = {len(calls)}")

        for mode,x in calls[:120]:
            if mode!="THUMB":
                print(f"  {mode} {fmt(x)}")
                continue
            fs,fe=enclosing_thumb_function(alice,x.address)
            ins=dis(alice,fs,fe,"THUMB")
            k0,v0,d0=back_const(alice,ins,x.address,"r0")
            k1,v1,d1=back_const(alice,ins,x.address,"r1")

            def p(k,v,d):
                if k=="CONST":
                    return f"0x{v:08X} via {d}"
                return f"{k}: {d}"

            print(
                f"  call@0x{x.address:08X} func=0x{fs:08X} "
                f"r0={p(k0,v0,d0)} ; r1={p(k1,v1,d1)}"
            )


def output_array_audit(images):
    banner("F. F00B7994 OWNER / CONSUMER AUDIT")

    pat=struct.pack("<I",OUTPUT_ARRAY)

    total_words=0
    total_xrefs=0

    for img in images:
        words=all_hits(img.data,pat)
        total_words+=len(words)
        print()
        print(f"{img.name}: raw pointer words to F00B7994 = {len(words)}")

        for off in words:
            word=img.base+off
            xrefs=real_literal_xrefs_to_word(img,word)
            total_xrefs+=len(xrefs)
            print(f"  word@0x{word:08X} real literal xrefs={len(xrefs)}")
            for mode,x in xrefs[:50]:
                print(f"    {mode} {fmt(x)}")
                if mode=="THUMB":
                    fs,fe=enclosing_thumb_function(img,x.address)
                    print(f"      function approx = 0x{fs:08X}..0x{fe:08X}")
                    print_region(
                        img,max(fs,x.address-0x18),min(fe,x.address+0x50),
                        "THUMB",{x.address}
                    )

    print()
    print(f"TOTAL pointer words = {total_words}")
    print(f"TOTAL real literal xrefs = {total_xrefs}")


def target_callers(images,resolved):
    banner("G. REAL TARGET OWNERSHIP")

    for label,(v,func,classification) in resolved.items():
        if not v or v.target_ptr is None:
            continue
        print()
        print(f"### {label} target=0x{v.target_ptr:08X}")
        for img in images:
            calls=scan_direct_calls(img,v.target_ptr)
            ptrs=raw_pointer_refs(img,v.target_ptr)
            print(
                f"{img.name}: direct calls={len(calls)} raw ptr refs={len(ptrs)}"
            )
            for mode,x in calls[:40]:
                print(f"  CALL {mode} {fmt(x)}")
            for addr,val in ptrs[:20]:
                lx=real_literal_xrefs_to_word(img,addr)
                print(
                    f"  PTR@0x{addr:08X}=0x{val:08X} "
                    f"real literal xrefs={len(lx)}"
                )


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
        default="research/f2/work/reports/s13_5a23_b709_alice_owner_import_semantics.txt",
    )
    return p.parse_args()


def resolve(root:Path,s):
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
        banner("S13.5A.23 - B709 ALICE OWNER / IMPORT VENEER SEMANTICS AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice=verify(
            resolve(root,args.alice),"ALICE",
            ALICE_BASE,ALICE_SIZE,ALICE_SHA256
        )
        zimage=verify(
            resolve(root,args.zimage),"ZIMAGE",
            ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA256
        )
        images=[alice,zimage]

        root_ok=root_mapper_full_audit(zimage)
        resolved=veneer_audit(alice,zimage,images)
        owner_ok=owner_audit(alice,resolved)
        callers_and_args(alice,resolved)
        output_array_audit(images)
        target_callers(images,resolved)

        banner("H. DECISION GATE")

        print(
            f"root mapper full-range correction = "
            f"{'PASS' if root_ok else 'OPEN'}"
        )
        print(
            f"B709 owner dataflow              = "
            f"{'PASS' if owner_ok else 'OPEN'}"
        )

        for label in [
            "A_COUNT_CANDIDATE","B_ENUM_CANDIDATE","C_CHILD_TRANSFORM"
        ]:
            v,func,cl=resolved.get(label,(None,None,None))
            print()
            print(f"{label}:")
            print(
                f"  veneer resolved = "
                f"{'PASS' if v and v.recognized and v.target_ptr is not None else 'OPEN'}"
            )
            if v and v.target_ptr is not None:
                print(f"  target          = 0x{v.target_ptr:08X}")
            if cl:
                kind,scores,exact=cl
                print(f"  semantic class  = {exact or kind}")

        print()
        if root_ok:
            print("[FACT] A.22's 'B709 root-category mapper = OPEN' is SUPERSEDED.")
            print("[FACT] F02F9D34 returns the zero-based direct-child index under B709")
            print("       for a descendant ID whose ancestry reaches B709.")

        if owner_ok:
            print("[FACT] ALICE 0x10313998 explicitly materializes the B709 child set")
            print("       into a stack u16 buffer, then transforms each child with selector 8.")
            print("       This is the strongest current static path to children[B709].")

        print()
        print("NEXT DECISION:")
        print("  If veneer A resolves to child-count semantics and veneer B to")
        print("  child-enumeration semantics, promote 0x10313998 to a FACT caller of:")
        print("      count = GET_CHILD_COUNT(B709)")
        print("      ENUM_CHILD_IDS(B709, buffer)")
        print("  Then follow only the real target of veneer B / registry bootstrap")
        print("  to recover exact B709 child IDs, or use any statically backed table")
        print("  exposed by that target.")
        print()
        print("DO NOT PROMOTE:")
        print("  B709 itself as 'Multimedia'; it is a higher/root category anchor.")
        print("  F00B7994 values as child IDs until veneer C semantics are proven.")
        print("  any B709 child as Multimedia until Image/Audio/UI ownership ties it.")
        print()
        print("STILL UNKNOWN:")
        print("  exact children[0xB709]")
        print("  numeric visible Multimedia ID")
        print("  FM Radio child ID")
        print("  exact Multimedia children[]")
        print("  whether 0x8928 is absent vs present-but-filtered in Multimedia")
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
