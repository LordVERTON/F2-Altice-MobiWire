#!/usr/bin/env python3
"""
S13.5A.22 - GET_PARENT_ID / B709 ROOT-CATEGORY CHILD AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.21 resolved the wrapper chain:

    0x10319094
      -> ALICE veneer 0x102FA0CC
      -> ZIMAGE Thumb 0xF02F9D34

The body at 0xF02F9D34 repeatedly calls 0xF02FBC24, compares against root
ID 0xB709, then scans the children[] of 0xB709 and returns a zero-based
index. If ancestry terminates at 0, it returns 0xFF; wrapper 0x10319094
then converts 0xFF -> 0x2E.

Earlier canonical dumps also strongly indicate that 0xF02FBC24 performs
ID -> parent-ID lookup:
  - direct parent field at registry-record +0x00 when nonzero;
  - otherwise reverse scan of registry children[];
  - matching parent dense-index converted back to ID via 0xF02FEFB4.

This pass makes that contract explicit and then attacks 0xB709 directly.

Goals:
  A. canonical validation;
  B. exact disassembly and structural proof of F02FBC24 = GET_PARENT_ID;
  C. exact disassembly and structural proof of F02F9D34 =
       DESCENDANT_ID -> DIRECT_CHILD_INDEX_UNDER_B709;
  D. validate F02FEFB4 inverse index->ID semantics around the callsite;
  E. census all static 0xB709 occurrences and code owners;
  F. find direct provider calls involving constant parent 0xB709:
       GET_CHILD_COUNT F02D8870
       ENUM_CHILD_IDS  F032ACDC
       GET_CHILD_META  F02F9CCC
  G. inspect all real xrefs/writers for registry globals F007F044/F007F048;
  H. attempt conservative recovery of a static/bootstrap backing pointer for
     the registry if a literal store is statically visible;
  I. rank only structurally referenced candidate child arrays containing
     resolver IDs near B709 ownership;
  J. decision gate.

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

GET_PARENT = 0xF02FBC24
ROOT_INDEX_MAPPER = 0xF02F9D34
INDEX_TO_ID = 0xF02FEFB4
PARENT_TO_INDEX = 0xF02E01B0

ROOT_ID = 0xB709

REGISTRY_GLOBAL = 0xF007F044
LOOKUP_GLOBAL = 0xF007F048

GET_CHILD_COUNT = 0xF02D8870
ENUM_CHILD_IDS = 0xF032ACDC
GET_CHILD_META = 0xF02F9CCC

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
        return self.base+len(self.data)
    def contains(self,addr:int):
        a=addr & ~1
        return self.base <= a < self.end
    def off(self,addr:int):
        return (addr & ~1)-self.base


@dataclass
class ResolverRow:
    index:int
    addr:int
    menu_id:int
    field2:int
    callback_ptr:int


def banner(s):
    print()
    print("="*140)
    print(s)
    print("="*140)


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


def verify(path:Path,name,base,size,expected_sha):
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
    if got.lower()!=expected_sha.lower():
        raise SystemExit(f"ABORT: {name} SHA256 mismatch")
    print(f"[PASS] canonical {name}")
    return Image(name,data,base)


def image_for(images,addr):
    a=addr & ~1
    for img in images:
        if img.base<=a<img.end:
            return img
    return None


def decode1(img,addr,mode="THUMB"):
    a=addr & ~1
    if not img.contains(a):
        return None
    md=md_t if mode=="THUMB" else md_a
    xs=list(md.disasm(img.data[img.off(a):img.off(a)+4],a,count=1))
    return xs[0] if xs else None


def dis(img,start,end,mode="THUMB"):
    start &= ~1
    if not img.contains(start):
        return []
    md=md_t if mode=="THUMB" else md_a
    end=min(end,img.end)
    return [x for x in md.disasm(img.data[img.off(start):img.off(start)+(end-start)],start) if x.address<end]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<9} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b","bl","blx"} or not x.operands:
        return None
    op=x.operands[0]
    return (op.imm & 0xFFFFFFFF) if op.type==ARM_OP_IMM else None


def literal_load(img,x,mode="THUMB"):
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


def print_region(img,start,end,mode="THUMB",marks=None):
    marks=marks or set()
    for x in dis(img,start,end,mode):
        notes=[]
        t=direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")
        li=literal_load(img,x,mode)
        if li:
            tags=[]
            if li[3]==REGISTRY_GLOBAL: tags.append("REGISTRY_GLOBAL")
            if li[3]==LOOKUP_GLOBAL: tags.append("LOOKUP_GLOBAL")
            if li[3]==ROOT_ID: tags.append("ROOT_B709")
            notes.append(
                f"literal@0x{li[2]:08X}=0x{li[3]:08X}->{li[0]}"
                + (f" <{'|'.join(tags)}>" if tags else "")
            )
        mark=">>>" if x.address in marks else "   "
        print(mark,fmt(x)+((" ; "+", ".join(notes)) if notes else ""))


def all_hits(data,needle):
    out=[]
    pos=0
    while True:
        pos=data.find(needle,pos)
        if pos<0:
            return out
        out.append(pos)
        pos+=1


def parse_resolver(zimage):
    rows=[]
    off=zimage.off(RESOLVER_BASE)
    for i in range(RESOLVER_COUNT):
        roff=off+i*RESOLVER_STRIDE
        rows.append(ResolverRow(
            i,
            RESOLVER_BASE+i*RESOLVER_STRIDE,
            u16(zimage.data,roff),
            u16(zimage.data,roff+2),
            u32(zimage.data,roff+4),
        ))
    return rows


def is_prologue(x):
    return bool(x and x.mnemonic=="push" and "lr" in x.op_str)


def is_return(x):
    return bool(
        x and (
            (x.mnemonic=="bx" and x.op_str.strip()=="lr")
            or (x.mnemonic=="pop" and "pc" in x.op_str)
        )
    )


def enclosing_function(img,target,back=0x500,forward=0x900):
    lo=max(img.base,target-back)&~1
    cands=[]
    for a in range(lo,target+1,2):
        x=decode1(img,a,"THUMB")
        if not is_prologue(x):
            continue
        xs=dis(img,a,min(img.end,a+forward),"THUMB")
        if any(z.address==target for z in xs):
            cands.append(a)
    if not cands:
        return target,min(img.end,target+0x100)
    start=cands[-1]
    xs=dis(img,start,min(img.end,start+forward),"THUMB")
    passed=False
    for x in xs:
        if x.address>=target:
            passed=True
        if passed and is_return(x):
            return start,x.address+len(x.bytes)
    return start,min(img.end,start+0x180)


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
        if not xs: continue
        x=xs[0]
        if x.mnemonic not in {"bl","blx"}: continue
        t=direct_target(x)
        if t is not None and (t&~1)==(target&~1):
            out.append(("THUMB",x))
    for off in range(0,len(img.data)-4,4):
        xs=list(md_a.disasm(img.data[off:off+4],img.base+off,count=1))
        if not xs: continue
        x=xs[0]
        if x.mnemonic not in {"bl","blx"}: continue
        t=direct_target(x)
        if t is not None and (t&~1)==(target&~1):
            out.append(("ARM",x))
    uniq={(m,x.address):(m,x) for m,x in out}
    return [uniq[k] for k in sorted(uniq,key=lambda q:(q[1],q[0]))]


def real_literal_xrefs_for_value(img,value):
    out=[]
    pat=struct.pack("<I",value&0xFFFFFFFF)
    for off in all_hits(img.data,pat):
        word=img.base+off
        for a in range(max(img.base,word-0x500)&~1,word+1,2):
            x=decode1(img,a,"THUMB")
            li=literal_load(img,x,"THUMB") if x else None
            if li and li[2]==word and li[3]==value:
                out.append(("THUMB",x,word))
        for a in range(max(img.base,word-0x1000)&~3,word+1,4):
            x=decode1(img,a,"ARM")
            li=literal_load(img,x,"ARM") if x else None
            if li and li[2]==word and li[3]==value:
                out.append(("ARM",x,word))
    uniq={(m,x.address,w):(m,x,w) for m,x,w in out}
    return [uniq[k] for k in sorted(uniq)]


def function_markers(img,start,end):
    xs=dis(img,start,end,"THUMB")
    calls=defaultdict(list)
    literals=defaultdict(list)
    for x in xs:
        t=direct_target(x)
        if x.mnemonic in {"bl","blx"} and t is not None:
            calls[t&~1].append(x)
        li=literal_load(img,x,"THUMB")
        if li:
            literals[li[3]].append(x)
    return xs,calls,literals


# -----------------------------------------------------------------------------
# Backward constant flow
# -----------------------------------------------------------------------------

def reg_written(x):
    if not x.operands:
        return None
    op=x.operands[0]
    return op.reg if op.type==ARM_OP_REG else None


def reg_id_by_name(insns,name):
    for x in insns:
        for op in x.operands:
            if op.type==ARM_OP_REG and x.reg_name(op.reg)==name:
                return op.reg
    return None


def backward_const(img,insns,before_addr,regname,depth=0):
    if depth>10:
        return ("UNKNOWN",None,"depth")
    hist=[x for x in insns if x.address<before_addr]
    rid=reg_id_by_name(hist,regname)
    if rid is None:
        return ("UNKNOWN",None,f"{regname} unseen")
    caller_saved=regname in {"r0","r1","r2","r3","r12","ip","lr"}

    for i in range(len(hist)-1,-1,-1):
        x=hist[i]
        if x.mnemonic in {"bl","blx"} and caller_saved:
            return ("UNKNOWN",None,f"{regname} clobbered by call @0x{x.address:08X}")
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
                k,v,d=backward_const(img,hist[:i+1],x.address,src,depth+1)
                return (k,v,f"{regname}<-{src}@0x{x.address:08X} <- {d}")
        if x.mnemonic in {"add","adds","sub","subs"}:
            imm=None
            for op in ops[1:]:
                if op.type==ARM_OP_IMM:
                    imm=op.imm
                    break
            if imm is not None:
                k,v,d=backward_const(img,hist[:i],x.address,regname,depth+1)
                if k=="CONST":
                    v=(v+imm)&0xFFFFFFFF if x.mnemonic.startswith("add") else (v-imm)&0xFFFFFFFF
                    return ("CONST",v,f"{d}; {x.mnemonic}#{imm}@0x{x.address:08X}")
            return ("EXPR",None,f"{x.mnemonic} {x.op_str}")
        if x.mnemonic.startswith("ldr"):
            return ("MEM",None,f"{x.mnemonic} {x.op_str}@0x{x.address:08X}")
        return ("UNKNOWN",None,f"writer {x.mnemonic} {x.op_str}@0x{x.address:08X}")
    return ("ARG",None,regname)


# -----------------------------------------------------------------------------
# Semantic audits
# -----------------------------------------------------------------------------

def audit_get_parent(zimage):
    banner("B. F02FBC24 GET_PARENT_ID AUDIT")

    start,end=enclosing_function(zimage,GET_PARENT)
    print(f"function = 0x{start:08X}..0x{end:08X}")
    print_region(
        zimage,start,end,"THUMB",
        {
            0xF02FBC26,0xF02FBC34,0xF02FBC3A,0xF02FBC40,
            0xF02FBC6C,0xF02FBC6E,0xF02FBC76,0xF02FBC7A,
        }
    )

    xs,calls,lits=function_markers(zimage,start,end)

    checks={
        "calls PARENT_TO_INDEX": bool(calls.get(PARENT_TO_INDEX)),
        "loads LOOKUP_GLOBAL": bool(lits.get(LOOKUP_GLOBAL)),
        "loads REGISTRY_GLOBAL": bool(lits.get(REGISTRY_GLOBAL)),
        "calls INDEX_TO_ID": bool(calls.get(INDEX_TO_ID)),
        "reads record +0 direct parent candidate":
            any(x.address==0xF02FBC40 and x.mnemonic=="ldrh" for x in xs),
        "searches child arrays":
            any(x.address==0xF02FBC68 and x.mnemonic=="ldr" for x in xs)
            and any(x.address==0xF02FBC6C and x.mnemonic=="ldrh" for x in xs),
        "compares candidate child to original ID":
            any(x.address==0xF02FBC6E and x.mnemonic.startswith("cmp") for x in xs),
    }

    print()
    for k,v in checks.items():
        print(f"{k:<48} = {'PASS' if v else 'OPEN'}")

    contract_pass=all(checks.values())

    print()
    if contract_pass:
        print("[FACT CANDIDATE] F02FBC24 implements GET_PARENT_ID(id):")
        print("  1) map id -> dense registry index;")
        print("  2) read registry_record[index]+0x00;")
        print("  3) if nonzero, return that value as parent ID;")
        print("  4) otherwise scan registry child arrays for the input ID;")
        print("  5) when found, convert owning parent dense index -> ID via F02FEFB4.")
    else:
        print("[OPEN] One or more structural markers are missing; inspect exact disassembly.")

    return contract_pass,start,end


def audit_root_mapper(zimage,parent_fact):
    banner("C. F02F9D34 ROOT-CATEGORY MAPPER AUDIT")

    start,end=enclosing_function(zimage,ROOT_INDEX_MAPPER)
    print(f"function = 0x{start:08X}..0x{end:08X}")
    print_region(
        zimage,start,end,"THUMB",
        {
            0xF02F9D38,0xF02F9D3C,0xF02F9D44,0xF02F9D4C,
            0xF02F9D54,0xF02F9D62,0xF02F9D72,0xF02F9D90,
        }
    )

    xs,calls,lits=function_markers(zimage,start,end)

    checks={
        "calls GET_PARENT_ID repeatedly": len(calls.get(GET_PARENT,[]))>=2,
        "loads root B709": bool(lits.get(ROOT_ID)),
        "loads registry global": bool(lits.get(REGISTRY_GLOBAL)),
        "calls PARENT_TO_INDEX(B709 path)": bool(calls.get(PARENT_TO_INDEX)),
        "returns FF on broken ancestry":
            any(x.address==0xF02F9D54 and x.mnemonic in {"mov","movs"} for x in xs),
        "scans B709 child array":
            any(x.address==0xF02F9D6E and x.mnemonic=="ldr" for x in xs)
            and any(x.address==0xF02F9D72 and x.mnemonic=="ldrh" for x in xs),
        "returns zero-based scan index":
            any(x.address==0xF02F9D90 and x.mnemonic in {"mov","movs"} for x in xs),
    }

    print()
    for k,v in checks.items():
        print(f"{k:<48} = {'PASS' if v else 'OPEN'}")

    contract_pass=parent_fact and all(checks.values())

    print()
    if contract_pass:
        print("[FACT CANDIDATE] F02F9D34(id) = direct-child index under root 0xB709:")
        print("  parent = GET_PARENT_ID(id)")
        print("  while parent != 0xB709:")
        print("      child  = parent")
        print("      parent = GET_PARENT_ID(parent)")
        print("      if parent == 0: return 0xFF")
        print("  return index of child in children[0xB709]")
    else:
        print("[OPEN] Root-category semantic proof incomplete.")

    return contract_pass,start,end


def audit_index_to_id(zimage):
    banner("D. F02FEFB4 INDEX_TO_ID SUPPORT AUDIT")

    start,end=enclosing_function(zimage,INDEX_TO_ID)
    print(f"function = 0x{start:08X}..0x{end:08X}")
    print_region(zimage,start,end,"THUMB",{INDEX_TO_ID})

    xs,calls,lits=function_markers(zimage,start,end)
    print()
    print(f"loads LOOKUP_GLOBAL = {'PASS' if lits.get(LOOKUP_GLOBAL) else 'OPEN'}")
    print("NOTE: F02FEFB4 is used by F02FBC24 exactly after finding an owning")
    print("registry dense index, supporting inverse dense-index -> public ID semantics.")


def b709_occurrence_audit(images):
    banner("E. STATIC 0xB709 OCCURRENCE / OWNER CENSUS")

    pat16=struct.pack("<H",ROOT_ID)
    pat32=struct.pack("<I",ROOT_ID)

    total16=0
    total32=0

    for img in images:
        h16=all_hits(img.data,pat16)
        h32=all_hits(img.data,pat32)
        total16 += len(h16)
        total32 += len(h32)

        print()
        print(f"{img.name}: raw u16 B709={len(h16)} raw u32 B709={len(h32)}")

        refs=real_literal_xrefs_for_value(img,ROOT_ID)
        print(f"  real literal xrefs to 0x0000B709 = {len(refs)}")
        for mode,x,w in refs[:80]:
            print(f"    {mode} {fmt(x)} literal-word@0x{w:08X}")
            if mode=="THUMB":
                fs,fe=enclosing_function(img,x.address)
                print(f"      function=0x{fs:08X}..0x{fe:08X}")
                print_region(
                    img,max(fs,x.address-0x18),min(fe,x.address+0x30),
                    "THUMB",{x.address}
                )

    print()
    print(f"TOTAL raw u16 B709 = {total16}")
    print(f"TOTAL raw u32 B709 = {total32}")


def provider_b709_calls(images):
    banner("F. DIRECT PROVIDER CALLS WITH CONSTANT PARENT 0xB709")

    providers=[
        ("GET_CHILD_COUNT",GET_CHILD_COUNT),
        ("ENUM_CHILD_IDS",ENUM_CHILD_IDS),
        ("GET_CHILD_META",GET_CHILD_META),
    ]

    hits=[]

    for name,target in providers:
        print()
        print(f"### {name} 0x{target:08X}")

        for img in images:
            calls=scan_direct_calls(img,target)
            print(f"{img.name}: direct calls={len(calls)}")

            for mode,x in calls:
                if mode!="THUMB":
                    continue
                fs,fe=enclosing_function(img,x.address)
                ins=dis(img,fs,fe,"THUMB")
                kind,val,desc=backward_const(img,ins,x.address,"r0")
                if kind=="CONST":
                    print(
                        f"  call@0x{x.address:08X} r0=0x{val:08X} "
                        f"{'<B709>' if val==ROOT_ID else ''} via {desc}"
                    )
                    if val==ROOT_ID:
                        hits.append((name,img,x,fs,fe))
                else:
                    print(
                        f"  call@0x{x.address:08X} r0={kind}: {desc}"
                    )

    print()
    print(f"provider calls with exact B709 = {len(hits)}")

    return hits


def registry_global_xrefs(images):
    banner("G. REGISTRY GLOBAL XREF / WRITE AUDIT")

    results=[]

    for global_addr,gname in [
        (REGISTRY_GLOBAL,"REGISTRY_GLOBAL"),
        (LOOKUP_GLOBAL,"LOOKUP_GLOBAL"),
    ]:
        print()
        print(f"### {gname} 0x{global_addr:08X}")

        for img in images:
            refs=real_literal_xrefs_for_value(img,global_addr)
            print(f"{img.name}: real literal xrefs={len(refs)}")

            for mode,x,w in refs:
                if mode!="THUMB":
                    print(f"  {mode} {fmt(x)}")
                    continue

                fs,fe=enclosing_function(img,x.address)
                print(f"  {fmt(x)} function=0x{fs:08X}..0x{fe:08X}")

                xs=dis(img,x.address,min(fe,x.address+0x60),"THUMB")
                li=literal_load(img,x,"THUMB")
                if not li:
                    continue
                base_reg=li[1]
                aliases={base_reg}

                for y in xs[1:]:
                    # propagate register aliases
                    if y.mnemonic in {"mov","movs"} and len(y.operands)>=2:
                        d,s=y.operands[0],y.operands[1]
                        if (
                            d.type==ARM_OP_REG and s.type==ARM_OP_REG
                            and s.reg in aliases
                        ):
                            aliases.add(d.reg)

                    # read/write through global-address register
                    if len(y.operands)>=2 and y.operands[1].type==ARM_OP_MEM:
                        mem=y.operands[1].mem
                        if mem.base in aliases:
                            if y.mnemonic.startswith("ldr"):
                                print(f"      READ  {fmt(y)}")
                            elif y.mnemonic.startswith("str"):
                                print(f"      WRITE {fmt(y)}")
                                results.append((gname,img,x,y,fs,fe))

                    # str src,[alias]
                    if (
                        y.mnemonic.startswith("str")
                        and len(y.operands)>=2
                        and y.operands[1].type==ARM_OP_MEM
                        and y.operands[1].mem.base in aliases
                    ):
                        results.append((gname,img,x,y,fs,fe))

                    if y.mnemonic in {"bl","blx"}:
                        aliases={
                            r for r in aliases
                            if y.reg_name(r) not in {"r0","r1","r2","r3","r12","ip","lr"}
                        }

                    if is_return(y):
                        break

    print()
    print(f"potential write-through-global events = {len(results)}")
    return results


def candidate_structural_arrays(images,rows):
    banner("H. STRUCTURALLY REFERENCED RESOLVER-ID ARRAY CANDIDATES")

    resolver_ids={r.menu_id for r in rows}
    known=set(KNOWN_IDS)

    candidates=[]

    # Search exact pointer literals to aligned/halfword-aligned regions with
    # 2..32 consecutive resolver IDs. Require at least 2 resolver IDs.
    for data_img in images:
        for off in range(0,len(data_img.data)-4,2):
            vals=[]
            for i in range(16):
                v=u16(data_img.data,off+i*2)
                if v is None:
                    break
                if v not in resolver_ids:
                    break
                vals.append(v)

            if len(vals)<2:
                continue

            start=data_img.base+off

            # Require an exact 32-bit pointer word to start somewhere in images,
            # and a real code literal xref to that pointer word.
            ptr_refs=[]
            pat=struct.pack("<I",start)
            for code_img in images:
                for poff in all_hits(code_img.data,pat):
                    word=code_img.base+poff
                    # validate true literal xref
                    xrefs=[]
                    for a in range(max(code_img.base,word-0x500)&~1,word+1,2):
                        x=decode1(code_img,a,"THUMB")
                        li=literal_load(code_img,x,"THUMB") if x else None
                        if li and li[2]==word and li[3]==start:
                            xrefs.append(x)
                    if xrefs:
                        ptr_refs.append((code_img,word,xrefs))

            if not ptr_refs:
                continue

            score=len(vals)*2
            if known & set(vals):
                score += 6

            candidates.append((score,data_img,start,vals,ptr_refs))

    # dedup start
    uniq={}
    for c in candidates:
        key=(c[1].name,c[2])
        if key not in uniq or c[0]>uniq[key][0]:
            uniq[key]=c

    ranked=sorted(uniq.values(),key=lambda c:(-c[0],c[1].name,c[2]))

    print(f"candidates = {len(ranked)}")

    for score,img,start,vals,refs in ranked[:100]:
        print()
        print(
            f"SCORE={score} {img.name} @0x{start:08X}: "
            + " ".join(
                f"{v:04X}"
                + (f"<{KNOWN_IDS[v]}>" if v in KNOWN_IDS else "")
                for v in vals
            )
        )
        for code_img,word,xrefs in refs:
            print(
                f"  pointer word {code_img.name}@0x{word:08X}, "
                f"real xrefs={len(xrefs)}"
            )
            for x in xrefs[:8]:
                fs,fe=enclosing_function(code_img,x.address)
                print(
                    f"    {fmt(x)} function=0x{fs:08X}"
                )

    print()
    print("IMPORTANT: these remain candidates only; exact B709 ownership is required")
    print("before treating any one as children[0xB709].")

    return ranked


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
        default="research/f2/work/reports/s13_5a22_get_parent_b709_root_category.txt",
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
        banner("S13.5A.22 - GET_PARENT_ID / B709 ROOT-CATEGORY CHILD AUDIT")
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
        rows=parse_resolver(zimage)

        parent_fact,parent_start,parent_end=audit_get_parent(zimage)
        mapper_fact,mapper_start,mapper_end=audit_root_mapper(zimage,parent_fact)
        audit_index_to_id(zimage)
        b709_occurrence_audit(images)
        provider_hits=provider_b709_calls(images)
        global_writes=registry_global_xrefs(images)
        arrays=candidate_structural_arrays(images,rows)

        banner("I. DECISION GATE")
        print(f"GET_PARENT_ID structural contract = {'PASS' if parent_fact else 'OPEN'}")
        print(f"B709 root-category mapper contract = {'PASS' if mapper_fact else 'OPEN'}")
        print(f"exact provider calls with B709     = {len(provider_hits)}")
        print(f"registry-global write events       = {len(global_writes)}")
        print(f"referenced resolver-ID arrays      = {len(arrays)}")
        print()

        if parent_fact:
            print("[FACT] F02FBC24 is eligible to name GET_PARENT_ID(id).")

        if mapper_fact:
            print("[FACT] F02F9D34 maps any descendant ID whose ancestry reaches")
            print("       0xB709 to the zero-based index of its direct child under B709.")
            print("       If ancestry cannot reach B709, it returns 0xFF.")
            print()
            print("[FACT] 0x10319094 therefore wraps a ROOT-CATEGORY INDEX lookup:")
            print("       category_index = F02F9D34(id)")
            print("       if category_index == 0xFF: category_index = 0x2E")

        print()
        if provider_hits:
            print("[PASS] A direct provider call with constant B709 was recovered.")
            print("[NEXT] Its caller context is the strongest path to exact children[0xB709].")
        elif global_writes:
            print("[NEXT] Inspect registry bootstrap write(s) above to recover the")
            print("       backing registry records and exact B709 children statically.")
        else:
            print("[OPEN] Exact B709 child-array backing pointer not yet recovered.")
            print("[NEXT] Follow B709 code-owner xrefs or runtime-registry bootstrap only.")

        print()
        print("DO NOT PROMOTE:")
        print("  any raw resolver-ID run as B709 children without ownership;")
        print("  any root-category index to 'Multimedia' without a visible-path binding;")
        print("  nearby 0x89xx values as FM Radio.")
        print()
        print("STILL UNKNOWN:")
        print("  numeric visible Multimedia ID")
        print("  FM Radio child ID")
        print("  exact Multimedia children[]")
        print("  exact children[0xB709] unless recovered above")
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
