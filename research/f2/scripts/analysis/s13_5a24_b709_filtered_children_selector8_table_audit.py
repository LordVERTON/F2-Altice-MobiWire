#!/usr/bin/env python3
"""
S13.5A.24 - B709 FILTERED CHILDREN / SELECTOR-8 TABLE CONTRACT AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.23 proved:
  - F02F9D34(id) returns the zero-based direct-child index under root 0xB709
    for an ID whose ancestry reaches 0xB709.
  - ALICE 0x10313998 materializes B709 children to a stack u16 buffer and
    stores veneer_C(child, 8) into F00B7994[i].
  - 0x10319094 was previously truncated. Its full body is:
        idx = F02F9D34(id)
        if idx == 0xFF:
            return 0x2E
        return F00B7994[idx]

A.23's generic target classifier also mislabeled veneer B and C as COUNT_LIKE
because its CFG omitted loop bodies. This pass deliberately uses FIXED-RANGE
linear disassembly for the three target functions.

Targets:
  veneer A 0x102FC51C -> F02D53DD / body F02D53DC..F02D5422
  veneer B 0x102FC3CC -> F02AE865 / body F02AE864..F02AE8C0
  veneer C 0x102FC20C -> F0316CE1 / body F0316CE0..F0316D6C

Known helper:
  F02D5458 = child filter predicate used by A/B.

Static selector table:
  count/global @ F03AD11C
  table base   @ F03AD120

Goals:
  A. validate canonical ALICE/ZIMAGE;
  B. fixed-range decode A/B/C, no CFG omission;
  C. prove A counts children accepted by the same F02D5458 predicate;
  D. prove B emits accepted child IDs to a compact u16 output buffer;
  E. classify F02D5458 neutrally from its exact body/callers;
  F. prove full 0x10319094 composition including F00B7994 lookup;
  G. recover selector-table count and raw structure at F03AD120;
  H. rank plausible static record strides using key-like u16 IDs;
  I. locate known resolver/root IDs inside selector-table region;
  J. inspect selectors 1/5/8 call sites and table access arithmetic;
  K. decision gate.

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

ROOT_ID = 0xB709
ROOT_MAPPER = 0xF02F9D34
GET_PARENT_ID = 0xF02FBC24
PARENT_TO_INDEX = 0xF02E01B0
REGISTRY_GLOBAL = 0xF007F044

VENEER_A = 0x102FC51C
TARGET_A = 0xF02D53DC
END_A = 0xF02D5422

VENEER_B = 0x102FC3CC
TARGET_B = 0xF02AE864
END_B = 0xF02AE8C0

VENEER_C = 0x102FC20C
TARGET_C = 0xF0316CE0
END_C = 0xF0316D6C

FILTER_PRED = 0xF02D5458

OWNER = 0x10313998
OUTPUT_ARRAY = 0xF00B7994
WRAPPER = 0x10319094

SELECTOR_COUNT_ADDR = 0xF03AD11C
SELECTOR_TABLE_ADDR = 0xF03AD120

RESOLVER_BASE = 0xF0345E68
RESOLVER_COUNT = 58
RESOLVER_STRIDE = 8

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0xB6FD: "ROOT_FAMILY",
    0xB6FE: "ROOT_FAMILY",
    0xB6FF: "ROOT_FAMILY",
    0xB701: "ROOT_FAMILY",
    0xB702: "ROOT_FAMILY",
    0xB703: "ROOT_FAMILY",
    0xB708: "ROOT_FAMILY",
    0xB709: "ROOT",
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
    name:str
    data:bytes
    base:int
    @property
    def end(self):
        return self.base+len(self.data)
    def contains(self,addr:int):
        a=addr&~1
        return self.base<=a<self.end
    def off(self,addr:int):
        return (addr&~1)-self.base


@dataclass
class ResolverRow:
    index:int
    addr:int
    menu_id:int
    field2:int
    callback:int


def banner(s):
    print()
    print("="*144)
    print(s)
    print("="*144)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u8(data,off):
    if off<0 or off+1>len(data):
        return None
    return data[off]


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
    a=addr&~1
    for img in images:
        if img.base<=a<img.end:
            return img
    return None


def decode1(img,addr,mode="THUMB"):
    a=(addr&~1) if mode=="THUMB" else (addr&~3)
    if not img.contains(a):
        return None
    md=md_t if mode=="THUMB" else md_a
    xs=list(md.disasm(img.data[img.off(a):img.off(a)+4],a,count=1))
    return xs[0] if xs else None


def dis(img,start,end,mode="THUMB"):
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
    return (op.imm&0xFFFFFFFF) if op.type==ARM_OP_IMM else None


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
            tag=""
            if (t&~1)==PARENT_TO_INDEX: tag="<PARENT_TO_INDEX>"
            elif (t&~1)==FILTER_PRED: tag="<FILTER_PRED>"
            elif (t&~1)==ROOT_MAPPER: tag="<ROOT_MAPPER>"
            notes.append(f"target=0x{t:08X}{tag}")
        li=literal_load(img,x,mode)
        if li:
            tags=[]
            if li[3]==REGISTRY_GLOBAL: tags.append("REGISTRY_GLOBAL")
            if li[3]==ROOT_ID: tags.append("B709")
            if li[3]==OUTPUT_ARRAY: tags.append("F00B7994")
            if li[3]==SELECTOR_TABLE_ADDR: tags.append("SELECTOR_TABLE")
            if li[3]==SELECTOR_COUNT_ADDR: tags.append("SELECTOR_COUNT")
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


def parse_resolver(zimage):
    rows=[]
    off=zimage.off(RESOLVER_BASE)
    for i in range(RESOLVER_COUNT):
        o=off+i*RESOLVER_STRIDE
        rows.append(ResolverRow(
            i,
            RESOLVER_BASE+i*RESOLVER_STRIDE,
            u16(zimage.data,o),
            u16(zimage.data,o+2),
            u32(zimage.data,o+4),
        ))
    return rows


def nearest_thumb_prologue(img,target,back=0x120):
    lo=max(img.base,target-back)&~1
    cands=[]
    for a in range(lo,target+1,2):
        x=decode1(img,a,"THUMB")
        if x and x.mnemonic=="push" and "lr" in x.op_str:
            cands.append(a)
    return cands[-1] if cands else target


def first_return_after(img,start,max_end):
    for x in dis(img,start,max_end,"THUMB"):
        if (x.mnemonic=="bx" and x.op_str.strip()=="lr") or (x.mnemonic=="pop" and "pc" in x.op_str):
            return x.address+len(x.bytes)
    return max_end


def has_target(xs,target):
    return any(
        x.mnemonic in {"bl","blx"}
        and direct_target(x) is not None
        and (direct_target(x)&~1)==(target&~1)
        for x in xs
    )


def addr_map(xs):
    return {x.address:x for x in xs}


def semantic_audit_ab(zimage):
    banner("B. FIXED-RANGE VENEER A — FILTERED CHILD COUNT CANDIDATE")
    print_region(
        zimage,TARGET_A,END_A,"THUMB",
        {0xF02D53DC,0xF02D53EE,0xF02D5406,0xF02D541A,0xF02D541E}
    )
    a=dis(zimage,TARGET_A,END_A,"THUMB")

    print()
    a_checks={
        "maps parent ID to registry index": has_target(a,PARENT_TO_INDEX),
        "loads registry global": any(
            (literal_load(zimage,x,"THUMB") or (None,None,None,None))[3]==REGISTRY_GLOBAL
            for x in a
        ),
        "reads raw child_count (+2)": any(
            x.mnemonic=="ldrh" and "#2" in x.op_str for x in a
        ),
        "reads child array (+0xC)": any(
            x.mnemonic=="ldr" and "#0xc" in x.op_str.lower() for x in a
        ),
        "loads child u16": any(x.mnemonic=="ldrh" for x in a),
        "calls F02D5458": has_target(a,FILTER_PRED),
        "compares filter result with zero": any(
            x.mnemonic=="cmp" and "r0, #0" in x.op_str for x in a
        ),
        "returns accumulator r5": any(
            x.mnemonic in {"mov","movs"} and "r0, r5" in x.op_str for x in a
        ),
    }
    for k,v in a_checks.items():
        print(f"{k:<46} = {'PASS' if v else 'OPEN'}")

    banner("C. FIXED-RANGE VENEER B — FILTERED CHILD ENUMERATION")
    print_region(
        zimage,TARGET_B,END_B,"THUMB",
        {0xF02AE864,0xF02AE87A,0xF02AE87E,0xF02AE880,0xF02AE884,
         0xF02AE898,0xF02AE89A,0xF02AE8A2,0xF02AE8BC}
    )
    b=dis(zimage,TARGET_B,END_B,"THUMB")
    bm=addr_map(b)

    b_checks={
        "maps parent ID to registry index": has_target(b,PARENT_TO_INDEX),
        "loads registry global": any(
            (literal_load(zimage,x,"THUMB") or (None,None,None,None))[3]==REGISTRY_GLOBAL
            for x in b
        ),
        "reads child pointer +0xC": any(
            x.mnemonic=="ldr" and "#0xc" in x.op_str.lower() for x in b
        ),
        "loads raw child u16": any(
            x.mnemonic=="ldrh" and x.address in range(0xF02AE87C,0xF02AE8A0)
            for x in b
        ),
        "calls same F02D5458 predicate": has_target(b,FILTER_PRED),
        "accept path requires predicate == 0": (
            bm.get(0xF02AE884) is not None
            and bm[0xF02AE884].mnemonic=="cmp"
            and "r0, #0" in bm[0xF02AE884].op_str
            and bm.get(0xF02AE886) is not None
            and bm[0xF02AE886].mnemonic=="bne"
        ),
        "copies accepted child ID to u16 output": (
            bm.get(0xF02AE8A2) is not None and bm[0xF02AE8A2].mnemonic=="strh"
        ),
        "increments compact output count r5": any(
            x.mnemonic in {"add","adds"} and "r5" in x.op_str and "#1" in x.op_str
            for x in b
        ),
        "returns output count r5": (
            bm.get(0xF02AE8BC) is not None
            and bm[0xF02AE8BC].mnemonic in {"mov","movs"}
            and "r0, r5" in bm[0xF02AE8BC].op_str
        ),
    }
    print()
    for k,v in b_checks.items():
        print(f"{k:<46} = {'PASS' if v else 'OPEN'}")

    a_ok=all(a_checks.values())
    b_ok=all(b_checks.values())

    print()
    if a_ok:
        print("[STRONG/FACT-SHAPE] F02D53DC counts children accepted by F02D5458.")
    if b_ok:
        print("[FACT-SHAPE] F02AE864 emits accepted raw child IDs to a compact u16")
        print("             output array and returns the number emitted.")
    if a_ok and b_ok:
        print("[PASS] Veneer A and B share the SAME child-filter predicate.")
        print("       Neutral names:")
        print("         A = COUNT_FILTERED_CHILDREN(parent)")
        print("         B = ENUM_FILTERED_CHILD_IDS(parent, out_u16)")
        print("       'filtered' does NOT yet mean 'visible'; exact predicate semantics remain open.")

    return a_ok,b_ok


def filter_predicate_audit(zimage):
    banner("D. F02D5458 CHILD-FILTER PREDICATE")

    start=nearest_thumb_prologue(zimage,FILTER_PRED,0x100)
    end=first_return_after(zimage,start,min(zimage.end,start+0x180))

    print(f"nearest function = 0x{start:08X}..0x{end:08X}")
    print_region(zimage,start,end,"THUMB",{FILTER_PRED})

    xs=dis(zimage,start,end,"THUMB")
    calls=[]
    lits=[]
    for x in xs:
        t=direct_target(x)
        if x.mnemonic in {"bl","blx"} and t is not None:
            calls.append((x,t))
        li=literal_load(zimage,x,"THUMB")
        if li:
            lits.append((x,li))

    print()
    print(f"direct calls = {len(calls)}")
    for x,t in calls:
        print(f"  {fmt(x)} -> 0x{t:08X}")

    print(f"literal loads = {len(lits)}")
    for x,li in lits:
        print(f"  {fmt(x)} ; 0x{li[3]:08X}")

    # Census direct callers and how result is tested.
    callers=[]
    for off in range(0,len(zimage.data)-4,2):
        x=decode1(zimage,zimage.base+off,"THUMB")
        if not x or x.mnemonic not in {"bl","blx"}:
            continue
        t=direct_target(x)
        if t is not None and (t&~1)==FILTER_PRED:
            callers.append(x)

    print()
    print(f"direct callers of F02D5458 = {len(callers)}")
    for x in callers[:80]:
        nxt=dis(zimage,x.address+4,min(zimage.end,x.address+0x14),"THUMB")
        print(f"  call {fmt(x)}")
        for y in nxt[:4]:
            print(f"      {fmt(y)}")

    print()
    print("SEMANTIC RULE USED BY A/B:")
    print("  F02D5458(child) == 0  -> child is retained")
    print("  F02D5458(child) != 0  -> child is skipped")
    print("Neutral label only: CHILD_FILTER_PREDICATE / exclusion predicate.")
    print("Do not rename it VISIBLE/HIDDEN until its body proves that meaning.")

    return start,end


def wrapper_audit(alice):
    banner("E. FULL 0x10319094 COMPOSITION")

    start=WRAPPER
    end=0x103190AA
    print_region(
        alice,start,end,"THUMB",
        {0x10319096,0x1031909A,0x1031909E,0x103190A2,0x103190A4,0x103190A6}
    )
    xs=dis(alice,start,end,"THUMB")
    m=addr_map(xs)

    li=(literal_load(alice,m.get(0x103190A2),"THUMB") or (None,None,None,None))[3]

    checks={
        "calls root mapper veneer": (
            m.get(0x10319096) is not None and m[0x10319096].mnemonic=="blx"
        ),
        "tests sentinel 0xFF": (
            m.get(0x1031909A) is not None
            and m[0x1031909A].mnemonic=="cmp"
            and "#0xff" in m[0x1031909A].op_str.lower()
        ),
        "fallback returns 0x2E": (
            m.get(0x1031909E) is not None
            and m[0x1031909E].mnemonic in {"mov","movs"}
            and "#0x2e" in m[0x1031909E].op_str.lower()
        ),
        "loads F00B7994 on success path": li==OUTPUT_ARRAY,
        "scales index by 2": (
            m.get(0x103190A4) is not None
            and m[0x103190A4].mnemonic=="lsls"
            and "#1" in m[0x103190A4].op_str
        ),
        "returns F00B7994[index] u16": (
            m.get(0x103190A6) is not None
            and m[0x103190A6].mnemonic=="ldrh"
        ),
    }

    print()
    for k,v in checks.items():
        print(f"{k:<46} = {'PASS' if v else 'OPEN'}")

    ok=all(checks.values())

    if ok:
        print()
        print("[FACT] 0x10319094 does NOT return the B709 root-child index.")
        print("[FACT] Composition:")
        print("       idx = F02F9D34(id)")
        print("       if idx == 0xFF: return 0x2E")
        print("       else: return F00B7994[idx]")
        print("[SUPERSEDED] old label: ROOT_CATEGORY_INDEX(id)")

    return ok


def selector_function_audit(zimage):
    banner("F. FIXED-RANGE SELECTOR FUNCTION F0316CE0")

    print_region(
        zimage,TARGET_C,END_C+8,"THUMB",
        {TARGET_C,0xF0316CE2,0xF0316CE4,0xF0316D62,0xF0316D68}
    )

    xs=dis(zimage,TARGET_C,END_C+8,"THUMB")

    print()
    print("Immediate constants / arithmetic possibly defining record stride:")
    for x in xs:
        if x.mnemonic in {"mov","movs","add","adds","sub","subs","lsls","lsrs","muls"}:
            if "#" in x.op_str or x.mnemonic=="muls":
                print(f"  {fmt(x)}")

    print()
    print("Memory operations:")
    for x in xs:
        if any(op.type==ARM_OP_MEM for op in x.operands):
            print(f"  {fmt(x)}")

    table_ok=False
    count_ok=False

    for x in xs:
        li=literal_load(zimage,x,"THUMB")
        if li:
            if li[3]==SELECTOR_TABLE_ADDR:
                table_ok=True
            if li[3]==SELECTOR_COUNT_ADDR:
                count_ok=True

    print()
    print(f"loads selector table F03AD120 = {'PASS' if table_ok else 'OPEN'}")
    print(f"loads selector count F03AD11C = {'PASS' if count_ok else 'OPEN'}")
    print("Known call signature from ALICE: F0316CE0(child_id, selector)")
    print("Observed selectors: 1, 5, 8")

    return xs,table_ok,count_ok


def table_audit(zimage,rows):
    banner("G. F03AD11C / F03AD120 STATIC TABLE AUDIT")

    count=u32(zimage.data,zimage.off(SELECTOR_COUNT_ADDR))
    print(f"u32[F03AD11C] = 0x{count:08X} ({count})")

    sane = count is not None and 0 < count <= 1024
    print(f"count sanity = {'PASS' if sane else 'OPEN'}")

    if not sane:
        print("Cannot safely derive table extent from count; dumping bounded 0x200 bytes.")
        extent=0x200
    else:
        extent=min(count*0x20,0x2000)

    end=min(zimage.end,SELECTOR_TABLE_ADDR+extent)

    print()
    print(f"raw selector-table window: 0x{SELECTOR_TABLE_ADDR:08X}..0x{end:08X}")

    # Hex + u16 view.
    for a in range(SELECTOR_TABLE_ADDR,end,16):
        chunk=zimage.data[zimage.off(a):zimage.off(a)+16]
        hs=" ".join(f"{b:02X}" for b in chunk)
        us=[]
        for i in range(0,len(chunk)-1,2):
            us.append(f"{struct.unpack_from('<H',chunk,i)[0]:04X}")
        print(f"  0x{a:08X}: {hs:<47} | {' '.join(us)}")

    resolver_ids={r.menu_id for r in rows}
    known=set(KNOWN_IDS)

    banner("H. RECORD-STRIDE RANKING")
    candidates=[]

    if sane:
        for stride in range(4,33,2):
            if SELECTOR_TABLE_ADDR + count*stride > zimage.end:
                continue

            firsts=[]
            res_hits=0
            known_hits=0
            zero_first=0
            unique=set()

            for i in range(count):
                off=zimage.off(SELECTOR_TABLE_ADDR+i*stride)
                k=u16(zimage.data,off)
                firsts.append(k)
                if k==0:
                    zero_first+=1
                unique.add(k)
                if k in resolver_ids:
                    res_hits+=1
                if k in known:
                    known_hits+=1

            # ID-like domain count.
            idlike=sum(1 for k in firsts if k is not None and 0x7000<=k<=0xBFFF)
            score=res_hits*6 + known_hits*4 + idlike - zero_first*2

            candidates.append((score,stride,res_hits,known_hits,idlike,len(unique),firsts))

        candidates.sort(key=lambda q:(-q[0],q[1]))

        for score,stride,res_hits,known_hits,idlike,uniq,firsts in candidates[:12]:
            print(
                f"stride=0x{stride:X} score={score} "
                f"resolver_first={res_hits} known_first={known_hits} "
                f"idlike_first={idlike} unique={uniq}/{count}"
            )
            print(
                "  first-u16: "
                + " ".join(
                    f"{k:04X}"
                    + (f"<{KNOWN_IDS[k]}>" if k in KNOWN_IDS else ("<RES>" if k in resolver_ids else ""))
                    for k in firsts[:40]
                )
            )

    banner("I. KNOWN-ID OCCURRENCES IN SELECTOR TABLE WINDOW")
    search_end=end
    for kid,name in sorted(KNOWN_IDS.items()):
        pat=struct.pack("<H",kid)
        region=zimage.data[zimage.off(SELECTOR_TABLE_ADDR):zimage.off(search_end)]
        offs=all_hits(region,pat)
        print(
            f"0x{kid:04X} {name:<12}: "
            + (
                ", ".join(f"0x{SELECTOR_TABLE_ADDR+o:08X}" for o in offs[:50])
                if offs else "NONE"
            )
        )

    # Also list all resolver IDs occurring in bounded region.
    found=defaultdict(list)
    region=zimage.data[zimage.off(SELECTOR_TABLE_ADDR):zimage.off(search_end)]
    for r in rows:
        pat=struct.pack("<H",r.menu_id)
        for off in all_hits(region,pat):
            found[r.menu_id].append(SELECTOR_TABLE_ADDR+off)

    print()
    print(f"resolver IDs occurring anywhere in table window = {len(found)}")
    for mid in sorted(found):
        print(
            f"  0x{mid:04X}: "
            + ", ".join(f"0x{x:08X}" for x in found[mid][:20])
        )

    return count,sane,candidates,found


def selector_callers(alice):
    banner("J. SELECTOR 1/5/8 CALLER CENSUS")

    # Direct calls are via veneer C.
    calls=[]

    for off in range(0,len(alice.data)-4,2):
        x=decode1(alice,alice.base+off,"THUMB")
        if not x or x.mnemonic not in {"bl","blx"}:
            continue
        t=direct_target(x)
        if t is not None and (t&~1)==VENEER_C:
            calls.append(x)

    print(f"direct ALICE calls to veneer C = {len(calls)}")

    for x in calls:
        lo=max(alice.base,x.address-0x14)
        hi=min(alice.end,x.address+0x18)
        print()
        print_region(alice,lo,hi,"THUMB",{x.address})


def output_array_ownership(alice):
    banner("K. F00B7994 READ/WRITE CROSS-CHECK")

    pat=struct.pack("<I",OUTPUT_ARRAY)
    words=all_hits(alice.data,pat)
    print(f"raw pointer words in ALICE = {len(words)}")

    for off in words:
        addr=alice.base+off
        print(f"  word@0x{addr:08X}")

        # Real Thumb literal refs only.
        refs=[]
        for a in range(max(alice.base,addr-0x500)&~1,addr+1,2):
            x=decode1(alice,a,"THUMB")
            li=literal_load(alice,x,"THUMB") if x else None
            if li and li[2]==addr and li[3]==OUTPUT_ARRAY:
                refs.append(x)

        for x in refs:
            print(f"    {fmt(x)}")
            print_region(
                alice,max(alice.base,x.address-0x18),
                min(alice.end,x.address+0x28),
                "THUMB",{x.address}
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
        default="research/f2/work/reports/s13_5a24_b709_filtered_children_selector8_table.txt",
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
        banner("S13.5A.24 - B709 FILTERED CHILDREN / SELECTOR-8 TABLE CONTRACT AUDIT")
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
        rows=parse_resolver(zimage)

        a_ok,b_ok=semantic_audit_ab(zimage)
        pred_start,pred_end=filter_predicate_audit(zimage)
        wrapper_ok=wrapper_audit(alice)
        selector_xs,table_ok,count_ref_ok=selector_function_audit(zimage)
        count,sane,strides,found=table_audit(zimage,rows)
        selector_callers(alice)
        output_array_ownership(alice)

        banner("L. DECISION GATE")

        print(f"A filtered-count shape       = {'PASS' if a_ok else 'OPEN'}")
        print(f"B filtered-enum shape        = {'PASS' if b_ok else 'OPEN'}")
        print(f"10319094 full composition    = {'PASS' if wrapper_ok else 'OPEN'}")
        print(f"C loads selector table       = {'PASS' if table_ok else 'OPEN'}")
        print(f"C loads selector count       = {'PASS' if count_ref_ok else 'OPEN'}")
        print(f"selector count sane          = {'PASS' if sane else 'OPEN'}")
        print()

        if a_ok and b_ok:
            print("[FACT/STRUCTURAL] A and B operate on the same parent children[] and")
            print("apply the same F02D5458 predicate.")
            print("[FACT/STRUCTURAL] B writes only predicate==0 child IDs into a compact")
            print("u16 output buffer and returns the number emitted.")
            print("[STRONG] A returns the matching compact count.")
            print()
            print("Preferred neutral names:")
            print("  F02D53DC = COUNT_FILTERED_CHILDREN(parent)")
            print("  F02AE864 = ENUM_FILTERED_CHILD_IDS(parent, out)")
            print("  F02D5458 = CHILD_FILTER_PREDICATE(child)")
            print("Do not substitute 'visible' for 'filtered' until predicate semantics are proven.")

        if wrapper_ok:
            print()
            print("[FACT] 0x10319094 returns a selector-8 value associated with the")
            print("B709 direct-child branch, not the branch index itself:")
            print("  idx = ROOT_CHILD_INDEX_UNDER_B709(id)")
            print("  if idx == FF: return 2E")
            print("  return F00B7994[idx]")

        if table_ok and count_ref_ok:
            print()
            print("[NEXT] Use the full F0316CE0 body + stride ranking above to derive")
            print("the exact F03AD120 record format and selector 8 field.")
            print("If B709 direct-child IDs appear as record keys, intersect them with")
            print("Image/Audio ancestry evidence before naming Multimedia.")

        print()
        print("IMPORTANT ALIGNMENT QUESTION:")
        print("  ROOT_MAPPER indexes raw children[B709], while 10313998 builds")
        print("  F00B7994 from FILTERED B709 children. If any B709 child is filtered out,")
        print("  indices could diverge. Therefore either:")
        print("    (a) all relevant B709 children pass F02D5458, or")
        print("    (b) there is an additional invariant not yet recovered.")
        print("  Do not assume (a) without proof.")
        print()
        print("STILL UNKNOWN:")
        print("  exact filtered children[B709]")
        print("  exact raw children[B709]")
        print("  exact selector-8 semantic")
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
