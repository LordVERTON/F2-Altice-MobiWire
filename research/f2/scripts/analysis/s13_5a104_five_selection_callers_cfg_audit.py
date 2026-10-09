#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.104 - five already-found direct callers of A90 selection owners.

STRICTLY OFFLINE. Reads canonical SHA-pinned ALICE & ZIMAGE binaries only;
writes ONE new text report under research/f2/work/reports, without overwriting.
No phone, USB, COM, patch, rebuild, flash, network access, or Notepad.

Scope: five exact BL sites from A103; local backward Thumb prologues, CFG
reachability within a narrow window, literal loads, local r0 definition hints.
This is LOCAL heuristic evidence, NOT proof of user OK/Select or Audio launch.
"""
from __future__ import annotations
import argparse
import hashlib
import struct
from collections import deque
from pathlib import Path

ALICE_BASE=0x1024EC00
ALICE_SIZE=0x157BB4
ALICE_SHA="7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_SIZE=0x185E98
ZIMAGE_SHA="85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
SITES={
  0x1039CCC4:(0x102ED240,"50f7bcfa"),
  0x1039E4A0:(0x102ED240,"4ef7cefe"),
  0x103A2330:(0x102ED240,"4af786ff"),
  0x10342E2C:(0x10345268,"02f01cfa"),
  0x10345334:(0x10345268,"fff798ff"),
}
# Anchors already verified by A90, A97, A103; do not rescan cross references.
REFERENCE_ANCHORS={
  0x102ED240:"10b5", 0x10345268:"f8b5",
  0x102ED260:"2cf0cafd", 0x10345282:"d4f7b9fd",
  0x10345296:"aaf7d9f8", 0x10340D2C:"c52f3410"
}


def abort(msg):
    raise SystemExit("ABORT: "+msg)


def branch_at(addr:int,h1:int,h2:int):
    """Thumb-2 BL / B.W decoder (signed 25-bit relative), A103 implementation."""
    if h1 & 0xF800 != 0xF000: return None
    tag=h2&0xD000
    if tag==0xD000: kind="BL"
    elif tag==0x9000: kind="B.W"
    else: return None
    s=(h1>>10)&1; j1=(h2>>13)&1; j2=(h2>>11)&1
    i1=1^(j1^s); i2=1^(j2^s)
    disp=(s<<24)|(i1<<23)|(i2<<22)|((h1&0x3FF)<<12)|((h2&0x7FF)<<1)
    if disp&(1<<24): disp-=1<<25
    return kind,(addr+4+disp)&0xFFFFFFFF


def self_test():
    for site,(target,raw) in SITES.items():
        assert branch_at(site,*struct.unpack('<HH',bytes.fromhex(raw))) == ("BL",target),hex(site)
    assert branch_at(0x102ED000,0xB510,0xBD10) is None
    assert branch_at(0x102ED000,*struct.unpack('<HH',bytes.fromhex('00f002b8'))) == ("B.W",0x102ED008)
    print("A104_SELF_TEST=PASS FIVE_EXACT_A103_BLS=5 PLUS_NEGATIVE_AND_WIDE_BRANCH")


def load(path:Path,label:str,size:int,sha:str):
    if not path.is_file(): abort(f"missing {label}: {path}")
    data=path.read_bytes(); digest=hashlib.sha256(data).hexdigest()
    if len(data)!=size or digest!=sha:
        abort(f"{label} guard FAIL size=0x{len(data):X} sha256={digest}")
    return data


def at(data:bytes,addr:int,count:int=4):
    off=addr-ALICE_BASE
    if off<0 or off+count>len(data): return None
    return data[off:off+count]


def verify(alice:bytes):
    for addr,hx in {**REFERENCE_ANCHORS,**{site:raw for site,(_,raw) in SITES.items()}}.items():
        if at(alice,addr,len(bytes.fromhex(hx)))!=bytes.fromhex(hx):
            abort(f"exact A90/A103 anchor mismatch 0x{addr:08X}")
    for site,(target,_) in SITES.items():
        if branch_at(site,*struct.unpack('<HH',at(alice,site,4))) != ("BL",target):
            abort(f"raw call target mismatch 0x{site:08X}")


def instruction(md,data,pc):
    raw=at(data,pc,4)
    if not raw:return None
    ins=next(md.disasm(raw,pc,count=1),None)
    return ins if ins and ins.address==pc else None


def m(ins): return ins.mnemonic.lower().split('.')[0]


def target(ins):
    from capstone.arm import ARM_OP_IMM
    for op in reversed(ins.operands):
        if op.type==ARM_OP_IMM: return (int(op.imm)&0xFFFFFFFF)&~1
    return None


def plit(ins,data):
    from capstone.arm import ARM_OP_MEM,ARM_REG_PC
    if m(ins)!="ldr" or len(ins.operands)<2:return None
    op=ins.operands[1]
    if op.type!=ARM_OP_MEM or op.mem.base!=ARM_REG_PC or op.mem.index:return None
    cell=(((ins.address+4)&~3)+op.mem.disp)&0xFFFFFFFF
    blob=at(data,cell,4)
    return (cell,struct.unpack('<I',blob)[0]) if blob else None


def fmt(ins,data):
    lit=plit(ins,data)
    return (f"0x{ins.address:08X} {ins.bytes.hex():<10} {ins.mnemonic:<9} {ins.op_str}"
           +(f" ; LITERAL[0x{lit[0]:08X}]=0x{lit[1]:08X}" if lit else ""))


def isret(ins):
    mn=m(ins); op=ins.op_str.lower().replace(' ','')
    return ((mn=='bx' and op=='lr') or (mn=='pop' and 'pc' in op)
            or (mn=='ldr' and op.startswith('pc,')))


def cfg(md,data,start,site,limit_insns=350):
    # Allow a small forward tail after the call site, never expand to a full application.
    low=start;high=site+0xA0
    queue=deque([start]);visited={};edges=[];calls=[];issues=[]
    cond={'beq','bne','bgt','bge','blt','ble','bhi','bhs','blo','bls','bpl','bmi','bvs','bvc','cbz','cbnz'}
    while queue and len(visited)<limit_insns:
        pc=queue.popleft()
        if pc in visited:continue
        if not (low<=pc<high):
            issues.append(f"OUT_OF_WINDOW 0x{pc:08X}");continue
        ins=instruction(md,data,pc)
        if not ins:
            issues.append(f"DECODE_FAIL 0x{pc:08X}");continue
        visited[pc]=ins;nm=m(ins);nextpc=pc+ins.size
        if nm in {'bl','blx'}:
            calls.append((pc,target(ins)))
            queue.append(nextpc)
        elif isret(ins):
            continue
        elif nm in cond or nm=='b':
            dest=target(ins)
            if dest is None:issues.append(f"INDIRECT_BRANCH 0x{pc:08X}")
            else:
                edges.append((pc,dest,nm));queue.append(dest)
            if nm!='b':queue.append(nextpc)
        elif nm in {'bx','tbb','tbh'} or (nm=='ldr' and ins.op_str.lower().startswith('pc,')):
            issues.append(f"INDIRECT_TERMINAL 0x{pc:08X} {nm}")
        else:queue.append(nextpc)
    if queue: issues.append(f"INSTRUCTION_CAP {limit_insns}")
    return visited,edges,calls,issues


def scan_candidates(md,data,site):
    # Only PUSH with LR is an entrance hypothesis, not proof of an actual owner.
    starts=[]
    for pc in range(max(ALICE_BASE,site-0x100),site,2):
        ins=instruction(md,data,pc)
        if ins and m(ins)=='push' and 'lr' in ins.op_str.lower():
            starts.append(pc)
    candidates=[]
    for pc in starts:
        visited,branches,calls,issues=cfg(md,data,pc,site)
        if site in visited:
            candidates.append((pc,visited,branches,calls,issues))
    return len(starts),candidates


def r0_hints(visited,site):
    # Only descriptions, NOT SSA/path-proven argument values.
    lines=[]
    for pc in sorted(p for p in visited if site-0x60<=p<site):
        ins=visited[pc];mn=m(ins);op=ins.op_str.lower().replace(' ','')
        if op.startswith('r0,') or mn in ('bl','blx') or ('r0' in op and mn in ('pop','ldm')):
            lines.append(f"  {pc:08X} {ins.mnemonic} {ins.op_str}"+(" ; CALL_RETURNS_R0_POSSIBLY_CLOBBERED" if mn in ('bl','blx') else ""))
    return lines


def run(alice,zimage):
    verify(alice)
    try:
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
    except ImportError as e:abort(f"Capstone missing: {e}")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    result=[
      "S13.5A.104 — FIVE A103 BL CALLS / BOUNDED THUMB CFG AND R0 PROVENANCE",
      "STRICTLY_OFFLINE=YES INPUTS_READ_ONLY=YES NO_NOTEPAD=YES",
      f"ALICE_GUARD=PASS SHA256={ALICE_SHA}",
      f"ZIMAGE_GUARD=PASS SHA256={ZIMAGE_SHA}",
      f"A103_FIVE_BL_ANCHORS=PASS A90_A97_OTHER_ANCHORS=PASS count={len(REFERENCE_ANCHORS)}",
      "SCOPE=ONLY five direct BL sites from A103, at most 0x100-byte predecessor prologues",
      "WARNING=heuristic owner/CFG; BL assumed return; local R0 hints NOT exact interprocedural argument provenance",
      "WARNING=raw Thumb signatures can be data; no proof of user OK/Select, Multimedia, or Audio 0x8928",
    ]
    counts=[]
    for site,(callee,_) in SITES.items():
        result.append(f"\n=== A103_SITE_0x{site:08X} -> 0x{callee:08X} ===")
        expected=instruction(md,alice,site)
        if not expected or m(expected)!='bl' or target(expected)!=callee:
            abort(f"Capstone Thumb interpretation disagrees with A103 at 0x{site:08X}")
        result.append("A103_BL_DECODE=PASS "+fmt(expected,alice))
        n,cands=scan_candidates(md,alice,site)
        result.append(f"NEARBY_PUSH_LR_CANDIDATES={n} LOCAL_OWNER_CANDIDATES_REACHING_BL={len(cands)}")
        counts.append(len(cands))
        if not cands:
            result.append("NO_OWNER_FROM_LOCAL_PROLOGUE=NOT_UNREACHABLE_PROOF")
            for pc in range(site-0x1C,site+0x12,2):
                ins=instruction(md,alice,pc)
                if ins and (pc==site or (pc<site and m(ins) in ('push','bl','blx','ldr','mov','movs'))):
                    result.append("RAW_LOCAL "+fmt(ins,alice))
            continue
        cands.sort(key=lambda tup:(abs(site-tup[0]),len(tup[4])))
        for idx,(start,visited,edges,calls,issues) in enumerate(cands[:4],1):
            result.append(f"OWNER_CANDIDATE_{idx}=0x{start:08X} REACHABLE={len(visited)} BRANCHES={len(edges)} CALLS={len(calls)} ISSUES={len(issues)}")
            for msg in issues[:12]:result.append("  CFG_NOTE "+msg)
            result.append("  LOCAL_NEAR_CALL_INSTRUCTIONS (site-0x50..site+0x12):")
            for pc in sorted(visited):
                if site-0x50<=pc<=site+0x12:
                    result.append("    "+fmt(visited[pc],alice))
            result.append("  R0_LOCAL_DEFS_HINTS (site-0x60..site):")
            result.extend(r0_hints(visited,site) or ["    no local definition observed; may derive from caller"])
            result.append("  LOCAL_DIRECT_CALLS:")
            for pc,t in calls:
                result.append(f"    0x{pc:08X} => "+(f"0x{t:08X}" if t is not None else "INDIRECT"))
            result.append("  LOCAL_BRANCHES:")
            for pc,t,mn in edges:
                result.append(f"    0x{pc:08X} {mn} -> 0x{t:08X}")
        if len(cands)>4:result.append(f"OTHER_CANDIDATES_NOT_PRINTED={len(cands)-4}")
    result += ["\n=== DECISION GATE ===",
        "TOTAL_SITE_COUNT=5",f"SITES_WITH_LOCAL_PROLOGUE_PATH={sum(x>0 for x in counts)}",
        "Prove callsite owner and R0 value before classifying any user-action callback.",
        "If a site is from a small wrapper, trace its immediate argument source rather than widening a raw scan.",
        "Selected leaf ID -> handler and descriptor+0x0C set to 1 remain UNPROVEN.",
        "NO_PHONE_USB_COM_FLASH_PATCH_REPACK=YES"]
    return '\n'.join(result)+'\n'


def root_guess():
    for parent in Path(__file__).resolve().parents:
        if (parent/'research'/'f2').is_dir(): return parent
    return Path.cwd()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=root_guess())
    p.add_argument('--alice',type=Path)
    p.add_argument('--zimage',type=Path)
    p.add_argument('--out',type=Path)
    p.add_argument('--self-test',action='store_true')
    args=p.parse_args();self_test()
    if args.self_test:return 0
    root=args.root.resolve()
    af=args.alice or root/'research/f2/work/extracted/altice_alice/alice-py.bin'
    zf=args.zimage or root/'research/f2/work/extracted/altice_platform/zimage.bin'
    output=args.out or root/'research/f2/work/reports/s13_5a104_five_selection_callers_cfg_audit.txt'
    if output.is_file():
        print(f"REPORT_ALREADY_EXISTS_UNCHANGED={output.resolve()}");return 0
    alice=load(af,'ALICE',ALICE_SIZE,ALICE_SHA)
    zimage=load(zf,'ZIMAGE',ZIMAGE_SIZE,ZIMAGE_SHA)
    report=run(alice,zimage)
    output.parent.mkdir(parents=True,exist_ok=True)
    try:
        with output.open('x',encoding='utf-8',newline='\n') as f:f.write(report)
    except FileExistsError:
        print(f"REPORT_ALREADY_EXISTS_UNCHANGED={output.resolve()}");return 0
    print(f"A104_REPORT_CREATED={output.resolve()} BYTES={output.stat().st_size}")
    print("A104_RESULT="+next(x for x in report.splitlines() if x.startswith("SITES_WITH_LOCAL_PROLOGUE_PATH=")))
    return 0

if __name__=='__main__':raise SystemExit(main())
