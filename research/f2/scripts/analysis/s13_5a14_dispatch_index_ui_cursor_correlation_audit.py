#!/usr/bin/env python3
"""
S13.5A.14 - DISPATCH INDEX SEMANTICS / UI CURSOR CORRELATION AUDIT

STRICTLY OFFLINE / READ-ONLY.

A.13 proved:
  - dispatcher = 0x1031CC8C
  - r4 = incoming r0
  - current callback = *(F009605C)
  - r0 = r4
  - blx callback

Repeated callers show:
  r4 = incoming r0
  r0 = r4 + 1
  blx 0x102FD13C
  r0 = r4
  bl  0x1031CC8C
  [often] bl 0x10315360
  [often] *(F004B04C) = r4

This pass resolves the shared helper and correlates the same value with
UI/list cursor state. It does not scan menu IDs broadly and generates no patch.
"""

from __future__ import annotations
import argparse, hashlib, io, struct, sys
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

DISPATCHER = 0x1031CC8C
PLUS1_VENEER = 0x102FD13C
POST_HELPER = 0x10315360
INDEX_GLOBAL = 0xF004B04C

WRAPPERS = [
    (0x1032D880, 0x1032D882),
    (0x10349EF8, 0x10349F08),
    (0x10352728, 0x10352734),
    (0x10352748, 0x10352754),
    (0x103595AC, 0x103595C0),
    (0x1036B6E8, 0x1036B718),
    (0x10377408, 0x10377414),
    (0x103964F6, 0x10396502),
    (0x103988DC, 0x103988EC),
]

md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md_t.detail=True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN); md_a.detail=True

@dataclass
class Image:
    name: str
    data: bytes
    base: int
    @property
    def end(self): return self.base + len(self.data)
    def contains(self, a): return self.base <= a < self.end
    def off(self, a): return a - self.base

class Tee:
    def __init__(self,*s): self.s=s
    def write(self,x):
        for f in self.s: f.write(x)
        return len(x)
    def flush(self):
        for f in self.s: f.flush()

def banner(s):
    print("\n" + "="*128)
    print(s)
    print("="*128)

def sha256(b): return hashlib.sha256(b).hexdigest()
def u16(b,o): return struct.unpack_from("<H",b,o)[0] if 0 <= o <= len(b)-2 else None
def u32(b,o): return struct.unpack_from("<I",b,o)[0] if 0 <= o <= len(b)-4 else None

def verify(path,name,base,size,sha):
    if not path.is_file(): raise SystemExit(f"ABORT: missing {name}: {path}")
    b=path.read_bytes(); h=sha256(b)
    print(f"{name}={path}\n  base=0x{base:08X}\n  size=0x{len(b):X}\n  sha256={h}")
    if len(b)!=size or h.lower()!=sha.lower(): raise SystemExit(f"ABORT: {name} canonical mismatch")
    print(f"[PASS] canonical {name}")
    return Image(name,b,base)

def img_for(images,a):
    a &= ~1
    for im in images:
        if im.contains(a): return im
    return None

def decode1(im,a,mode="THUMB"):
    if mode=="THUMB": a &= ~1
    if not im.contains(a): return None
    md = md_t if mode=="THUMB" else md_a
    xs=list(md.disasm(im.data[im.off(a):im.off(a)+4],a,count=1))
    return xs[0] if xs else None

def dis(im,a,b,mode="THUMB"):
    if mode=="THUMB": a &= ~1
    if not im.contains(a): return []
    md=md_t if mode=="THUMB" else md_a
    b=min(b,im.end)
    return [x for x in md.disasm(im.data[im.off(a):im.off(b)],a) if x.address<b]

def fmt(x): return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<8} {x.op_str}"

def direct_target(x):
    if not x or x.mnemonic not in {"b","bl","blx"} or not x.operands: return None
    return x.operands[0].imm & 0xffffffff if x.operands[0].type==ARM_OP_IMM else None

def literal(im,x,mode="THUMB"):
    if not x or not x.mnemonic.startswith("ldr") or len(x.operands)<2: return None
    d,s=x.operands[0],x.operands[1]
    if d.type!=ARM_OP_REG or s.type!=ARM_OP_MEM or s.mem.base!=ARM_REG_PC: return None
    pc=((x.address+4)&~3) if mode=="THUMB" else x.address+8
    la=(pc+s.mem.disp)&0xffffffff
    if not im.contains(la): return None
    return x.reg_name(d.reg),d.reg,la,u32(im.data,im.off(la))

def print_region(im,a,b,mode="THUMB",marks=None):
    marks=marks or set()
    for x in dis(im,a,b,mode):
        notes=[]
        t=direct_target(x)
        if t is not None: notes.append(f"target=0x{t:08X}")
        li=literal(im,x,mode)
        if li:
            tag=[]
            if li[3]==INDEX_GLOBAL: tag.append("INDEX_GLOBAL")
            notes.append(f"literal@0x{li[2]:08X}=0x{li[3]:08X}->{li[0]}" + (f" <{'|'.join(tag)}>" if tag else ""))
        print((">>> " if x.address in marks else "    ")+fmt(x)+((" ; "+", ".join(notes)) if notes else ""))

def all_hits(b,n):
    out=[]; p=0
    while True:
        p=b.find(n,p)
        if p<0:return out
        out.append(p); p+=1

def scan_calls(im,target):
    out=[]
    for off in range(0,len(im.data)-4,2):
        h1=u16(im.data,off); h2=u16(im.data,off+2)
        if h1 is None or h2 is None or (h1&0xF800)!=0xF000 or (h2&0xC000)!=0xC000: continue
        xs=list(md_t.disasm(im.data[off:off+4],im.base+off,count=1))
        if not xs: continue
        x=xs[0]
        if x.mnemonic in {"bl","blx"}:
            t=direct_target(x)
            if t is not None and (t&~1)==(target&~1): out.append(("THUMB",x))
    for off in range(0,len(im.data)-4,4):
        w=u32(im.data,off)
        if w is None or not ((w&0x0E000000)==0x0A000000 or (w&0xFE000000)==0xFA000000): continue
        xs=list(md_a.disasm(im.data[off:off+4],im.base+off,count=1))
        if not xs: continue
        x=xs[0]
        if x.mnemonic in {"bl","blx"}:
            t=direct_target(x)
            if t is not None and (t&~1)==(target&~1): out.append(("ARM",x))
    d={(m,x.address):(m,x) for m,x in out}
    return [d[k] for k in sorted(d,key=lambda z:(z[1],z[0]))]

def raw_ptrs(im,target):
    out=[]
    for v in {(target&~1)&0xffffffff,(target|1)&0xffffffff}:
        for off in all_hits(im.data,struct.pack("<I",v)): out.append((im.base+off,v))
    return sorted(set(out))

def real_literal_xrefs(im,value):
    out=[]
    for roff in all_hits(im.data,struct.pack("<I",value&0xffffffff)):
        la=im.base+roff
        for off in range(max(0,roff-0x500)&~1,roff+1,2):
            x=decode1(im,im.base+off,"THUMB"); li=literal(im,x,"THUMB") if x else None
            if li and li[2]==la and li[3]==value: out.append(("THUMB",x,la))
        for off in range(max(0,roff-0x1000)&~3,roff+1,4):
            x=decode1(im,im.base+off,"ARM"); li=literal(im,x,"ARM") if x else None
            if li and li[2]==la and li[3]==value: out.append(("ARM",x,la))
    d={(m,x.address,la):(m,x,la) for m,x,la in out}
    return [d[k] for k in sorted(d)]

def is_prologue(x): return bool(x and x.mnemonic=="push" and "lr" in x.op_str)

def enclosing_start(im,target,back=0x400):
    c=[]
    for a in range((max(im.base,target-back)&~1),target+1,2):
        x=decode1(im,a)
        if not is_prologue(x): continue
        if any(z.address==target for z in dis(im,a,min(im.end,a+0x700))): c.append(a)
    return c[-1] if c else None

def reg_written(x):
    return x.operands[0].reg if x.operands and x.operands[0].type==ARM_OP_REG else None

def backward_source(im,ins,before,name,depth=0):
    if depth>8:return "UNKNOWN(depth)"
    hist=[x for x in ins if x.address<before]
    rid=None
    for x in hist:
        for op in x.operands:
            if op.type==ARM_OP_REG and x.reg_name(op.reg)==name: rid=op.reg; break
        if rid is not None: break
    if rid is None:return f"UNKNOWN({name} unseen)"
    caller_saved=name in {"r0","r1","r2","r3","r12","ip","lr"}
    for i in range(len(hist)-1,-1,-1):
        x=hist[i]
        if x.mnemonic in {"bl","blx"} and caller_saved:return f"UNKNOWN({name} clobbered by call @0x{x.address:08X})"
        if reg_written(x)!=rid:continue
        li=literal(im,x)
        if li and li[1]==rid:return f"CONST 0x{li[3]:08X} via literal @0x{li[2]:08X}"
        ops=x.operands
        if x.mnemonic in {"mov","movs"} and len(ops)>=2:
            s=ops[1]
            if s.type==ARM_OP_IMM:return f"CONST 0x{s.imm&0xffffffff:08X} @0x{x.address:08X}"
            if s.type==ARM_OP_REG:
                sn=x.reg_name(s.reg)
                return f"{name} <- {sn} @0x{x.address:08X} <- "+backward_source(im,hist[:i+1],x.address,sn,depth+1)
        if x.mnemonic.startswith("ldr") and len(ops)>=2 and ops[1].type==ARM_OP_MEM:
            m=ops[1].mem
            return f"MEM {x.mnemonic} [{x.reg_name(m.base)}{m.disp:+#x}] @0x{x.address:08X}"
        if x.mnemonic in {"add","adds","sub","subs","lsls","lsrs"}: return f"EXPR {x.mnemonic} {x.op_str} @0x{x.address:08X}"
        return f"{x.mnemonic} {x.op_str} @0x{x.address:08X}"
    return f"ARG/INHERITED {name}"

def resolve_veneer(alice):
    w0=u32(alice.data,alice.off(PLUS1_VENEER)); w1=u32(alice.data,alice.off(PLUS1_VENEER+4))
    x=decode1(alice,PLUS1_VENEER,"ARM")
    print(f"0x{PLUS1_VENEER:08X}: raw0=0x{w0:08X} raw1=0x{w1:08X}")
    print(f"ARM decode: {fmt(x) if x else 'UNRESOLVED'}")
    return w1 if x and x.mnemonic=="ldr" else None

def global_users(im,addr):
    out=[]
    refs=real_literal_xrefs(im,addr)
    for mode,seed,la in refs:
        if mode!="THUMB": continue
        li=literal(im,seed)
        if not li: continue
        aliases={li[1]}
        for z in dis(im,seed.address,min(im.end,seed.address+0x70)):
            if z.address==seed.address:continue
            if z.mnemonic in {"mov","movs"} and len(z.operands)>=2:
                d,s=z.operands[0],z.operands[1]
                if d.type==ARM_OP_REG and s.type==ARM_OP_REG and s.reg in aliases: aliases.add(d.reg)
            for op in z.operands:
                if op.type==ARM_OP_MEM and op.mem.base in aliases and op.mem.disp==0 and (z.mnemonic.startswith("ldr") or z.mnemonic.startswith("str")):
                    out.append((seed,z))
    d={(a.address,b.address):(a,b) for a,b in out}
    return [d[k] for k in sorted(d)]

def wrapper_pattern(im,start,calladdr):
    xs=dis(im,start,min(im.end,start+0x60))
    flags=dict(preserve=False,plus1=False,plus1_call=False,dispatch=False,post=False,store_global=False)
    litregs={}
    for x in xs:
        compact=x.op_str.replace(" ","")
        if x.mnemonic in {"mov","movs"} and compact=="r4,r0": flags["preserve"]=True
        if x.mnemonic in {"add","adds"} and "r0" in x.op_str and "#1" in x.op_str: flags["plus1"]=True
        t=direct_target(x)
        if t is not None and (t&~1)==PLUS1_VENEER: flags["plus1_call"]=True
        if t is not None and (t&~1)==DISPATCHER: flags["dispatch"]=True
        if t is not None and (t&~1)==POST_HELPER: flags["post"]=True
        li=literal(im,x)
        if li and li[3]==INDEX_GLOBAL: litregs[li[1]]=x.address
        if x.mnemonic.startswith("str") and len(x.operands)>=2 and x.operands[1].type==ARM_OP_MEM:
            mem=x.operands[1].mem
            if mem.mem if False else False: pass
            if mem.base in litregs and mem.disp==0: flags["store_global"]=True
    return flags,xs

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--alice",default="research/f2/work/extracted/altice_alice/alice-py.bin")
    ap.add_argument("--zimage",default="research/f2/work/extracted/altice_platform/zimage.bin")
    ap.add_argument("--report",default="research/f2/work/reports/s13_5a14_dispatch_index_ui_cursor_correlation.txt")
    a=ap.parse_args()
    root=Path.cwd()
    def P(s): 
        p=Path(s); return p if p.is_absolute() else root/p
    rp=P(a.report); rp.parent.mkdir(parents=True,exist_ok=True)
    cap=io.StringIO(); old=sys.stdout; sys.stdout=Tee(old,cap)
    try:
        banner("S13.5A.14 - DISPATCH INDEX SEMANTICS / UI CURSOR CORRELATION AUDIT")
        print("STRICTLY OFFLINE\nPHONE ACCESSED       : NO\nFLASH MODIFIED       : NO\nPATCH GENERATED      : NO\nREPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice=verify(P(a.alice),"ALICE",ALICE_BASE,ALICE_SIZE,ALICE_SHA256)
        zimage=verify(P(a.zimage),"ZIMAGE",ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA256)
        images=[alice,zimage]

        banner("B. RESOLVE 0x102FD13C")
        target_ptr=resolve_veneer(alice)
        print(f"resolved pointer = {('0x%08X'%target_ptr) if target_ptr is not None else 'UNRESOLVED'}")
        if target_ptr is not None:
            target=target_ptr&~1; mode="THUMB" if target_ptr&1 else "ARM"; im=img_for(images,target)
            print(f"target=0x{target:08X} mode={mode} owner={im.name if im else 'OUTSIDE CANONICAL IMAGES'}")
            if im: print_region(im,target,min(im.end,target+0x100),mode)

        banner("C. CALLS TO PLUS-ONE HELPER")
        calls=scan_calls(alice,PLUS1_VENEER)
        print(f"direct calls = {len(calls)}")
        for mode,x in calls[:80]:
            fs=enclosing_start(alice,x.address)
            print(f"\n{mode} {fmt(x)}")
            if fs is not None:
                ins=dis(alice,fs,min(alice.end,fs+0x500))
                print(f"  function=0x{fs:08X}")
                print(f"  r0 source={backward_source(alice,ins,x.address,'r0')}")

        banner("D. 0x10315360")
        print_region(alice,POST_HELPER,min(alice.end,POST_HELPER+0x100))

        banner("E. F004B04C USERS")
        refs=real_literal_xrefs(alice,INDEX_GLOBAL)
        print(f"real literal xrefs = {len(refs)}")
        for m,x,la in refs: print(f"  {m} {fmt(x)} literal@0x{la:08X}")
        users=global_users(alice,INDEX_GLOBAL)
        print(f"exact short load/store users = {len(users)}")
        for seed,user in users:
            rw="WRITE" if user.mnemonic.startswith("str") else "READ"
            print(f"  {rw}: {fmt(seed)} -> {fmt(user)}")

        banner("F. DISPATCHER WRAPPER PATTERN")
        core=post=stores=0
        for start,calladdr in WRAPPERS:
            flags,xs=wrapper_pattern(alice,start,calladdr)
            if flags["preserve"] and flags["plus1"] and flags["plus1_call"] and flags["dispatch"]: core+=1
            if flags["post"]: post+=1
            if flags["store_global"]: stores+=1
            print(f"\nwrapper 0x{start:08X}: {flags}")
            print_region(alice,start,min(alice.end,start+0x50),marks={calladdr})
        print(f"\ncore pattern count = {core}/{len(WRAPPERS)}")
        print(f"post-helper count  = {post}/{len(WRAPPERS)}")
        print(f"F004B04C stores    = {stores}/{len(WRAPPERS)}")

        banner("G. WRAPPER OWNERS")
        owners=0
        for start,_ in WRAPPERS:
            dc=scan_calls(alice,start); ptr=raw_ptrs(alice,start)
            if dc or ptr: owners+=1
            print(f"\n0x{start:08X}: direct callers={len(dc)} raw ptr refs={len(ptr)}")
            for m,x in dc[:20]:
                fs=enclosing_start(alice,x.address)
                print(f"  {m} {fmt(x)}")
                if fs is not None and m=="THUMB":
                    ins=dis(alice,fs,min(alice.end,fs+0x500))
                    print(f"    caller=0x{fs:08X} r0={backward_source(alice,ins,x.address,'r0')}")
            for pa,pv in ptr[:20]:
                print(f"  ptr@0x{pa:08X}=0x{pv:08X}")

        banner("H. DECISION GATE")
        print(f"veneer resolved         = {'PASS' if target_ptr is not None else 'OPEN'}")
        print(f"core wrapper repetition = {core}/{len(WRAPPERS)}")
        print(f"F004B04C exact users    = {len(users)}")
        print(f"wrapper ownership hits  = {owners}")
        print()
        if target_ptr is not None and core>=5:
            print("[STRONGLY SUPPORTED] dispatcher argument is a zero-based UI/list item index.")
            print("Evidence: original value is preserved, value+1 is sent to a shared helper,")
            print("original value is dispatched, SELECT_CB uses it as children[index], and")
            print("the same value is persisted by multiple wrappers.")
            print("[NEXT] Promote to FACT only if helper target or wrapper owner identifies")
            print("highlight/current-item/list-position semantics.")
        else:
            print("[NEXT] Continue only from resolved helper/owner evidence.")
        print()
        print("STILL UNKNOWN:")
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
        print(f"\nREPORT = {rp}")
        return 0
    finally:
        sys.stdout=old
        rp.write_text(cap.getvalue(),encoding="utf-8")

if __name__=="__main__":
    raise SystemExit(main())
