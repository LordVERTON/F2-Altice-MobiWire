#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import re
import sys
import traceback
from pathlib import Path
from collections import defaultdict
from contextlib import redirect_stdout

TITLE = "S13.5A.59 - B702 RUNTIME CHILD ENUMERATOR / DYNAMIC ROOT_MAPPER TRACE"
ROOT_MAPPER = 0x10319094
MAPPER_CORE = 0xF02F9D34
A58_CAND = 0x1037AB2C
FOCUS = {0xB702:"B702",0xB709:"B709",0x8569:"8569",0x87ED:"87ED",0x86C0:"86C0",0x8928:"8928"}
MEM_RE = re.compile(r"\[(r(?:1[0-2]|[0-9])|sp|lr)(?:,\s*#(-?(?:0x[0-9a-f]+|\d+)))?\]", re.I)
DEST_RE = re.compile(r"^\s*(?:ldr|ldrh|ldrb|ldrsh|ldrsb)\w*\s+(r(?:1[0-2]|[0-9]))\s*,", re.I)

class Tee:
    def __init__(self,*s): self.s=s
    def write(self,d):
        for x in self.s: x.write(d); x.flush()
        return len(d)
    def flush(self):
        for x in self.s: x.flush()

def h(s):
    print(); print("="*120); print(s); print("="*120)

def pmem(t):
    m=MEM_RE.search(t)
    if not m: return None
    return m.group(1).lower(), int(m.group(2),0) if m.group(2) else 0

def ldest(t):
    m=DEST_RE.search(t); return m.group(1).lower() if m else None

def calls(aud,fa): return {aud.normalized_target(raw)[0] for _,raw in fa.calls}

def ctx(aud,c,b=0x30,a=0x20,mark="FOCUS"):
    pc=(c-b)&~1; end=c+a
    while pc<end:
        x=aud.decode_one(pc)
        if x is None: pc+=2; continue
        ex=[]
        if x.target is not None:
            n,v=aud.normalized_target(x.target); ex.append(f"target=0x{n:08X}"+(f"[{v}]" if v else ""))
        if x.literal_value is not None:
            lab=FOCUS.get(x.literal_value); ex.append(f"literal=0x{x.literal_value:08X}"+(f"<{lab}>" if lab else ""))
            s=aud.string_at(x.literal_value)
            if s: ex.append(f'STR="{s}"')
        print(f"0x{pc:08X}: {x.text}"+(" ; "+" ".join(ex) if ex else "")+(f" <{mark}>" if pc==c else ""))
        pc+=max(2,x.size)

def dump_func(aud,entry,limit=420):
    fa=aud.audit_func(entry,max_span=0x1600,max_insns=1800)
    print(f"entry=0x{entry:08X} image={fa.image} insns={len(fa.insns)} calls={len(fa.calls)} literals={len(fa.literals)} truncated={fa.truncated}")
    for i,addr in enumerate(sorted(fa.insns)):
        if i>=limit: print("  ... truncated"); break
        x=fa.insns[addr]; ex=[]
        if x.target is not None:
            n,v=aud.normalized_target(x.target); ex.append(f"target=0x{n:08X}"+(f"[{v}]" if v else ""))
        if x.literal_value is not None:
            lab=FOCUS.get(x.literal_value); ex.append(f"literal=0x{x.literal_value:08X}"+(f"<{lab}>" if lab else ""))
        print(f"  0x{addr:08X}: {x.text}"+(" ; "+" ".join(ex) if ex else ""))
    return fa

def same_base(fa):
    c=defaultdict(list); p=defaultdict(list)
    for a,x in fa.insns.items():
        t=x.text.lower(); m=pmem(t)
        if not m: continue
        b,o=m
        if t.startswith("ldrh") and o==2: c[b].append(a)
        if t.startswith("ldr") and not t.startswith(("ldrh","ldrb","ldrsh","ldrsb")) and o==0xC: p[b].append(a)
    return {b:(c[b],p[b]) for b in set(c)&set(p)}

def child_evidence(aud,fa,same):
    ordered=[fa.insns[a] for a in sorted(fa.insns)]; pos={x.addr:i for i,x in enumerate(ordered)}; out=[]
    for rb,(cs,ps) in same.items():
        for site in ps:
            cr=ldest(fa.insns[site].text)
            if not cr: continue
            half=[]; inc=[]; mapper=[]
            for y in ordered[pos[site]+1:pos[site]+45]:
                t=y.text.lower(); m=pmem(t)
                if m and m[0]==cr and t.startswith("ldrh"): half.append(y.addr)
                if re.match(rf"^(?:adds|add|subs|sub)\s+{cr}\b",t) and ("#2" in t or "#0x2" in t): inc.append(y.addr)
                if y.is_call and y.target is not None and aud.normalized_target(y.target)[0]==ROOT_MAPPER: mapper.append(y.addr)
            if half or inc or mapper: out.append((rb,cr,site,half,inc,mapper))
    return out

def candidate_entries(aud,site,back=0x340):
    img=aud.image_for(site)
    if img is None: return []
    out=[]; seen=set(); pc=max(img.base,site-back)&~1
    while pc<=site:
        x=aud.decode_one(pc)
        if x and x.text.lower().startswith("push") and "lr" in x.text.lower():
            fa=aud.audit_func(pc,max_span=0x1600,max_insns=1800)
            if site in fa.insns and pc not in seen: seen.add(pc); out.append((pc,fa))
        pc+=2
    out.sort(key=lambda z:(site-z[0],z[0])); return out

def reverse_calls(aud,targets):
    ts={x&~1 for x in targets}; out={x:[] for x in ts}
    for img in aud.images:
        pc=img.base&~1; end=img.end-2
        while pc<end:
            x=aud.decode_one(pc)
            if x and x.is_call and x.target is not None:
                n,v=aud.normalized_target(x.target)
                if n in ts: out[n].append((img.name,pc,v))
            pc+=2
    return out

def dyn_mapper(aud):
    rows=reverse_calls(aud,[ROOT_MAPPER])[ROOT_MAPPER]; out=[]
    for image,site,via in rows:
        img=aud.image_for(site); pc=max(img.base,site-0x30)&~1; ins=[]
        while pc<site:
            x=aud.decode_one(pc)
            if x: ins.append(x); pc+=max(2,x.size)
            else: pc+=2
        src=None
        for x in reversed(ins):
            t=x.text.lower()
            if x.is_call: break
            if re.match(r"^ldrh\s+r0\s*,",t): src=(x.addr,x.text); break
            if re.match(r"^(?:ldr|ldrb|movs?|adds?|subs?|muls?)\s+r0\b",t): break
        if src: out.append((image,site,src,candidate_entries(aud,site)[:3]))
    return out

def signature(aud,entry,fa):
    s=same_base(fa); ce=child_evidence(aud,fa,s); cs=calls(aud,fa); lits=defaultdict(list)
    for site,la,v in fa.literals:
        if v in FOCUS: lits[v].append(site)
    dm=[]; ordered=[fa.insns[a] for a in sorted(fa.insns)]
    for i,x in enumerate(ordered):
        if x.is_call and x.target is not None and aud.normalized_target(x.target)[0]==ROOT_MAPPER:
            for y in reversed(ordered[max(0,i-12):i]):
                if re.match(r"^ldrh\s+r0\s*,",y.text.lower()): dm.append((x.addr,y.addr,y.text)); break
                if y.is_call: break
    score=(12 if s else 0)+(12 if ce else 0)+(12 if dm else 0)+(4 if ROOT_MAPPER in cs else 0)+(10 if 0xB702 in lits else 0)+(3 if 0xB709 in lits else 0)+(2 if 0x8569 in lits or 0x87ED in lits else 0)
    if any(e[4] for e in ce): score+=5
    return dict(entry=entry,fa=fa,same=s,ce=ce,dm=dm,lits=lits,calls=cs,score=score)

def show(sig):
    fa=sig['fa']; print(f"entry=0x{sig['entry']:08X} score={sig['score']} image={fa.image} insns={len(fa.insns)} calls={len(fa.calls)}")
    for b,(c,p) in sig['same'].items(): print(f"  SAME_BASE {b}: +2="+",".join(f"0x{x:08X}" for x in c)+" +0xC="+",".join(f"0x{x:08X}" for x in p))
    for rb,cr,site,half,inc,mapper in sig['ce']:
        print(f"  CHILD_PTR record={rb} child={cr} load=0x{site:08X}")
        if half: print("    halfword_reads="+",".join(f"0x{x:08X}" for x in half))
        if inc: print("    plus2="+",".join(f"0x{x:08X}" for x in inc))
        if mapper: print("    mapper="+",".join(f"0x{x:08X}" for x in mapper))
    for c,s,t in sig['dm']: print(f"  DYNAMIC_MAPPER call=0x{c:08X} src=0x{s:08X} {t}")
    for v,rows in sig['lits'].items(): print(f"  LIT {FOCUS[v]}: "+",".join(f"0x{x:08X}" for x in rows))

def body():
    repo=Path.cwd().resolve(); hp=repo/'research/f2/automation/jobs/s13_5a51_launcher_dispatch_init_trace.py'
    if not hp.is_file(): raise SystemExit('Run from C:\\Users\\verto\\F2-Altice-MobiWire')
    sys.path.insert(0,str(hp.parent)); import s13_5a51_launcher_dispatch_init_trace as m
    alice,zimage=m.load_images(); aud=m.StaticAudit(alice,zimage)
    print('='*120); print(TITLE); print('='*120); print('STRICTLY OFFLINE: local firmware reads only.')

    h('A. FULL A.58 CANDIDATE CLASSIFICATION')
    fa1=dump_func(aud,A58_CAND); s1=signature(aud,A58_CAND,fa1); print('\nSUMMARY 1037AB2C'); show(s1)
    print(); fa2=dump_func(aud,MAPPER_CORE); s2=signature(aud,MAPPER_CORE,fa2); print('\nSUMMARY F02F9D34'); show(s2)

    h('B. SAME-BASE +2 / +0xC CANDIDATE RECOVERY')
    counts=[]; childs=[]
    for img in aud.images:
        pc=img.base&~1; end=img.end-2
        while pc<end:
            x=aud.decode_one(pc)
            if x:
                t=x.text.lower(); mm=pmem(t)
                if mm:
                    b,o=mm
                    if t.startswith('ldrh') and o==2: counts.append((img.name,x.addr,b))
                    if t.startswith('ldr') and not t.startswith(('ldrh','ldrb','ldrsh','ldrsb')) and o==0xC: childs.append((img.name,x.addr,b))
            pc+=2
    cb=defaultdict(list)
    for im,a,b in childs: cb[(im,b)].append(a)
    seeds=[]
    for im,a,b in counts:
        for c in cb.get((im,b),[]):
            if abs(c-a)<=0x180: seeds.append((im,min(a,c),max(a,c),b))
    print(f"count_seeds={len(counts)} childptr_seeds={len(childs)} local_same_reg_pairs={len(seeds)}")
    funcs={}; prov=defaultdict(list)
    for im,a,b,r in seeds:
        for entry,fa in candidate_entries(aud,a)[:2]:
            if a in fa.insns and b in fa.insns:
                funcs.setdefault(entry,fa); prov[entry].append((a,b,r)); break
    sigs=[signature(aud,e,fa) for e,fa in funcs.items()]; sigs.sort(key=lambda x:(-x['score'],x['entry']))
    print(f"validated_functions={len(sigs)}")
    for s in sigs[:60]: show(s)

    h('C. DYNAMIC ROOT_MAPPER CALLS FED BY LDRH R0')
    dyn=dyn_mapper(aud); print(f"dynamic_mapper_calls={len(dyn)}")
    dynfunc={}; dprov=defaultdict(list)
    for im,site,src,entries in dyn:
        print(f"\n{im} call=0x{site:08X} source=0x{src[0]:08X} {src[1]}"); ctx(aud,site,0x38,0x24,'ROOT_MAPPER')
        for e,fa in entries: dynfunc.setdefault(e,fa); dprov[e].append((site,src[0]))

    h('D. INTERSECTION / RANKING')
    merged={s['entry']:s for s in sigs}
    for e,fa in dynfunc.items(): merged.setdefault(e,signature(aud,e,fa))
    ranked=[]
    for e,s in merged.items():
        bonus=(15 if e in dynfunc else 0)+(10 if s['same'] else 0)+(10 if s['ce'] else 0)
        s=dict(s); s['combined']=s['score']+bonus; ranked.append(s)
    ranked.sort(key=lambda x:(-x['combined'],x['entry']))
    for s in ranked[:40]: print(f"\ncombined={s['combined']}"); show(s)

    h('E. REVERSE CALLERS OF BEST CANDIDATES')
    top=[s['entry'] for s in ranked[:10] if s['combined']>=12]
    for x in (A58_CAND,MAPPER_CORE):
        if x not in top: top.append(x)
    rev=reverse_calls(aud,top)
    for t in top:
        rows=rev.get(t&~1,[]); print(f"\nTARGET 0x{t:08X}: direct_callers={len(rows)}")
        for im,site,via in rows[:30]: print(f"  {im} 0x{site:08X} via={via or 'DIRECT'}"); ctx(aud,site,0x28,0x18,'CALL')

    h('F. MAPPER CORE CHECK')
    rows=reverse_calls(aud,[MAPPER_CORE])[MAPPER_CORE]; print(f"F02F9D34 direct_callers={len(rows)}")
    for im,site,via in rows: print(f"  {im} 0x{site:08X} via={via or 'DIRECT'}")
    if len(rows)==1 and rows[0][1]==0x10319096:
        print('FACT: F02F9D34 is the direct core used by ROOT_MAPPER 10319094; do not classify it as visible menu builder from offsets alone.')

    h('G. DECISION GATE')
    strong=[s for s in ranked if s['same'] and (s['dm'] or s['ce'])]
    print(f"strong_child_enumerator_candidates={len(strong)}")
    for s in strong[:20]: print(f"  0x{s['entry']:08X} score={s['score']} combined={s['combined']}")
    if strong:
        print(f"RESULT: leading runtime child-enumerator candidate = 0x{strong[0]['entry']:08X}.")
        print('NEXT: trace its argument provenance until runtime parent B702 is proven, then compare construction/action for child 8569 vs 87ED.')
    elif dyn:
        print('RESULT: dynamic child-ID -> ROOT_MAPPER sites exist but are not yet joined to +2/+0xC record access in one function.')
        print('NEXT: trace the best dynamic mapper caller backward one function boundary to its record lookup.')
    else:
        print('RESULT: no direct ldrh-r0 -> ROOT_MAPPER pattern found in the bounded scan.')
        print('NEXT: widen register dataflow one function boundary around the registry accessor.')
    print(); print('PHONE ACCESSED       : NO'); print('FLASH MODIFIED       : NO'); print('PATCH GENERATED      : NO'); print('HARDWARE WRITE AUTHORIZED: NO')

def main():
    report=Path.cwd()/'research/f2/work/reports/s13_5a59_b702_runtime_child_enumerator_trace.txt'; report.parent.mkdir(parents=True,exist_ok=True)
    with report.open('w',encoding='utf-8',newline='\n') as fp:
        tee=Tee(sys.stdout,fp)
        with redirect_stdout(tee):
            try: body(); print(); print('='*120); print('EXIT CODE = 0'); print('='*120); return 0
            except Exception: print(); print('='*120); print('EXCEPTION'); print('='*120); traceback.print_exc(file=tee); print('EXIT CODE = 1'); return 1

if __name__=='__main__': raise SystemExit(main())
