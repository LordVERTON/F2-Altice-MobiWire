"""Rank candidate homologues using instruction and operand sequences, never addresses."""
from collections import defaultdict
from functools import lru_cache
import difflib
import hashlib
import json
from analyze_alice_extra_calls import norm, calls, target, PAIRS, compare, summary
from inspect_alice_details import ROOT, load

def fingerprint(f):
    return hashlib.sha256(','.join(i['mnemonic'] for i in f['instructions']).encode()).hexdigest()

def grams(seq):
    return {tuple(seq[i:i+4]) for i in range(len(seq)-3)}

class Matcher:
    def __init__(self,q,a):
        self.q,self.a=q,a
        self.prep={}
        self.index=defaultdict(set)
        for side,fs in [('q',q),('a',a)]:
            for e,f in fs.items():
                mn=tuple(i['mnemonic'] for i in f['instructions'])
                op=tuple(norm(i) for i in f['instructions'])
                self.prep[side,e]=(mn,op,grams(mn),fingerprint(f))
                if side=='a':
                    for g in grams(mn): self.index[g].add(e)

    @lru_cache(None)
    def score(self,qe,ae):
        if qe not in self.q or ae not in self.a: return None
        qm,qo,qg,qh=self.prep['q',qe]; am,ao,ag,ah=self.prep['a',ae]
        if not qm or not am: return None
        mr=difflib.SequenceMatcher(None,qm,am,autojunk=False).ratio()
        op=difflib.SequenceMatcher(None,qo,ao,autojunk=False).ratio()
        jac=len(qg&ag)/max(1,len(qg|ag))
        qc,ac=len(calls(self.q[qe])),len(calls(self.a[ae]))
        return dict(score=round(.50*op+.35*mr+.15*jac,4),mnemonic=round(mr,4),
                    operands=round(op,4),jaccard=round(jac,4),hash_equal=qh==ah,
                    q_ins=len(qm),a_ins=len(am),q_calls=qc,a_calls=ac,q_hash=qh,a_hash=ah)

    def best(self,qe,limit=5):
        if qe not in self.q: return []
        qm,qo,qg,qh=self.prep['q',qe]
        if not qm: return []
        options=defaultdict(int)
        for g in qg:
            for ae in self.index[g]: options[ae]+=1
        if len(qm)<8:
            options={ae:1 for ae in self.a if self.prep['a',ae][0]==qm}
        ranking=[]
        for ae,n in options.items():
            am,ao,ag,ah=self.prep['a',ae]
            if not .55<=len(am)/len(qm)<=1.8: continue
            ranking.append((n/max(1,len(qg|ag)),ae))
        result=[]
        for _,ae in sorted(ranking,reverse=True)[:40]:
            s=self.score(qe,ae)
            if s: result.append(dict(altice=ae,**s))
        return sorted(result,key=lambda r:r['score'],reverse=True)[:limit]

    def call_structure(self,qe,ae):
        if qe not in self.q or ae not in self.a: return []
        result=[]
        for tag,x,y in compare(self.q[qe],self.a[ae]):
            if (x and x['call']) or (y and y['call']):
                qt=target(x) if x and x['call'] else None
                at=target(y) if y and y['call'] else None
                s=self.score(qt,at) if qt and at else None
                result.append(dict(qsite=x['address'] if x else None,
                                   asite=y['address'] if y else None,
                                   qtarget=qt,atarget=at,evidence=s))
        return result

def main():
    q,a=load('qmobile_normalized'),load('altice')
    matcher=Matcher(q,a)
    report=[]; data=[]
    for old,ae in PAIRS:
        qe='103fe67c' if old=='103fe66a' else old
        if qe not in q:
            report.append(qe+' NOT FOUND after normalization'); continue
        f,g=q[qe],a[ae]
        report.append('\n'+summary(f)+' <-> '+summary(g))
        aligned=compare(f,g)
        item=dict(qmobile=qe,altice=ae,call_pairs=[],extra=[])
        for tag,x,y in aligned:
            if x and x['call']:
                qt=target(x)
                if y and y['call']:
                    at=target(y); s=matcher.score(qt,at)
                    best=matcher.best(qt,3)
                    entry=dict(qsite=x['address'],asite=y['address'],qtarget=qt,atarget=at,
                               evidence=s,alternatives=best,call_structure=matcher.call_structure(qt,at))
                    item['call_pairs'].append(entry)
                    report.append(f"{x['address']} -> {qt} <-> {y['address']} -> {at} {s}")
                    if best: report.append('  best '+str([(r['altice'],r['score']) for r in best]))
                else:
                    best=matcher.best(qt,5)
                    item['extra'].append(dict(site=x['address'],target=qt,best=best))
                    report.append('UNPAIRED '+x['address']+' '+qt+' '+str(best))
        data.append(item)
        (ROOT/f'normalized_{qe}_{ae}_instructions.txt').write_text('\n'.join(
            f"{t} {x['address']+' '+x['text'] if x else '':50s} | {y['address']+' '+y['text'] if y else ''}"
            for t,x,y in aligned),encoding='utf-8')
    (ROOT/'callee_matches.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
    (ROOT/'callee_matches.txt').write_text('\n'.join(report),encoding='utf-8')
    print('\n'.join(report))

if __name__=='__main__': main()
