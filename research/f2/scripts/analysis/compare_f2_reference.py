#!/usr/bin/env python3
"""Measure firmware proximity from ExportAliceDetails JSONL files.

This ranks a comparison witness technically. Scores do not identify media apps.
Application claims require menu/FM/Image Viewer call-graph anchors in the report.
"""
import argparse
from collections import Counter, defaultdict
import difflib
import hashlib
import json
from pathlib import Path
import re
import statistics

ADDR = re.compile(r'0x[0-9a-fA-F]{7,8}')
ANCHOR = re.compile(r'audio|mp3|audply|video|vdoply|multimedia|fmr|radio|image|imgview|camera|recorder',re.I)

def load(path):
    with open(path,encoding='utf-8-sig') as f:
        return [json.loads(line) for line in f if line.strip()]

def canonical(i): return ADDR.sub('<reloc>',i.get('text','').lower())
def fp(seq): return hashlib.sha256('\n'.join(seq).encode()).hexdigest()
def ngrams(seq,n=4):
    if len(seq)<n: return {tuple(seq)} if seq else set()
    return {tuple(seq[i:i+n]) for i in range(len(seq)-n+1)}
def calls(f): return [i for i in f.get('instructions',[]) if i.get('call')]
def call_edges(f):
    return tuple(t for i in calls(f) for t in i.get('targets',[]))
def seq(f): return tuple(canonical(i) for i in f.get('instructions',[]))
def ins_hash(f): return fp(seq(f))

def match(q,a):
    aseq={f['entry']:seq(f) for f in a}
    qseq={f['entry']:seq(f) for f in q}
    exact_mn=defaultdict(list); exact_op=defaultdict(list); index=defaultdict(set)
    amap={f['entry']:f for f in a}; qmap={f['entry']:f for f in q}
    for f in a:
        s=aseq[f['entry']]
        if len(s)<8: continue
        exact_mn[fp([i.get('mnemonic','') for i in f['instructions']])].append(f['entry'])
        exact_op[fp(s)].append(f['entry'])
        for gram in ngrams(s): index[gram].add(f['entry'])
    proposals=[]; sim_index={}
    for f in q:
        s=qseq[f['entry']]
        if len(s)<8: continue
        grams=ngrams(s); hits=Counter()
        for g in grams:
            for ae in index.get(g,()): hits[ae]+=1
        ranked=[]
        for ae,overlap in hits.items():
            other=aseq[ae]
            ratio=len(other)/len(s)
            if not .55<=ratio<=1.8: continue
            jac=overlap/max(1,len(grams|ngrams(other)))
            ranked.append((jac,ae))
        ranked.sort(reverse=True)
        best=[]
        for jac,ae in ranked[:20]:
            other=aseq[ae]
            sm=difflib.SequenceMatcher(None,s,other,autojunk=False)
            operand=sm.ratio()
            mn=difflib.SequenceMatcher(None,[i.get('mnemonic','') for i in qmap[f['entry']]['instructions']],
                                       [i.get('mnemonic','') for i in amap[ae]['instructions']],autojunk=False).ratio()
            # Call-site topology: number/order/indirect-vs-direct plus mapped callee fingerprints.
            qc,ac=calls(qmap[f['entry']]),calls(amap[ae])
            shape=1-abs(len(qc)-len(ac))/max(1,len(qc),len(ac))
            score=.50*operand+.30*mn+.12*jac+.08*shape
            rec={'q':f['entry'],'a':ae,'score':round(score,5),'operands':round(operand,5),
                 'mnemonics':round(mn,5),'ngrams':round(jac,5),'call_shape':round(shape,5),
                 'q_ins':len(s),'a_ins':len(other),'q_calls':len(qc),'a_calls':len(ac),
                 'q_call_targets':list(call_edges(qmap[f['entry']])),
                 'a_call_targets':list(call_edges(amap[ae])),
                 'q_fp':ins_hash(qmap[f['entry']]),'a_fp':ins_hash(amap[ae])}
            best.append(rec)
        if best:
            best.sort(key=lambda x:x['score'],reverse=True)
            proposals.extend(best[:3]); sim_index[f['entry']]=best
    # Greedy one-to-one assignment avoids inflating common-code counts.
    proposals.sort(key=lambda x:x['score'],reverse=True)
    mapping={}; reverse={}
    for p in proposals:
        if p['score']<.68: break
        if p['q'] not in mapping and p['a'] not in reverse:
            mapping[p['q']]=p['a']; reverse[p['a']]=p['q']
    exactop=set(exact_op)&set(fp([i.get('mnemonic','') for i in f['instructions']]) for f in q)
    exact_mn_count=sum(min(sum(1 for f in q if fp([i.get('mnemonic','') for i in f['instructions']])==k),len(v)) for k,v in exact_mn.items())
    exact_op_count=sum(min(sum(1 for f in q if ins_hash(f)==k),len(v)) for k,v in exact_op.items())
    q_total=sum(len(f.get('instructions',[])) for f in q)
    a_total=sum(len(f.get('instructions',[])) for f in a)
    pairs=[]; aligned_total=0; edge_total=0; edge_hits=0; addr_deltas=[]
    qbase=min((int(f['entry'],16) for f in q),default=0)
    abase=min((int(f['entry'],16) for f in a),default=0)
    for qe,ae in mapping.items():
        f,g=qmap[qe],amap[ae]; s=seq(f); t=aseq[ae]
        sm=difflib.SequenceMatcher(None,s,t,autojunk=False)
        aligned=sum(n for _,_,n in sm.get_matching_blocks())
        aligned_total+=aligned
        qe_calls=[x for x in call_edges(f) if x in mapping]
        ae_calls=set(call_edges(g))
        edge_total+=len(qe_calls)
        edge_hits+=sum(1 for x in qe_calls if mapping[x] in ae_calls)
        addr_deltas.append(abs((int(qe,16)-qbase)-(int(ae,16)-abase)))
        pairs.append({'q':qe,'a':ae,'instructions':len(s),'aligned':aligned,
                      'q_bytes':f.get('bytes'),'a_bytes':g.get('bytes'),
                      'q_calls':len(calls(f)),'a_calls':len(calls(g)),
                      'q_fingerprint':ins_hash(f),'a_fingerprint':ins_hash(g),
                      'call_edges_mapped_q':len(qe_calls),'call_edges_matched':sum(1 for x in qe_calls if mapping[x] in ae_calls)})
    q_strings=[]; a_strings=[]
    for side,fs,dest in [('witness',q,q_strings),('altice',a,a_strings)]:
        for f in fs:
            for i in f.get('instructions',[]):
                for r in i.get('refs',[]):
                    val=r.get('string')
                    if val and ANCHOR.search(str(val)):
                        dest.append({'function':f['entry'],'site':i['address'],'reference':r,'text':str(val)[:200]})
    report={
      'witness_functions':len(q),'altice_functions':len(a),
      'exact_mnemonic_sequence_matches':exact_mn_count,
      'exact_relocated_instruction_sequence_matches':exact_op_count,
      'one_to_one_high_confidence_function_pairs':len(mapping),
      'aligned_instructions':aligned_total,
      'alignable_proportion_vs_smaller_image':round(aligned_total/max(1,min(q_total,a_total)),5),
      'call_graph_edges_from_mapped_functions':edge_total,
      'call_graph_edges_preserved':edge_hits,
      'call_graph_edge_preservation':round(edge_hits/max(1,edge_total),5),
      'median_relative_address_delta_bytes':int(statistics.median(addr_deltas)) if addr_deltas else None,
      'interpretation':'Technical proximity score inputs only; application/menu identification requires anchored evidence.',
      'top_pairs':sorted(pairs,key=lambda p:p['aligned'],reverse=True)[:500],
      'best_candidate_per_witness_function':{k:v[:3] for k,v in sim_index.items()},
      'string_anchor_references':{'witness':q_strings,'altice':a_strings}}
    return report

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--witness',required=True); ap.add_argument('--altice',required=True)
    ap.add_argument('--out',required=True); ap.add_argument('--label',default='reference witness')
    args=ap.parse_args()
    result=match(load(args.witness),load(args.altice)); result['witness_label']=args.label
    Path(args.out).write_text(json.dumps(result,indent=2),encoding='utf-8')
    print('Witness:',args.label)
    for key in ('witness_functions','altice_functions','exact_mnemonic_sequence_matches',
                'exact_relocated_instruction_sequence_matches','one_to_one_high_confidence_function_pairs',
                'aligned_instructions','alignable_proportion_vs_smaller_image','call_graph_edge_preservation'):
        print(f'{key}: {result[key]}')
    print('Report:',args.out)

if __name__=='__main__': main()
