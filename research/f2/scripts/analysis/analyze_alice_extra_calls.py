"""Offline comparison of read-only Ghidra instruction exports."""
import difflib
import hashlib
import json
import re
from pathlib import Path
from inspect_alice_details import ROOT, load

PAIRS = [('103fe66a','10289d10'), ('10415c14','102c6f8c'),
         ('104323d4','102d82d0'), ('102f13b6','10220344'),
         ('10314ca8','1024ec0c'), ('103512f0','1027a1b0'), ('10408eda','1024a55c')]

def norm(i):
    # Keep registers, small constants and offsets. Abstract relocated addresses only.
    return re.sub(r'0x[0-9a-fA-F]{7,8}', '<addr>', i['text'])

def calls(f):
    return [i for i in f['instructions'] if i['call']]

def target(i):
    return ','.join(i['targets']) or 'INDIRECT:' + ','.join(i['operands'])

def summary(f):
    return f"{f['entry']} bytes={f['bytes']} ins={len(f['instructions'])} calls={len(calls(f))}"

def compare(q,a):
    qi,ai=q['instructions'],a['instructions']
    sm=difflib.SequenceMatcher(None,list(map(norm,qi)),list(map(norm,ai)),autojunk=False)
    rows=[]
    for tag,i,j,k,l in sm.get_opcodes():
        if tag=='equal':
            rows += [('=',x,y) for x,y in zip(qi[i:j],ai[k:l])]
        else:
            # Preserve every instruction; replacements are deliberately not claimed homologous.
            rows += [('-',x,None) for x in qi[i:j]]
            rows += [('+',None,y) for y in ai[k:l]]
    return rows

def main():
    qf,af=load('qmobile'),load('altice')
    lines=[]
    for qe,ae in PAIRS:
        q,a=qf[qe],af[ae]
        lines += ['\nCANDIDATE '+summary(q)+' <-> '+summary(a),'QMOBILE CALLS']
        lines += [i['address']+' '+i['text']+' '+target(i) for i in calls(q)]
        lines += ['ALTICE CALLS']+[i['address']+' '+i['text']+' '+target(i) for i in calls(a)]
        rows=compare(q,a)
        lines += ['DIFFERENCES (addresses abstracted, registers/constants retained)']
        for tag,x,y in rows:
            if tag!='=' or (x and x['call']):
                lines.append(f"{tag} {x['address']+' '+x['text'] if x else '':50s} | {y['address']+' '+y['text'] if y else ''}")
        (ROOT / f'candidate_{qe}_{ae}_instructions.txt').write_text('\n'.join(
            f"{t} {x['address']+' '+x['text'] if x else '':50s} | {y['address']+' '+y['text'] if y else ''}"
            for t,x,y in rows),encoding='utf-8')
        (ROOT / f'candidate_{qe}_{ae}_decompiled.txt').write_text(
            'QMOBILE\n'+q.get('decompiled','')+'\nALTICE\n'+a.get('decompiled',''),encoding='utf-8')
    (ROOT/'extra_call_preliminary.txt').write_text('\n'.join(lines),encoding='utf-8')
    print('\n'.join(lines))

if __name__=='__main__':
    main()
