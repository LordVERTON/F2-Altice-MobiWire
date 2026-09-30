from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inspect_alice_details import load
from _paths import QMOBILE_ALICE

q=load('qmobile_normalized'); a=load('altice')
raw=(QMOBILE_ALICE/'alice-py.bin').read_bytes()
print('FIRST CANDIDATE: literal pool words before real prologue')
for address in range(0x103fe664,0x103fe67c,4):
    print(hex(address),hex(struct.unpack_from('<I',raw,address-0x1018a598)[0]))
for f in q.values():
    for i in f['instructions']:
        for r in i['refs']:
            try: addr=int(r['to'],16)
            except ValueError: continue
            if 0x103fe664<=addr<0x103fe67c:
                print('POOL REF',f['entry'],i['address'],i['text'],r)
for build,fs,entries in [('Q',q,['103fe67c','10415c14','104323d4','10314caa','10314cac']),('A',a,['10289d10','102c6f8c','102d82d0'])]:
    for e in entries:
        if e not in fs: continue
        f=fs[e]
        print(build,e,'incoming',f['incoming'])
        print('HEAD',[(i['address'],i['text']) for i in f['instructions'][:5]])
        print('TAIL',[(i['address'],i['text']) for i in f['instructions'][-7:]])
print('NORMALIZED CALL METRICS')
for build,fs,base,size in [('Q',q,0x1018a598,len(raw)),('A',a,0x101812c4,1407924)]:
    cs=[i for f in fs.values() for i in f['instructions'] if i['call']]
    ds=[i for i in cs if i['targets']]
    known=[i for i in ds if i['targets'][0] in fs]
    print(build,'functions',len(fs),'calls',len(cs),'direct',len(ds),'known',len(known))
    if build=='Q':
        for f in fs.values():
            for i in f['instructions']:
                if i['address']=='10314ca8': print('OLD FAKE ENTRY NOW',f['entry'],i)
