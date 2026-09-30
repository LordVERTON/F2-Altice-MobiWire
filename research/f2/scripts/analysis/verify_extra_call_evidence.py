"""Independent checks of byte provenance and the concrete conclusions in the report."""
import hashlib
import json
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inspect_alice_details import ROOT,load
from analyze_alice_extra_calls import calls,norm
from _paths import ALTICE_ALICE, QMOBILE_ALICE

q,a=load('qmobile_normalized'),load('altice')
expected={
    str(QMOBILE_ALICE/'alice-py.bin'):'25b10ac9ab0d5cc7fe4602c20ace6cd8bab2efd9e2ce7ac9aa55404a6fee18dc',
    str(ALTICE_ALICE/'alice-py.bin'):'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea',
}
checks={}
for name,digest in expected.items():
    actual=hashlib.sha256(Path(name).read_bytes()).hexdigest()
    assert actual==digest, (name,actual)
    checks[name+' unchanged']=actual
for qe,ae in [('103fe67c','10289d10'),('104323d4','102d82d0')]:
    qi,ai=q[qe]['instructions'],a[ae]['instructions']
    assert list(map(norm,qi))==list(map(norm,ai)),(qe,ae)
    assert len(calls(q[qe]))==len(calls(a[ae]))
    mapping={x['address']:y['address'] for x,y in zip(qi,ai)}
    for x,y in zip(qi,ai):
        if x['jump']:
            assert [mapping.get(t) for t in x['targets']]==y['targets'],(x,y)
    checks[qe+' <-> '+ae]=dict(instructions=len(qi),calls=len(calls(q[qe])),
        operands_equal_after_relocation=True,all_internal_branch_destinations_match=True)
i=next(i for i in q['10415c14']['instructions'] if i['address']=='10415cdc')
hi,lo=struct.unpack('<HH',bytes.fromhex(i['hex']))
assert hi&0xf800==0xf000 and lo&0xf800==0xf800
displacement=((hi&0x7ff)<<12)|((lo&0x7ff)<<1)
if displacement&0x400000: displacement-=0x800000
decoded=(int(i['address'],16)+4+displacement)&0xffffffff
assert decoded==0x10394dcc,hex(decoded)
assert q['10394dcc']['bytes']==26
assert len(q['10394dcc']['instructions'])==11
assert [c['targets'][0] for c in calls(q['10394dcc'])]==['10300eb4','1032668c']
assert len(calls(q['10415c14']))==len(calls(a['102c6f8c']))+1
assert len(q['10415c14']['instructions'])==len(a['102c6f8c']['instructions'])+6
assert {r['from'] for r in q['10394dcc']['incoming']}=={'10415cdc','102c4d4c'}
checks['10415cdc BL independently decoded']=dict(bytes=i['hex'],target=f'{decoded:08x}',
    target_bytes=26,target_instructions=11,target_calls=2)
assert all(i['length']==4 for i in q['104323d4']['instructions'])
checks['third candidate entirely ARM']=True
(ROOT/'extra_call_validation.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
print('PASS: source hashes, full operand alignments, internal branches, independent BL target, call counts and references.')
