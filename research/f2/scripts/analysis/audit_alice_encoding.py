import hashlib
import struct
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inspect_alice_details import load
from _paths import ALTICE_ALICE, QMOBILE_ALICE

for build,folder,base,entries in [
    ('qmobile',QMOBILE_ALICE,0x1018a598,[0x103fe66a,0x103fe706,0x10415cdc,0x102f13ba,0x102f13c2]),
    ('altice',ALTICE_ALICE,0x101812c4,[0x10289d10,0x10289d9a,0x102c703a])]:
    p=folder
    data=(p/'alice-py.bin').read_bytes()
    raw=(p/'alice-translated-py.bin').read_bytes()
    print(build,'identical?',data==raw,'changed bytes',sum(a!=b for a,b in zip(data,raw)))
    for name in ('alice-py.bin','alice-translated-py.bin'):
        b=(p/name).read_bytes()
        print(name,len(b),hashlib.sha256(b).hexdigest())
    for addr in entries:
        off=addr-base
        print(hex(addr),'offset',hex(off),'py',data[off:off+16].hex(' '),'translated',raw[off:off+16].hex(' '))
    fs=load(build)
    calls=[i for f in fs.values() for i in f['instructions'] if i['call']]
    direct=[i for i in calls if i['targets']]
    inside=[i for i in direct if base<=int(i['targets'][0],16)<base+len(data)]
    known=[i for i in direct if i['targets'][0] in fs]
    print('Call sites',len(calls),'direct',len(direct),'inside ALICE',len(inside),'known entry',len(known))
