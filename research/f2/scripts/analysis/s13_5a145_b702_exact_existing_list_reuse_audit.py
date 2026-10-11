#!/usr/bin/env python3
"""S13.5A.145: test exact pre-existing 6-byte B702 child-list reuse.

Constrained read-only hypothesis; NOT a padding scan, ROM allocation, patch, or
proof of pointer alias/runtime loading. Reuses historical A111 static layout.
"""
from __future__ import annotations
import argparse
import hashlib
import struct
from pathlib import Path

ALICE_SHA = '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
ZIMAGE_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
BOOT_SHA = 'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'
ALICE_SIZE, ZIMAGE_SIZE, BOOT_SIZE = 0x157BB4, 0x185E98, 0x4B06C
ZBASE = 0xF023CA50
RECORDS, DESCRIPTOR, RANGES = 0xF0378760, 0xF037C08C, 0xF037BF54
B702_IDX, B703_IDX, AUDIO_IDX = 884, 885, 490
EXPECTED = struct.pack('<HHH', 0x8569, 0x87ED, 0x8928)

def guard(path: Path, expected_size: int, sha: str, label: str) -> bytes:
    if not path.is_file():
        raise RuntimeError(f'MISSING_{label}={path}')
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != expected_size or actual != sha:
        raise RuntimeError(f'{label}_HASH_OR_SIZE_MISMATCH actual_size={len(data)} actual_sha256={actual}')
    return data

def get(data: bytes, address: int, size: int) -> bytes:
    off = address - ZBASE
    if off < 0 or off + size > len(data):
        raise RuntimeError(f'OUTSIDE_ZIMAGE=0x{address:08X} size={size}')
    return data[off:off+size]

def u16(data: bytes, address: int) -> int:
    return struct.unpack('<H', get(data,address,2))[0]

def u32(data: bytes, address: int) -> int:
    return struct.unpack('<I', get(data,address,4))[0]

def record(data: bytes, i: int) -> tuple[int,int,int]:
    a = RECORDS + 16*i
    return u16(data,a),u16(data,a+2),u32(data,a+12)

def intersections(a:int,b:int,c:int,d:int)->bool:
    return a<d and c<b

def find_all(blob:bytes, value:bytes)->list[int]:
    out=[]; start=0
    while True:
        i=blob.find(value,start)
        if i<0:break
        out.append(i)
        start=i+1
    return out

def self_test()->None:
    t=b'X'+EXPECTED+b'YY'+EXPECTED+b'Z'
    assert find_all(t,EXPECTED)==[1,9]
    assert intersections(1,7,6,9) and not intersections(1,7,7,9)
    assert struct.unpack('<HHH',EXPECTED)==(0x8569,0x87ED,0x8928)
    print('A145_SELF_TEST=PASS')

def analyze(args:argparse.Namespace)->None:
    root=Path(args.root)
    alice=root/'research/f2/work/extracted/altice_alice/alice-py.bin'
    zimage=root/'research/f2/work/extracted/altice_platform/zimage.bin'
    boot=Path(args.boot)
    guard(alice,ALICE_SIZE,ALICE_SHA,'ALICE')
    z=guard(zimage,ZIMAGE_SIZE,ZIMAGE_SHA,'ZIMAGE')
    guard(boot,BOOT_SIZE,BOOT_SHA,'BOOT_ZIMAGE')
    lines=['S13.5A.145 - EXACT PREEXISTING B702 CHILD LIST REUSE',
           'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_PATCH_FLASH_REPACK=YES',
           'METHOD=EXACT_6_BYTE_SEQUENCE_SEARCH_NOT_PADDING_OR_FREE_SPACE_SCAN',
           'ALICE_GUARD=PASS','ZIMAGE_GUARD=PASS','BOOT_ZIMAGE_GUARD=PASS']
    if u32(z,DESCRIPTOR)!=RECORDS or u32(z,DESCRIPTOR+4)!=RANGES or u16(z,DESCRIPTOR+8)!=52:
        raise RuntimeError('STATIC_DESCRIPTOR_MISMATCH')
    b702=record(z,B702_IDX);b703=record(z,B703_IDX);audio=record(z,AUDIO_IDX)
    if b702 != (0xB709,2,0xF0378720) or b703[1:] != (2,0xF0378724) or audio[0]!=0xB702:
        raise RuntimeError('B702_B703_AUDIO_RECORD_MISMATCH')
    if get(z,0xF0378720,6)!=struct.pack('<HHH',0x8569,0x87ED,0xA07B):
        raise RuntimeError('B702_B703_POOL_ADJACENCY_MISMATCH')
    lines.extend(['A111_B702_STATIC_ANCHORS=PASS',
                  'DESIRED_LIST='+','.join(f'0x{x:04X}' for x in (0x8569,0x87ED,0x8928)),
                  'CURRENT_B702_CHILD_PTR=0xF0378720 COUNT=2',
                  'CURRENT_B703_CHILD_PTR=0xF0378724 COUNT=2'])
    owned=[]; invalid=[]
    for i in range(895):
        parent,count,ptr=record(z,i)
        if not count:continue
        end=ptr+2*count
        if count>4096 or ptr&1 or ptr<ZBASE or end>ZBASE+len(z) or end<ptr:
            invalid.append((i,ptr,count));continue
        owned.append((i,ptr,end))
    if invalid:
        raise RuntimeError(f'UNCLASSIFIED_NONEMPTY_LISTS={len(invalid)}')
    found=find_all(z,EXPECTED)
    lines.extend([f'VALID_CHILD_LIST_INTERVALS={len(owned)}',f'EXACT_6BYTE_OCCURRENCES_TOTAL={len(found)}'])
    for off in found:
        addr=ZBASE+off
        aligned=addr%2==0
        owners=[i for i,start,end in owned if intersections(addr,addr+6,start,end)]
        overlaps_struct=intersections(addr,addr+6,RECORDS,RECORDS+895*16) or intersections(addr,addr+6,RANGES,RANGES+52*6) or intersections(addr,addr+6,DESCRIPTOR,DESCRIPTOR+12)
        lines.append(f'EXACT_LIST_LOCATION=0x{addr:08X} ALIGNED_U16={"YES" if aligned else "NO"} '+
                     f'EXISTING_CHILD_OWNERS={",".join(map(str,owners)) if owners else "NONE"} '+
                     f'OVERLAPS_REGISTRY_METADATA={"YES" if overlaps_struct else "NO"} '+
                     'RUNTIME_SAFE=UNPROVEN')
    potentially=[off for off in found if ((ZBASE+off)%2==0 and
                   not any(intersections(ZBASE+off,ZBASE+off+6,start,end) for _,start,end in owned) and
                   not intersections(ZBASE+off,ZBASE+off+6,RECORDS,RECORDS+895*16) and
                   not intersections(ZBASE+off,ZBASE+off+6,RANGES,RANGES+52*6) and
                   not intersections(ZBASE+off,ZBASE+off+6,DESCRIPTOR,DESCRIPTOR+12))]
    lines.extend([f'EXACT_SEQUENCE_NONCHILD_NONMETADATA_ALIGNED_LOCATIONS={len(potentially)}',
                  'NOTE=ANY_MATCH_MAY_BE_CODE_OR_RESOURCE_AND_IS_NOT_PROVEN_REUSABLE',
                  'NOTE=NO_MATCH_CANNOT_RULE_OUT_RELOCATION_WITH_NEW_STORAGE',
                  'RUNTIME_F007F044_ALIASES_STATIC_RECORDS=UNPROVEN',
                  'UI_OK_TO_AUDIO_LAUNCHER=UNPROVEN',
                  'RELOCATION_DESTINATION_VERIFIED=NO',
                  'PATCH_FLASH_READY=NO',
                  'A145_EXACT_LIST_REUSE_AUDIT=PASS',
                  'NEXT=IF_NO_MATCH_CLOSE_EXACT_PREEXISTING_LIST_REUSE;DO_NOT_REPEAT_PADDING_CENSUS'])
    p=Path(args.out)
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x',encoding='utf8') as f:f.write('\n'.join(lines)+'\n')
    print('A145_EXACT_LIST_REUSE_AUDIT=PASS')
    print('A145_REPORT='+str(p))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--root',default=r'C:\Users\verto\F2-Altice-MobiWire')
    parser.add_argument('--boot',default=r'C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin')
    parser.add_argument('--out',default=None)
    a=parser.parse_args()
    if a.self_test:self_test()
    else:
        if a.out is None:parser.error('--out required')
        analyze(a)
