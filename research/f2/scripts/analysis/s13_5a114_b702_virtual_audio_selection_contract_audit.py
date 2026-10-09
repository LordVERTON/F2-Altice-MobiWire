#!/usr/bin/env python3
"""S13.5A.114: read-only hypothetical B702 child-list / native resolver contract.

NOT a CPU emulator, patch, binary writer, loader model, or proof of a user
selection launching Audio. A hypothetical third entry is constructed solely as
an immutable Python tuple; the ALICE and ZIMAGE firmware images are read-only.

All runtime dispatch conclusions remain UNPROVEN. This specifically reuses
prior S13.5A.10/97 child index/ID contracts and S11/A87 native resolver facts;
it is a bounded *cross-layer differential check*, not a repeated code census.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import struct

ALICE_SIZE = 0x157BB4
ALICE_SHA = '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
RECORD_BASE = 0xF0378760
RECORD_SIZE = 0x10
RECORD_COUNT = 895
DESC_ADDR = 0xF037C08C
RANGES = 0xF037BF54
POOL = 0xF0378720
RESOLVER_START = 0xF0345E68
RESOLVER_COUNT = 58
RESOLVER_STEP = 8
KNOWN_DENSE = {0x8928:490, 0xB702:884, 0xB703:885, 0xB709:891}
B702_ORIGINAL = (0x8569,0x87ED)
B702_VIRTUAL = (0x8569,0x87ED,0x8928)
NATIVE_CALLBACKS = {0x87ED:0xF02F3F9D, 0x8928:0x1033D841, 0x86C0:0x1033E26D}
REPORT_NAME = 's13_5a114_b702_virtual_audio_selection_contract_audit.txt'


def abort(msg: str) -> None:
    raise RuntimeError('A114_ABORT: ' + msg)


def read_guard(path: Path, size: int, sha256: str, label: str) -> bytes:
    if not path.is_file():
        abort(f'{label} not found: {path}')
    result = path.read_bytes()
    digest = hashlib.sha256(result).hexdigest()
    if len(result)!=size or digest!=sha256:
        abort(f'{label} mismatch size=0x{len(result):X} sha256={digest}')
    return result


def take(blob: bytes, addr: int, length: int) -> bytes:
    offset = addr-ZIMAGE_BASE
    if length < 0 or offset < 0 or offset+length > len(blob):
        abort(f'ZIMAGE out-of-bounds at 0x{addr:08X} len={length}')
    return blob[offset:offset+length]


def u16(blob: bytes, addr: int) -> int:
    return struct.unpack('<H',take(blob,addr,2))[0]


def u32(blob: bytes, addr: int) -> int:
    return struct.unpack('<I',take(blob,addr,4))[0]


def record(blob: bytes, index: int) -> dict[str,int]:
    if not 0<=index<RECORD_COUNT:
        abort(f'record index outside canonical table: {index}')
    addr = RECORD_BASE + index*RECORD_SIZE
    return {'addr':addr,'parent':u16(blob,addr),'count':u16(blob,addr+2),'ptr':u32(blob,addr+12)}


def id_at(index: int, entries: tuple[int,...]) -> int:
    # High-level mathematical model of a proven descriptor+0x40/+0x48 ABI.
    # Does NOT execute or prove live runtime ALICE instructions.
    return entries[index] if 0<=index<len(entries) else 0xFFFF


def index_of(identifier: int, entries: tuple[int,...]) -> int:
    try:
        return entries.index(identifier)
    except ValueError:
        return 0xFFFFFFFF


def resolver_rows(blob: bytes) -> list[tuple[int,int,int]]:
    out = []
    for idx in range(RESOLVER_COUNT):
        addr = RESOLVER_START+idx*RESOLVER_STEP
        out.append((u32(blob,addr),u32(blob,addr+4),addr))
    return out


def render_list(entries: tuple[int,...]) -> str:
    return ','.join(f'0x{value:04X}' for value in entries)


def self_test() -> None:
    assert RECORD_BASE + 884*0x10==0xF037BEA0
    assert RECORD_BASE + 490*0x10==0xF037A600
    assert id_at(2,B702_ORIGINAL)==0xFFFF
    assert index_of(0x8928,B702_ORIGINAL)==0xFFFFFFFF
    assert id_at(2,B702_VIRTUAL)==0x8928
    assert index_of(0x8928,B702_VIRTUAL)==2
    for i,idv in enumerate(B702_VIRTUAL):
        assert index_of(id_at(i,B702_VIRTUAL),B702_VIRTUAL)==i
    assert B702_VIRTUAL[:2]==B702_ORIGINAL
    assert struct.pack('<HHH',*B702_VIRTUAL)==bytes.fromhex('6985ed872889')
    assert RESOLVER_START+14*8==0xF0345ED8
    assert RESOLVER_START+22*8==0xF0345F18
    assert POOL+len(B702_ORIGINAL)*2==0xF0378724
    # A synthetic in-memory resolver with an Image positive control and Audio.
    fake = bytearray(64)
    struct.pack_into('<II',fake,8,0x87ED,0xF02F3F9D)
    struct.pack_into('<II',fake,16,0x8928,0x1033D841)
    assert struct.unpack_from('<II',fake,16)==(0x8928,0x1033D841)
    print('A114_SELF_TEST=PASS VIRTUAL_INDEX_ROUNDTRIP_LIST_PACK_AND_RESOLVER_LAYOUT')


def assess(alice: bytes, zimg: bytes) -> str:
    if (u32(zimg,DESC_ADDR),u32(zimg,DESC_ADDR+4),u16(zimg,DESC_ADDR+8)) != (RECORD_BASE,RANGES,52):
        abort('canonical registry descriptor drift')
    b702 = record(zimg,KNOWN_DENSE[0xB702])
    b703 = record(zimg,KNOWN_DENSE[0xB703])
    b709 = record(zimg,KNOWN_DENSE[0xB709])
    audio = record(zimg,KNOWN_DENSE[0x8928])
    if (b702['parent'],b702['count'],b702['ptr'])!=(0xB709,2,POOL):
        abort('B702 static record changed')
    if (b703['count'],b703['ptr'])!=(2,POOL+4):
        abort('B703 adjacent record changed')
    if (b709['count'],audio['parent'])!=(9,0xB702):
        abort('B709/Audio record differs from A111')
    if tuple(u16(zimg,POOL+2*i) for i in range(3))!=(0x8569,0x87ED,0xA07B):
        abort('B702/B703 packed array differs')
    rows = resolver_rows(zimg)
    resolved: dict[int,tuple[int,int]]={}
    for wanted,callback in NATIVE_CALLBACKS.items():
        matches=[(cb,addr) for ident,cb,addr in rows if ident==wanted]
        if len(matches)!=1 or matches[0][0]!=callback:
            abort(f'expected native resolver row mismatch id=0x{wanted:04X} matches={matches}')
        resolved[wanted]=matches[0]
    # Historical positive anchor controls show row14/22 are stable.
    if resolved[0x87ED][1]!=0xF0345ED8 or resolved[0x8928][1]!=0xF0345F18:
        abort('A87 resolver rows relocated unexpectedly')
    lines = [
        'S13.5A.114 — B702 VIRTUAL AUDIO EXPOSURE / NATIVE RESOLVER DIFFERENTIAL',
        'STRICTLY_OFFLINE=YES SOURCE_IMAGES_READ_ONLY=YES VIRTUAL_LIST_ONLY=YES',
        'NO_PHONE_USB_COM_NOTEPAD_FLASH_REPACK_PATCH_EMULATOR_EDIT=YES',
        f'ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={ALICE_SHA}',
        f'ZIMAGE_GUARD=PASS SIZE=0x{len(zimg):X} SHA256={ZIMAGE_SHA}',
        'METHOD=PINNED_STATIC_CHILD_LIST_PLUS_PINNED_NATIVE_RESOLVER_AND_PURE_PYTHON_SHADOW_MODEL',
        'NOT_EXECUTED=THUMB_CPU_RUNTIME_ALICE_UI_HANDLERS_OR_ACTUAL_FIRMWARE_ACTION_DISPATCH',
        'PREVIOUSLY_CLASSIFIED=A111_A113_STORAGE;A10_A97_INDEX_TO_ID;S11_A87_NATIVE_RESOLVER',
        '',
        '=== A. CANONICAL STATIC CONTROLS ===',
        f'B702_RECORD=0x{b702["addr"]:08X} COUNT={b702["count"]} CHILD_PTR=0x{b702["ptr"]:08X}',
        f'B703_RECORD=0x{b703["addr"]:08X} COUNT={b703["count"]} CHILD_PTR=0x{b703["ptr"]:08X}',
        f'AUDIO_RECORD=0x{audio["addr"]:08X} PARENT=0x{audio["parent"]:04X} STATIC_CHILD_COUNT={audio["count"]}',
        f'CURRENT_B702_CHILDREN={render_list(B702_ORIGINAL)}',
        f'NEXT_16BIT_VALUE=0x{u16(zimg,POOL+4):04X} B703_FIRST=YES',
        'INPLACE_COUNT_ONLY=PROVEN_COLLISION_FROM_A111_NO_NEW_CANDIDATE_PROPOSED',
        '',
        '=== B. NATIVE 58x8 RESOLVER POSITIVE CONTROLS ===',
        f'RESOLVER_TABLE=0x{RESOLVER_START:08X} ROWS={RESOLVER_COUNT} STRIDE={RESOLVER_STEP}',
    ]
    for wanted in (0x87ED,0x8928,0x86C0):
        cb,addr=resolved[wanted]
        lines.append(f'RESOLVER_ID=0x{wanted:04X} ROW_ADDR=0x{addr:08X} CALLBACK_PTR=0x{cb:08X} MATCH=PASS')
    lines += [
        'CAUTION=CALLBACK_PTR_ARE_REGISTERED_INIT_RESOLVER_CALLBACKS_NOT_PROVEN_MENU_LEAF_LAUNCHERS',
        '',
        '=== C. MEMORY-ONLY DIFFERENTIAL (NOT EXECUTABLE FIRMWARE EMULATION) ===',
        f'ORIGINAL_LIST={render_list(B702_ORIGINAL)}',
        f'SHADOW_LIST={render_list(B702_VIRTUAL)}',
        f'SHADOW_ARRAY_BYTES_LE={struct.pack("<HHH",*B702_VIRTUAL).hex()}',
        'SOURCE_ROM_BYTES_CHANGED=NO; FIRMWARE_PATCH_EMITTED=NO',
    ]
    for label,entries in (('CURRENT',B702_ORIGINAL),('VIRTUAL',B702_VIRTUAL)):
        for i in range(4):
            ident = id_at(i,entries)
            back = index_of(ident,entries) if ident!=0xFFFF else 0xFFFFFFFF
            cb = next((r[1] for r in rows if r[0]==ident),None)
            cbtext=f'0x{cb:08X}' if cb is not None else 'NO_MATCH_IN_58_STATIC_ROWS'
            lines.append(f'{label} INDEX={i} MODEL_CHILD_ID=0x{ident:04X} MODEL_REVERSE_INDEX={back if back!=0xFFFFFFFF else "INVALID"} NATIVE_RESOLVER_PTR={cbtext}')
    lines += [
        '',
        '=== D. EVIDENCE / REQUIRED GATES ===',
        'ID_EXPOSURE_SHADOW_CONTRACT=PASS_HIGH_LEVEL_MODEL_ONLY',
        'NATIVE_8928_RESOLVER_ENTRY=PASS_STATIC_ROM',
        'REAL_B702_PROVIDER_RUNTIME_CHILD_LIST_AFTER_RELOCATION=UNPROVEN',
        'SELECT_OK_EVENT_SELECTED_ID_TO_NATIVE_APP_INVOCATION=UNPROVEN',
        'CALLBACK_1033D841_IS_DIRECT_LEAF_LAUNCHER=NOT_ESTABLISHED_REGISTRATION_CALLBACK_ONLY',
        'RELOCATION_STORAGE_AND_LOADER_INTEGRITY=UNPROVEN',
        'FM_RADIO_ROM_ID=UNKNOWN',
        'PHYSICAL_OR_EMULATOR_PATCH_READY=NO',
        'NEXT_NONREDUNDANT_EVIDENCE=REAL_SELECTED_87ED_POSITIVE_CONTROL_TO_LEAF_ACTION_DISPATCH_OR_TRUSTED_VIRTUAL_UI_HARNESS',
        'DO_NOT_REPEAT=A90_A110_GENERIC_EVENT_REGISTRY_OR_A112_A113_PADDING_HEURISTICS',
        'NO_PHONE_USB_COM_PATCH_FLASH_REPACK=YES',
    ]
    return '\n'.join(lines)+'\n'


def main()->None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=Path(r'C:\Users\verto\F2-Altice-MobiWire'))
    ap.add_argument('--out',type=Path)
    ap.add_argument('--self-test',action='store_true')
    args=ap.parse_args()
    self_test()
    if args.self_test:
        return
    root=args.root
    alice=read_guard(root/'research/f2/work/extracted/altice_alice/alice-py.bin',ALICE_SIZE,ALICE_SHA,'ALICE')
    zimg=read_guard(root/'research/f2/work/extracted/altice_platform/zimage.bin',ZIMAGE_SIZE,ZIMAGE_SHA,'ZIMAGE')
    report=assess(alice,zimg)
    out=args.out or root/'research/f2/work/reports'/REPORT_NAME
    if not out.parent.is_dir():
        abort('report folder missing: '+str(out.parent))
    with out.open('x',encoding='utf-8',newline='\n') as f:
        f.write(report)
    print(f'A114_REPORT_CREATED={out} BYTES={out.stat().st_size}')
    print('A114_RESULT=VIRTUAL_SELECTION_MODEL_NO_REAL_LAUNCH_PROOF_NO_PATCH')

if __name__=='__main__':
    main()
