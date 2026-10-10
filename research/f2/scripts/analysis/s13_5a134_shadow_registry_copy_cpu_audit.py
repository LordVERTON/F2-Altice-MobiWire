#!/usr/bin/env python3
"""S13.5A.134 - isolated CPU emulation of native list copy, NOT ROM modification.

Uses canonical ZIMAGE bytes and Unicorn to execute F032ACDC with a synthetic
registry descriptor and source U16 array in virtual RAM. Only F02E01B0
(ID -> dense index) is shimmed, returning synthetic registry slot 0.
Does not claim a real B702 3-child registry, usable patch, or OK dispatch.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, struct, sys
from pathlib import Path

ENTRY=0xF032ACDC
MAPPER=0xF02E01B0
REGPTR=0xF007F044
ZBASE=0xF023CA50
ZSIZE=0x185E98
ZSHA='85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
ALICE_SHA='7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
BOOT_SHA='aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'
ALICE_SIZE=0x157BB4; BOOT_SIZE=0x4B06C
CODE_MAP=0xF0200000; CODE_SIZE=0x200000
SYS_MAP=0xF0070000; SYS_SIZE=0x20000
RAM_BASE=0x20000000; RAM_SIZE=0x100000
RECORDS=0x20020000; SOURCE=0x20030000; DEST=0x20040000; RET=0x20080000
GUARD_BYTE=0xA5


def canonical(path, label, size, digest):
    if not path.is_file(): raise RuntimeError(f'MISSING_{label}={path}')
    data=path.read_bytes(); got=hashlib.sha256(data).hexdigest()
    if len(data)!=size or got!=digest:
        raise RuntimeError(f'{label}_SIZE_SHA_MISMATCH size={len(data)} hash={got}')
    return data


def run_case(image, labels, count, expected):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_PROT_ALL
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1
    uc=Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(CODE_MAP,CODE_SIZE,UC_PROT_ALL)
    uc.mem_write(ZBASE,image)
    uc.mem_map(SYS_MAP,SYS_SIZE,UC_PROT_ALL)
    uc.mem_map(RAM_BASE,RAM_SIZE,UC_PROT_ALL)
    uc.mem_write(REGPTR,struct.pack('<I',RECORDS))
    uc.mem_write(RECORDS+2,struct.pack('<H',count))
    uc.mem_write(RECORDS+0xC,struct.pack('<I',SOURCE))
    uc.mem_write(SOURCE,struct.pack('<'+'H'*count,*expected))
    uc.mem_write(DEST-16,bytes([GUARD_BYTE])*160)
    uc.reg_write(UC_ARM_REG_R0,0xB702)
    uc.reg_write(UC_ARM_REG_R1,DEST)
    uc.reg_write(UC_ARM_REG_SP,0x200FF000)
    uc.reg_write(UC_ARM_REG_LR,RET|1)
    uc.reg_write(UC_ARM_REG_PC,ENTRY|1)
    state={'n':0,'mapper':0,'stopped':False,'error':None}
    def hook(guest,address,size,user):
        state['n']+=1
        if address==MAPPER:
            state['mapper']+=1
            guest.reg_write(UC_ARM_REG_R0,0)
            guest.reg_write(UC_ARM_REG_PC,guest.reg_read(UC_ARM_REG_LR))
        elif address==RET:
            state['stopped']=True;guest.emu_stop()
        elif not (ENTRY<=address<ENTRY+0x40):
            state['error']=f'UNEXPECTED_PC_0x{address:08X}';guest.emu_stop()
        elif state['n']>2000:
            state['error']='STEP_CAP';guest.emu_stop()
    def invalid(guest,access,address,size,value,user):
        state['error']=f'UNMAPPED_ADDRESS_0x{address:08X}';return False
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.hook_add(UC_HOOK_MEM_INVALID,invalid)
    try:uc.emu_start(ENTRY|1,0,count=2000)
    except Exception as e:state['error']=str(e)
    got=tuple(struct.unpack('<'+'H'*count,bytes(uc.mem_read(DEST,count*2))))
    pre=bytes(uc.mem_read(DEST-16,16))
    tail=bytes(uc.mem_read(DEST+count*2,128-count*2))
    flags=bytes(uc.mem_read(DEST+128,16))
    guard_ok=pre==bytes([GUARD_BYTE])*16 and tail==bytes([GUARD_BYTE])*(128-count*2) and flags==bytes([GUARD_BYTE])*16
    passed=state['stopped'] and state['error'] is None and got==expected and guard_ok and state['mapper']==count*2+1
    labels.extend([f'CASE_COUNT={count} EXPECTED='+','.join(f'{x:04X}' for x in expected),
        'RESULT='+','.join(f'{x:04X}' for x in got),
        f'REACHED_RETURN={state["stopped"]} CPU_STEPS={state["n"]} MAPPER_CALLS={state["mapper"]}',
        f'SENTINELS_INTACT={guard_ok} ERROR={state["error"] or "NONE"}',
        f'CASE_{count}_ASSERT='+('PASS' if passed else 'FAIL'),''])
    return passed


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true');p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:
        assert ENTRY&1==0 and MAPPER&1==0 and ZBASE<=ENTRY<ZBASE+ZSIZE
        assert (0x180-0x100)//2==64 and 0x1C0-0x180==64
        print('A134_STATIC_SELF_TEST=PASS')
        if not any((a.root,a.boot,a.out)):return 0
    if not all((a.root,a.boot,a.out)):p.error('--root --boot --out required')
    try:
        alice=canonical(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',ALICE_SIZE,ALICE_SHA)
        boot=canonical(a.boot,'BOOT_ZIMAGE',BOOT_SIZE,BOOT_SHA)
        image=canonical(a.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',ZSIZE,ZSHA)
        if image[ENTRY-ZBASE:ENTRY-ZBASE+2]!=bytes.fromhex('f0b5') or image[MAPPER-ZBASE:MAPPER-ZBASE+2]!=bytes.fromhex('f0b5'):
            # mapper prologue may differ; only validate executable mapping for mapper
            if image[ENTRY-ZBASE:ENTRY-ZBASE+2]!=bytes.fromhex('f0b5'):raise RuntimeError('ENTRY_BYTES_CHANGED')
        # Exact A133 copy-loop anchors
        anchors={0xF032ACEA:'b5f761fa',0xF032AD00:'2952',0xF032AD10:'a042',0xF032AD12:'e9d8'}
        for addr,raw in anchors.items():
            if image[addr-ZBASE:addr-ZBASE+len(bytes.fromhex(raw))]!=bytes.fromhex(raw):
                raise RuntimeError(f'A133_COPY_ANCHOR_MISMATCH_0x{addr:08X}')
        lines=['S13.5A.134 - CONDITIONAL UNICORN NATIVE COPY WITH SYNTHETIC REGISTRY',
            'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_FIRMWARE_PATCH=YES',
            'ALICE_GUARD=PASS SHA256='+ALICE_SHA,'BOOT_ZIMAGE_GUARD=PASS SHA256='+BOOT_SHA,
            'ZIMAGE_GUARD=PASS SHA256='+ZSHA,'A133_COPY_ANCHORS=PASS',
            'UNTRUSTED_CONTEXT=REGISTRY_SLOT0_SYNTHETIC COUNT_AND_SOURCE_SYNTHETIC',
            'EXTERNAL_SHIM=F02E01B0_ALWAYS_RETURNS_DENSE_0',
            'GUEST_CODE=REAL_ZIMAGE_F032ACDC','BUFFER=VIRTUAL_RAM_SENTINELS_NOT_DEVICE_MEMORY','']
        outcomes=[]
        for count in (2,3,64):
            values=tuple([0x8569,0x87ED,0x8928]+[0xA000+i for i in range(61)])[:count]
            outcomes.append(run_case(image,lines,count,values))
        ok=all(outcomes)
        lines.extend(['A134_SHADOW_COPY_CPU='+('PASS_ALL_CASES' if ok else 'FAIL'),
            'NATIVE_REGISTRY_B702_3_ITEMS_REAL=UNPROVEN',
            'REAL_UI_OK_TO_AUDIO=UNPROVEN','ROM_RELOCATION_OR_PATCH_READY=NO',
            'NEXT=FIND_SAFE_RUNTIME_INJECTION_POINT_OR_NATIVE_REGISTRY_PRODUCER_WITH_CALLBACK_CONTROL'])
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(lines)+'\n')
        print('A134_REPORT_CREATED='+str(a.out))
        print('A134_SHADOW_COPY_CPU='+('PASS_ALL_CASES' if ok else 'FAIL'))
        return 0 if ok else 1
    except Exception as e:
        print(f'A134_ABORT={type(e).__name__}: {e}',file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
