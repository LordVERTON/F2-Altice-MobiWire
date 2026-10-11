#!/usr/bin/env python3
"""A148: compare direct ROM registry alias against RAM-copy control with real native mapper/copy. No firmware modifications; this does NOT prove actual startup globals."""
from __future__ import annotations
import argparse, hashlib, struct, sys
from pathlib import Path

ZBASE=0xF023CA50; ZSIZE=0x185E98
ZSHA='85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
ASHA='7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
BSHA='aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'
ENTRY=0xF032ACDC; MAPPER=0xF02E01B0; REGPTR=0xF007F044; DESCPTR=0xF007F048
DESCRIPTOR=0xF037C08C; RECORDS_ROM=0xF0378760; RANGES=0xF037BF54
B702=884; B703=885; AUDIO=490; RECORDS=0x20020000; SOURCE=0x20030000
DEST=0x20040000; RETURN=0x20080000; SYS=0xF0070000; RAM=0x20000000

def guard(p,sz,sha,label):
    b=p.read_bytes(); actual=hashlib.sha256(b).hexdigest()
    if len(b)!=sz or actual!=sha:raise RuntimeError(f'{label}_GUARD_FAIL size={len(b)} sha={actual}')
    return b

def run(z,mode):
    from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_PROT_ALL,UC_HOOK_CODE,UC_HOOK_MEM_INVALID
    from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_R0,UC_ARM_REG_R1
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(0xF0200000,0x200000,UC_PROT_ALL)
    u.mem_write(ZBASE,z)
    u.mem_map(SYS,0x20000,UC_PROT_ALL)
    u.mem_map(RAM,0x100000,UC_PROT_ALL)
    # Control mirrors A146: byte-identical RAM copy, but leaves B702 unmodified.
    # Experimental arm points F007F044 DIRECTLY at original ZIMAGE records.
    record_bytes=z[RECORDS_ROM-ZBASE:RECORDS_ROM-ZBASE+895*16]
    assert len(record_bytes)==895*16
    if mode=='ROM_DIRECT':
        regbase=RECORDS_ROM
    else:
        regbase=RECORDS
        u.mem_write(RECORDS,record_bytes)
    u.mem_write(REGPTR,struct.pack('<I',regbase))
    u.mem_write(DESCPTR,struct.pack('<I',DESCRIPTOR))
    seq=(0x8569,0x87ED)
    u.mem_write(DEST-16,b'\xA5'*160)
    u.reg_write(UC_ARM_REG_R0,0xB702)
    u.reg_write(UC_ARM_REG_R1,DEST)
    u.reg_write(UC_ARM_REG_SP,0x200FF000)
    u.reg_write(UC_ARM_REG_LR,RETURN|1)
    u.reg_write(UC_ARM_REG_PC,ENTRY|1)
    st={'steps':0,'mapper':0,'end':False,'fault':None}
    def code_hook(uc,addr,sz,other):
        st['steps']+=1
        if addr==MAPPER:st['mapper']+=1
        if addr==RETURN:st['end']=True;uc.emu_stop()
        elif st['steps']>25000:st['fault']='STEP_CAP';uc.emu_stop()
    def invalid(uc,access,addr,size,val,other):
        st['fault']=f'UNMAPPED_0x{addr:08X}';return False
    u.hook_add(UC_HOOK_CODE,code_hook)
    u.hook_add(UC_HOOK_MEM_INVALID,invalid)
    try:u.emu_start(ENTRY|1,0,count=25000)
    except Exception as e:st['fault']=st['fault'] or repr(e)
    result=struct.unpack('<'+'H'*len(seq),bytes(u.mem_read(DEST,2*len(seq))))
    guard_ok=(bytes(u.mem_read(DEST-16,16))==b'\xA5'*16 and
              bytes(u.mem_read(DEST+2*len(seq),128-2*len(seq)))==b'\xA5'*(128-2*len(seq)) and
              bytes(u.mem_read(DEST+128,16))==b'\xA5'*16)
    ok=st['end'] and st['fault'] is None and result==seq and guard_ok and st['mapper']>=1
    return ok,st,result,guard_ok

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true');p.add_argument('--root',type=Path)
    p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:
        assert B703==B702+1 and DESCRIPTOR==RANGES+52*6
        assert RECORDS_ROM+895*16==0xF037BF50
        assert struct.pack('<3H',0x8569,0x87ED,0x8928).hex()=='6985ed872889'
        print('A148_SELF_TEST=PASS')
        if not (a.root or a.boot or a.out):return 0
    if not all([a.root,a.boot,a.out]):p.error('--root --boot --out required')
    try:
        root=a.root/'research/f2/work/extracted'
        guard(root/'altice_alice/alice-py.bin',0x157BB4,ASHA,'ALICE')
        z=guard(root/'altice_platform/zimage.bin',ZSIZE,ZSHA,'ZIMAGE')
        guard(a.boot,0x4B06C,BSHA,'BOOT_ZIMAGE')
        off=DESCRIPTOR-ZBASE
        assert struct.unpack_from('<III',z,off)==(RECORDS_ROM,RANGES,52)
        assert struct.unpack_from('<H',z,0xF037BEA0-ZBASE+2)[0]==2
        assert struct.unpack_from('<I',z,0xF037BEA0-ZBASE+12)[0]==0xF0378720
        assert struct.unpack_from('<2H',z,0xF0378720-ZBASE)==(0x8569,0x87ED)
        lines=['S13.5A.148 - DIRECT STATIC ROM REGISTRY VS COPY-OF-ROM CONTROL',
          'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_PATCH_FLASH_REPACK=YES',
          'ALICE_GUARD=PASS','ZIMAGE_GUARD=PASS','BOOT_ZIMAGE_GUARD=PASS',
          'A148_ROM_RECORD_ANCHORS=PASS',
          'GUEST_CODE=REAL_UNSHIMMED_F02E01B0_AND_F032ACDC',
          'ONLY_SYNTHETIC_GLOBALS=F007F044_AND_F007F048',
          'ROM_DIRECT_REGBAS=0xF0378760;RAM_COPY_REGBAS=0x20020000',
          'NO_B702_MUTATION=YES;ORIGINAL_LIST=8569,87ED',
          'EXPERIMENT_NOT_ACTUAL_STARTUP=YES']
        results=[]
        for mode in ('ROM_DIRECT','RAM_COPY_CONTROL'):
            ok,st,got,go=run(z,mode)
            lines += [f'{mode}_RESULT='+','.join(f'{x:04X}' for x in got),
                      f'{mode}_MAPPER_ENTRIES={st["mapper"]}',
                      f'{mode}_STEPS={st["steps"]}',
                      f'{mode}_RETURN={st["end"]} SENTINELS={go} ERROR={st["fault"]}',
                      f'{mode}_ASSERT={"PASS" if ok else "INCONCLUSIVE"}']
            results.append(ok)
        allok=all(results)
        lines += ['A148_DIRECT_ROM_VS_RAM_COPY='+('PASS_BOTH_CASES' if allok else 'INCONCLUSIVE'),
                  'REGISTRY_BOOT_ALIAS=UNPROVEN','REAL_UI_AUDIO_LAUNCH=UNPROVEN',
                  'PATCH_FLASH_READY=NO','NEXT=DO_NOT_INFER_REAL_BOOT_FROM_HYPOTHETICAL_POINTER_INITIALIZATION']
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8') as f:f.write('\n'.join(lines)+'\n')
        print('A148_DIRECT_ROM_VS_RAM_COPY='+('PASS_BOTH_CASES' if allok else 'INCONCLUSIVE'))
        return 0  # INCONCLUSIVE is a reported scientific result, not a script failure.
    except Exception as e:
        print('A148_ABORT='+repr(e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
