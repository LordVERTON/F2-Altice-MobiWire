#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.72: focused static-record-to-action callback provenance audit.

Scope is deliberately narrow: G2 source+0x0C -> dynamic+0x10 copy, G1
static+0x10 -> F02DDB84 -> F009343C indirect call, and ONLY exact
F009343C PC-literal references in ALICE/ZIMAGE. There is no hardware I/O,
firmware modification, repack, patch, broad menu audit, or ID census.

A linear disassembly is NOT runtime reachability. A PC-relative literal
reference is NOT evidence of an executed path or a field's semantic meaning.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_MEM, ARM_OP_IMM, ARM_OP_REG, ARM_REG_PC
except ImportError as exc:
    raise SystemExit(f'ABORT: install capstone in the chosen offline Python venv: {exc}')

A_BASE, A_SIZE = 0x1024EC00, 0x157BB4
A_SHA = '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
Z_BASE, Z_SIZE = 0xF023CA50, 0x185E98
Z_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
TABLE, PTR_SLOT, INDEX_CTX, ACTION_SLOT = 0xF00B9A30, 0xF004C5B4, 0xF004C5CC, 0xF009343C
HELPER = 0xF02DDB84


def banner(s):
    print('\n' + '='*104 + '\n' + s + '\n' + '='*104)


@dataclass(frozen=True)
class Image:
    name: str
    base: int
    data: bytes

    def valid(self, addr, size=1):
        return self.base <= addr and addr + size <= self.base + len(self.data)

    def read(self, addr, size):
        if not self.valid(addr, size):
            raise SystemExit(f'ABORT: out-of-image read {self.name} @0x{addr:08X}+0x{size:X}')
        start = addr - self.base
        return self.data[start:start+size]

    def u32(self, addr):
        if not self.valid(addr,4):
            return None
        return struct.unpack('<I', self.read(addr,4))[0]


def load(path, name, base, size, expected):
    if not path.is_file():
        raise SystemExit(f'ABORT: missing {name}: {path}')
    buf=path.read_bytes()
    sha=hashlib.sha256(buf).hexdigest()
    passed = len(buf)==size and sha==expected
    print(f'{name}: size=0x{len(buf):X} sha256={sha} GUARD={"PASS" if passed else "FAIL"} path={path}')
    if not passed:
        raise SystemExit('ABORT: canonical image mismatch; no audit performed')
    return Image(name,base,buf)


class Decoder:
    def __init__(self, imgs):
        self.imgs=imgs
        self.cs=Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
        self.cs.detail=True

    def image(self, addr):
        for im in self.imgs:
            if im.valid(addr,2):
                return im
        raise SystemExit(f'ABORT: unmapped instruction 0x{addr:08X}')

    def one(self, addr):
        im=self.image(addr)
        size=min(4, im.base+len(im.data)-addr)
        return next(iter(self.cs.disasm(im.read(addr,size),addr,count=1)),None)

    def seq(self,start,stop):
        if start & 1 or stop & 1 or not 0 < stop-start <= 0x140:
            raise SystemExit(f'ABORT: invalid bounded decode window 0x{start:X}..0x{stop:X}')
        at=start
        while at < stop:
            ins=self.one(at)
            if ins is None or ins.size not in (2,4) or at+ins.size>stop:
                print(f'  DECODE_STOP @0x{at:08X}')
                break
            yield ins
            at+=ins.size

    def literal(self, ins):
        if not ins.mnemonic.lower().startswith('ldr') or len(ins.operands)<2:
            return None
        src=ins.operands[1]
        if src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
            return None
        cell=((ins.address+4)&~3)+src.mem.disp
        return cell,self.image(ins.address).u32(cell)


def req(dec, addr, op=None, literal=None, source_offset=None, indirect=None):
    ins=dec.one(addr)
    if ins is None:
        raise SystemExit(f'ABORT: no instruction at 0x{addr:08X}')
    m=ins.mnemonic.lower().split('.')[0]
    if op is not None and m!=op:
        raise SystemExit(f'ABORT: anchor mnemonic mismatch 0x{addr:08X}: wanted {op}, got {m}')
    lit=dec.literal(ins)
    if literal is not None and (not lit or lit[1]!=literal):
        raise SystemExit(f'ABORT: literal mismatch at 0x{addr:08X}: {lit} expected 0x{literal:08X}')
    if source_offset is not None and (len(ins.operands)<2 or ins.operands[1].type!=ARM_OP_MEM or ins.operands[1].mem.disp!=source_offset):
        raise SystemExit(f'ABORT: field-offset mismatch 0x{addr:08X}')
    if indirect is not None and (not ins.operands or ins.operands[0].type!=ARM_OP_REG or ins.reg_name(ins.operands[0].reg)!=indirect):
        raise SystemExit(f'ABORT: indirect target mismatch 0x{addr:08X}')
    if m in ('bl','blx') and literal is None and indirect is None and op=='bl':
        if not ins.operands or ins.operands[0].type!=ARM_OP_IMM or (ins.operands[0].imm & ~1)!=HELPER:
            raise SystemExit(f'ABORT: helper target mismatch at 0x{addr:08X}')
    return ins


def window(dec, label,start,stop):
    print(f'\n[{label}] 0x{start:08X}..0x{stop:08X}')
    print('  LINEAR STATIC DISASSEMBLY ONLY: branches/pools may make later instructions unreachable')
    for ins in dec.seq(start,stop):
        lit=dec.literal(ins)
        extra=''
        if lit:
            addr,v=lit
            extra=f'  ; literal cell=0x{addr:08X} value={"0x%08X"%v if v is not None else "OUTSIDE"}'
            if v==TABLE: extra+=' STATIC_TABLE'
            if v==PTR_SLOT: extra+=' DYNAMIC_PTR_SLOT'
            if v==INDEX_CTX: extra+=' SELECTED_INDEX_CTX'
            if v==ACTION_SLOT: extra+=' ACTION_SLOT'
        if ins.address in (0xF02D5E96,0xF02D5E9E,0xF02B7656,0xF02B7676,0xF02B7694,0xF02B7662,0xF02B7678):
            extra+='  ; TARGETED_PROVENANCE_SITE'
        print(f'  0x{ins.address:08X}: {ins.mnemonic:<9} {ins.op_str:<32}{extra}')


def literal_xrefs(dec, value):
    """Only candidate PC-relative LDRs to one newly discovered action slot."""
    pattern=struct.pack('<I',value)
    result=[]
    raw=0
    for im in dec.imgs:
        data=im.data
        pos=-1
        while True:
            pos=data.find(pattern,pos+1)
            if pos<0: break
            raw+=1
            cell=im.base+pos
            if cell&3: continue
            lo=max(im.base,cell-0x400)
            # All possible 16/32-bit Thumb LDR literal instruction starts.
            for addr in range((lo+1)&~1,cell,2):
                ins=dec.one(addr)
                if ins is None: continue
                lit=dec.literal(ins)
                if lit and lit[0]==cell and lit[1]==value:
                    result.append((im,ins,cell))
    unique={ins.address:(im,ins,cell) for im,ins,cell in result}
    return raw,[unique[a] for a in sorted(unique)]


def local_action_usage(dec,ins):
    """Intentionally small linear print; classify possible loads/stores only."""
    dst=ins.reg_name(ins.operands[0].reg)
    print(f'  0x{ins.address:08X}: {ins.mnemonic} {ins.op_str} => {dst}=0x{ACTION_SLOT:08X}')
    for item in dec.seq(ins.address+ins.size,ins.address+ins.size+0x20):
        ops=item.operands
        uses=[]
        for j,o in enumerate(ops):
            if o.type==ARM_OP_MEM and o.mem.base and item.reg_name(o.mem.base)==dst:
                uses.append('MEM_BASE')
            elif o.type==ARM_OP_REG and item.reg_name(o.reg)==dst:
                uses.append(f'REG_OPERAND{j}')
        annot=('  ; mentions original literal register: '+','.join(uses)) if uses else ''
        print(f'    0x{item.address:08X}: {item.mnemonic:<8} {item.op_str:<31}{annot}')
        # Register overwritten; simple linear window cannot follow an alias.
        if ops and ops[0].type==ARM_OP_REG and item.reg_name(ops[0].reg)==dst and item.mnemonic.lower().split('.')[0] in ('ldr','mov','movs','add','adds','sub','subs'):
            if item.mnemonic.lower().split('.')[0]=='ldr' and len(ops)>1 and ops[1].type==ARM_OP_MEM and ops[1].mem.base and item.reg_name(ops[1].mem.base)==dst:
                print('    NOTE: initial action pointer dereferenced; following use requires a new register state')
            break


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice',type=Path,default=Path(r'.\research\f2\work\extracted\altice_alice\alice-py.bin'))
    p.add_argument('--zimage',type=Path,default=Path(r'.\research\f2\work\extracted\altice_platform\zimage.bin'))
    args=p.parse_args()
    print('S13.5A.72 - SELECTED ACTION CALLBACK PROVENANCE AUDIT')
    print('STRICTLY OFFLINE: no USB/COM/phone/BROM/DA/readflash/writeflash/erase/repack/patch')
    print('READS only two local canonical files; stdout only; all emitted text ASCII-safe')
    banner('A. CANONICAL BYTE GUARDS - FAIL CLOSED')
    alice=load(args.alice,'ALICE',A_BASE,A_SIZE,A_SHA)
    z=load(args.zimage,'ZIMAGE',Z_BASE,Z_SIZE,Z_SHA)
    dec=Decoder((alice,z))
    banner('B. EXACT ANCHOR CHECKS - ALREADY OBSERVED IN A.71')
    tests=[
        (0xF02D5E76,'ldr',TABLE,None,None),
        (0xF02D5E8C,'ldr',PTR_SLOT,None,None),
        (0xF02D5E92,'ldr',None,0x0C,None),
        (0xF02D5E96,'str',None,0x10,None),
        (0xF02D5E9E,'str',None,0x14,None),
        (0xF02B7644,'ldr',INDEX_CTX,None,None),
        (0xF02B7646,'ldr',TABLE,None,None),
        (0xF02B7650,'ldrb',None,0x14,None),
        (0xF02B7656,'ldr',None,0x10,None),
        (0xF02B7662,'bl',None,None,None),
        (0xF02B766C,'ldr',PTR_SLOT,None,None),
        (0xF02B7676,'ldr',None,0x0,None),
        (0xF02B7678,'ldr',ACTION_SLOT,None,None),
        (0xF02B7694,'blx',None,None,'r5'),
    ]
    for addr,op,literal,disp,target in tests:
        ins=req(dec,addr,op,literal,disp,target)
        print(f'PASS 0x{addr:08X}: {ins.mnemonic:<7} {ins.op_str}')
    print('ANCHOR_CHECK=PASS; no runtime claim')
    banner('C. SELECTED STATIC FIELDS, CONDITIONAL COPY, CALLBACK ARGUMENT ASSEMBLY')
    window(dec,'G2 copy static +0x0C into dynamic +0x10 when type low byte in {1,2,4}',0xF02D5E76,0xF02D5EAE)
    window(dec,'G1 selected static +0x10 passed through F02DDB84 and indirect callback',0xF02B7644,0xF02B7698)
    print('\nPROVEN A.71 FIELD BRIDGE: DYN[index].field10 = STATIC[index].field0C (conditional)')
    print('G1: when STATIC[index].byte14==1 and STATIC[index].field10!=0,')
    print('    F02DDB84 is called with r0=STATIC[index].field10, r1=sp+4, r2=sp;')
    print('    then BLX [F009343C] with r2=STATIC[index].field10 and')
    print('    r0/r1 varying with the dynamic record header and helper output.')
    print('WARNING: G1 field10 is STATIC field10, not the G2-copied DYNAMIC field10.')
    print('Neither field meaning nor registration of Audio 0x8928 is established.')
    banner('D. HELPER F02DDB84 - BOUNDED ENTRY SLICE ONLY')
    window(dec,'F02DDB84 callee; inspect memory writes to supplied r1/r2 output pointers',HELPER,HELPER+0xA0)
    banner('E. ONE-SYMBOL ACTION SLOT 0xF009343C - PC-LITERAL USES ONLY')
    raw,refs=literal_xrefs(dec,ACTION_SLOT)
    print(f'EXACT_U32_CELLS={raw} VALIDATED_THUMB_PC_LDR_SITES={len(refs)}')
    for im,ins,cell in refs[:20]:
        print(f'\n  {im.name}: PC_LDR at 0x{ins.address:08X} literal_cell=0x{cell:08X}')
        local_action_usage(dec,ins)
    if len(refs)>20:
        print(f'  OUTPUT_CAPPED: {len(refs)-20} verified sites omitted; narrow one if needed')
    banner('F. DECISION / NEXT MISSING LINK')
    print('1. Static record field0C -> dynamic selected record field10: CODE-PROVEN conditional copy.')
    print('2. Static record field10 -> helper F02DDB84 and global callback [F009343C]: CODE-PROVEN call setup.')
    print('3. These are DIFFERENT source fields. No proof dynamic field10 reaches callback.')
    print('4. Identify who assigns [F009343C], and what its callee does with r2 and the action code.')
    print('5. Do not assume alias of [F004C5B4] and F00B9A30. No Audio 0x8928 launcher proven.')
    print('PHONE ACCESSED=NO FLASH MODIFIED=NO PATCH=NO REPACK=NO HARDWARE WRITE=NO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
