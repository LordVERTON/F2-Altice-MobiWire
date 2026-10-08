#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.71 — tightly bounded dual-buffer / selected-dispatch bridge audit.

Use the four already identified instruction neighborhoods only. Answer:
  * Does code reading BOTH F00B9A30 (fixed 0x20-stride callback records)
    and [F004C5B4] (ALICE dynamic 0x20-stride visible records)
    copy/compare/alias one record or route selected fields between them?
  * Does one local flow read the dynamic record +0x10 and hand it to a
    dispatcher/call site?

No general xref sweep, no registry census, no USB/COM/phone, no writes,
no repack, no flash, no patch candidate automatically proposed.

The annotated symbolic traces are LINEAR HEURISTICS, not CFG reachability,
stack correctness, proof of runtime pointer equality or active dispatch.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
except ImportError as e:
    raise SystemExit(f"ABORT: capstone unavailable in local Python venv: {e}")

ALICE_BASE, ALICE_SIZE = 0x1024EC00, 0x157BB4
ALICE_SHA = '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
ZIMAGE_BASE, ZIMAGE_SIZE = 0xF023CA50, 0x185E98
ZIMAGE_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
RECORD_PTR_SLOT, DISPATCH_TABLE = 0xF004C5B4, 0xF00B9A30
SELECTION_STRUCT, WRITER_STRUCT = 0xF004C5CC, 0xF004C5AC

# Every site derives from A.70's verified PC-relative LDR cell; no global search.
GROUPS = (
    ("G1: ZIMAGE F02B76xx — selected state, fixed callback table, dynamic record pointer",
     0xF02B7644, 0xF02B76A0,
     {0xF02B7644: "selection struct", 0xF02B7646: "callback table", 0xF02B766C: "dynamic pointer"}),
    ("G2: ZIMAGE F02D5Exx — static callback table and dynamic buffer in adjacent instructions",
     0xF02D5E76, 0xF02D5EC2,
     {0xF02D5E76: "callback table", 0xF02D5E8C: "dynamic pointer"}),
    ("G3: ZIMAGE F0303Dxx — both table bases, neighboring literal loads",
     0xF0303DE6, 0xF0303ED0,
     {0xF0303DE6: "dynamic pointer", 0xF0303DF2: "callback table"}),
    ("CONTROL: ZIMAGE F0319150 — confirmed selected index → dynamic record +0x10 STORE",
     0xF031910E, 0xF031915A,
     {0xF031912C: "dynamic pointer", 0xF0319150: "selected record +0x10 STORE"}),
)


def banner(title):
    print('\n'+'='*114+'\n'+title+'\n'+'='*114)


@dataclass(frozen=True)
class Image:
    name: str
    base: int
    data: bytes

    def contains(self, addr, size=1):
        return self.base <= addr and addr + size <= self.base + len(self.data)

    def u32(self, addr):
        if not self.contains(addr, 4):
            return None
        return struct.unpack_from('<I', self.data, addr-self.base)[0]

    def section(self, addr, amount):
        if not self.contains(addr, amount):
            raise ValueError(f'{self.name}: address 0x{addr:08X} is outside canonical image')
        return self.data[addr-self.base:addr-self.base+amount]


def guard(path, name, base, size, sha):
    if not path.is_file():
        raise SystemExit(f'ABORT: missing {name} image at {path}')
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    ok = len(data) == size and digest == sha
    print(f'{name}: size=0x{len(data):X} sha256={digest} GUARD={"PASS" if ok else "FAIL"}; {path}')
    if not ok:
        raise SystemExit('ABORT: canonical byte guard mismatch. No audit performed.')
    return Image(name, base, data)


class Decoder:
    def __init__(self, images):
        self.images = images
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def image(self, addr):
        for im in self.images:
            if im.contains(addr, 2):
                return im
        raise ValueError(f'0x{addr:08X} is not ALICE/ZIMAGE code')

    def one(self, addr):
        im = self.image(addr)
        room = min(4, im.base+len(im.data)-addr)
        return next(iter(self.md.disasm(im.section(addr,room),addr,count=1)), None)

    def lit(self, ins):
        if not ins.mnemonic.lower().startswith('ldr') or len(ins.operands) < 2:
            return None
        arg = ins.operands[1]
        if arg.type != ARM_OP_MEM or arg.mem.base != ARM_REG_PC:
            return None
        pc = (ins.address+4) & ~3
        cell = (pc + arg.mem.disp) & 0xFFFFFFFF
        return cell,self.image(ins.address).u32(cell)

    def aligned_insns(self, start, stop):
        pos = start
        while pos < stop:
            ins = self.one(pos)
            if ins is None or ins.size not in (2,4):
                print(f'  DECODE STOP at 0x{pos:08X}; residual bytes excluded')
                break
            if pos+ins.size>stop:
                break
            yield ins
            pos += ins.size


def rn(ins, op):
    return ins.reg_name(op.reg) if op.type == ARM_OP_REG else None


def srcval(ins, op, state):
    if op.type == ARM_OP_IMM:
        return f'0x{op.imm & 0xFFFFFFFF:X}'
    if op.type == ARM_OP_REG:
        return state.get(rn(ins,op),rn(ins,op))
    return '?'


def memexpr(ins, op, state):
    m=op.mem
    b=ins.reg_name(m.base) if m.base else '?'
    i=ins.reg_name(m.index) if m.index else None
    s=state.get(b,b)
    if i:
        s += f'+{state.get(i,i)}'
    if m.disp:
        s += f'{m.disp:+#x}'
    return s


def reg_name_of(ins, op):
    return ins.reg_name(op.reg) if op.type==ARM_OP_REG else '?'


def abstract_trace(insns, d):
    """Straight-line expression breadcrumbs. NOT proof under branching/calls."""
    state={}
    stats={'literal_dyn':0, 'literal_static':0, 'selected_field10_store':0,
           'dynamic_record_field_reads':[], 'callback_sinks':[], 'cross_buf_memory_ops':0}
    for ins in insns:
        op=ins.mnemonic.lower().split('.')[0]
        ops=ins.operands
        notes=[]
        literal=d.lit(ins)
        dst=rn(ins,ops[0]) if ops else None

        if literal and dst:
            cell,value=literal
            if value is None:
                state[dst]='?' 
            else:
                state[dst]=f'0x{value:08X}'
                notes.append(f'PC-LITERAL@0x{cell:08X}=0x{value:08X}')
                if value==RECORD_PTR_SLOT or value==WRITER_STRUCT:
                    stats['literal_dyn']+=1
                    notes.append('DYNAMIC_BUFFER_GLOBAL_ANCHOR')
                if value==DISPATCH_TABLE:
                    stats['literal_static']+=1
                    notes.append('STATIC_CALLBACK_TABLE_ANCHOR')
                if value==SELECTION_STRUCT:
                    notes.append('SELECTED_INDEX_CONTEXT_ANCHOR')
        elif op in ('mov','movs') and dst and len(ops)>1:
            state[dst]=srcval(ins,ops[1],state)
        elif op in ('lsl','lsls','lsr','lsrs') and dst and len(ops)>1:
            if len(ops)>=3:
                lhs=srcval(ins,ops[1],state)
                rhs=srcval(ins,ops[2],state)
            else:
                lhs=state.get(dst,dst)
                rhs=srcval(ins,ops[1],state)
            state[dst]=f'({lhs} {"<<" if op.startswith("lsl") else ">>"} {rhs})'
        elif op in ('add','adds','sub','subs') and dst and len(ops)>1:
            lhs=srcval(ins,ops[1],state) if len(ops)>2 else state.get(dst,dst)
            rhs=srcval(ins,ops[2],state) if len(ops)>2 else srcval(ins,ops[1],state)
            state[dst]=f'({lhs}{"+" if op.startswith("add") else "-"}{rhs})'
        elif (op.startswith('ldr') or op=='ldrsb') and dst and len(ops)>1 and ops[1].type==ARM_OP_MEM:
            source=memexpr(ins,ops[1],state)
            # Above literal case handles PC-relative LDR.
            if not literal:
                if source=='0xF004C5B4' or source=='0xF004C5AC+0x8':
                    state[dst]='DYNAMIC_RECORD_PTR'
                    notes.append('READ [F004C5B4] → dynamic record buffer base')
                elif source=='0xF004C5CC+0x18':
                    state[dst]='SELECTED_INDEX'
                    notes.append('READ selected index')
                else:
                    state[dst]=f'MEM[{source}]'
                if 'DYNAMIC_RECORD_PTR' in source:
                    notes.append(f'DYNAMIC_RECORD_SOURCE: MEM[{source}]')
                    if any(k in source for k in ('+0x10','+0x8','+0x1c','+0xC','+0xc')):
                        stats['dynamic_record_field_reads'].append(f'0x{ins.address:08X} {ins.op_str}: {source}')
                if '0xF00B9A30' in source:
                    notes.append(f'STATIC_CALLBACK_RECORD_READ: MEM[{source}]')
                    stats['cross_buf_memory_ops']+=1
        elif op.startswith('str') and len(ops)>1 and ops[1].type==ARM_OP_MEM:
            target=memexpr(ins,ops[1],state)
            value=srcval(ins,ops[0],state)
            if 'DYNAMIC_RECORD_PTR' in target:
                notes.append(f'DYNAMIC_RECORD_STORE to [{target}] <- {value}')
                if '+0x10' in target:
                    stats['selected_field10_store']+=1
            if '0xF00B9A30' in target:
                notes.append(f'STATIC_TABLE_STORE [{target}] <- {value}')
                stats['cross_buf_memory_ops']+=1
        elif op=='blx' and ops and ops[0].type==ARM_OP_REG:
            target=state.get(rn(ins,ops[0]),rn(ins,ops[0]))
            stats['callback_sinks'].append((ins.address,target))
            notes.append(f'INDIRECT_CALL_FROM={target}')

        # Invalidate caller-saved registers across calls, not preserved regs.
        if op in ('bl','blx'):
            if op=='bl':
                notes.append(f'DIRECT_CALL at 0x{ins.address:08X}; r0-r3 clobbered')
            for r in ('r0','r1','r2','r3'):
                state.pop(r,None)
        # The linear engine does not follow conditional branches.
        if op.startswith('b') and op not in ('bl','blx','bic','bics'):
            notes.append('BRANCH/RETURN — subsequent linear state may not be reachable on this path')
        if op in ('pop','ldm'):
            # These may overwrite registers; prevent certainty from inherited expressions.
            notes.append('MULTIREG op — subsequent register state may be incomplete')
        output = f'  0x{ins.address:08X}: {ins.mnemonic:<9} {ins.op_str:<34}'
        if notes:
            output += ' ; ' + ' | '.join(notes)
        print(output)
    return stats


def exact_site_check(d, requested):
    banner('B. PREVIOUSLY VERIFIED INSTRUCTION ANCHORS — EXACT PC LDR RECHECK')
    for group,_,_,sites in GROUPS:
        print(f'\n{group}')
        for address,label in sites.items():
            ins=d.one(address)
            if ins is None:
                print(f'  ABORT: undecodable anchor 0x{address:08X}')
                raise SystemExit('ABORT: invalid anchor instruction (wrong input/mapping?)')
            lit=d.lit(ins)
            print(f'  0x{address:08X}: {ins.mnemonic} {ins.op_str} [{label}]'
                  + (f' PC-cell=0x{lit[0]:08X} value={"0x%08X" % lit[1] if lit[1] is not None else "OOB"}' if lit else ' (non-literal/field store as expected)'))
            if address not in (0xF0319150,) and not lit:
                raise SystemExit(f'ABORT: expected exact PC-relative literal at 0x{address:08X}; stop for manual review')
    print('ANCHOR_CHECK=PASS (valid instruction decoding and literal provenance; not runtime reachability)')


def main():
    pa=argparse.ArgumentParser(description=__doc__)
    pa.add_argument('--alice',type=Path,default=Path(r'.\research\f2\work\extracted\altice_alice\alice-py.bin'))
    pa.add_argument('--zimage',type=Path,default=Path(r'.\research\f2\work\extracted\altice_platform\zimage.bin'))
    args=pa.parse_args()
    print('S13.5A.71 — DUAL BUFFER SELECTED DISPATCH BRIDGE AUDIT')
    print('STRICTLY OFFLINE: USB=NO COM=NO PHONE=NO BROM=NO DA=NO FLASH_WRITE=NO ERASE=NO REPACK=NO')
    print('No binary modifications and no output files, stdout only.')
    banner('A. CANONICAL SOURCE GUARDS — FAIL CLOSED')
    a=guard(args.alice,'ALICE',ALICE_BASE,ALICE_SIZE,ALICE_SHA)
    z=guard(args.zimage,'ZIMAGE',ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA)
    d=Decoder((a,z))
    exact_site_check(d,None)
    results=[]
    banner('C. BOUNDED DUAL-BASE INSTRUCTION SLICES — LITERAL-ANNOTATED / BRANCH-CAUTIOUS')
    for label,start,stop,anchors in GROUPS:
        if stop-start>0x120 or start%2 or stop%2:
            raise SystemExit(f'ABORT: unbounded/unaligned window {label}')
        print(f'\n[{label}] 0x{start:08X}..0x{stop:08X} ({stop-start} bytes)')
        print('  NOTE: linear Thumb decoding from a bounded start; disassembly may cross a branch or pool.')
        insns=list(d.aligned_insns(start,stop))
        visited={i.address for i in insns}
        for site in anchors:
            if site not in visited:
                print(f'  WARNING: anchor 0x{site:08X} not hit by chosen linear start; standalone anchor follows')
        stats=abstract_trace(insns,d)
        for addr in anchors:
            if addr not in visited:
                ins=d.one(addr)
                if ins is not None:
                    lit=d.lit(ins)
                    print(f'    ANCHOR_ONLY 0x{addr:08X}: {ins.mnemonic} {ins.op_str}'
                          + (f' ; literal=0x{lit[1]:08X}' if lit and lit[1] is not None else ''))
        results.append((label,stats))
        print('  GROUP_SUMMARY: '+ ', '.join(f'{k}={v}' for k,v in stats.items()))
    banner('D. EVIDENCE GATE — DO NOT AUTOMATICALLY INFER POINTER ALIAS OR PATCH')
    for label,st in results:
        print(f'{label}\n  direct constants in this linear trace: dyn={st["literal_dyn"]} table={st["literal_static"]}')
        for s in st['dynamic_record_field_reads']:
            print('  CANONICAL_FIELD_READ_CANDIDATE: '+s)
        for address,origin in st['callback_sinks']:
            print(f'  BLX_CANDIDATE at 0x{address:08X} target={origin}')
    print('\nDECISION CRITERIA: do NOT equate a dynamic PTR and static callback base just because')
    print('both are read in one function. Need a witnessed field-load/compare/copy or proven initializer,')
    print('with selected index and an executable callback handoff. A static base may simply be a separate layer.')
    print('If this does not prove an action link, next gate must be one specific missing provenance link,')
    print('not a duplicate global xref/registry census.')
    print('PHONE ACCESSED=NO; FLASH MODIFIED=NO; PATCH GENERATED=NO; HARDWARE WRITE AUTHORIZED=NO')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
