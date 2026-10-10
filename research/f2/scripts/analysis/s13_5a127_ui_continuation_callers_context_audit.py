#!/usr/bin/env python3
"""S13.5A.127 - bounded, read-only analysis of six OTHER exact callers of 0x102EF44C.

Evidence only: caller context is not proof of an OK key event. No firmware patch,
no USB, serial, emulator execution, or device communication. Exclusive report.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

NAME = 's13_5a127_ui_continuation_callers_context_audit'
SITES = {
    0x1033F490: bytes.fromhex('aff7dcff'),
    0x1033F4D8: bytes.fromhex('aff7b8ff'),
    0x10340BA6: bytes.fromhex('aef751fc'),
    0x10342DEC: bytes.fromhex('acf72efb'),
    0x10345296: bytes.fromhex('aaf7d9f8'),
    0x103453B2: bytes.fromhex('aaf74bf8'),
}
DEST = 0x102EF44C
WINDOW_BEFORE = 0x80
WINDOW_AFTER = 0x30

def load_a121():
    path=Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
    if not path.is_file(): raise RuntimeError('MISSING_DEPENDENCY_A121='+str(path))
    spec=importlib.util.spec_from_file_location('f2_a121_dep',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def check_sites(alice, base, md, immediate_dest):
    evidence=[]
    for site, raw in SITES.items():
        offset=site-base
        if offset < 0 or offset+4 > len(alice):
            raise RuntimeError('SITE_OUTSIDE_ALICE=0x%08X'%site)
        actual=alice[offset:offset+4]
        if actual!=raw: raise RuntimeError('A126_BYTES_MISMATCH site=0x%08X actual=%s'%(site,actual.hex()))
        inst=list(md.disasm(raw,site,1))
        if len(inst)!=1 or inst[0].mnemonic.split('.')[0]!='bl' or immediate_dest(inst[0])!=DEST:
            raise RuntimeError('A126_CALL_TARGET_MISMATCH=0x%08X'%site)
        evidence.append((site, raw.hex()))
    return evidence

def one_context(md, alice, base, site):
    # A full-function CFG is deliberately NOT inferred from an arbitrary pre-call byte.
    # Decode aligned independent candidate windows, mark uncertain start boundaries.
    lo=max(base, (site-WINDOW_BEFORE)&~1)
    hi=min(base+len(alice),site+4+WINDOW_AFTER)
    lines=[]
    starts=[]
    for candidate in (lo, site-0x40, site-0x20, site-0x10):
        candidate=max(lo,candidate&~1)
        if candidate in starts: continue
        starts.append(candidate)
        ip=candidate; decoded=[]; count=0
        while ip<hi and count<110:
            inst=list(md.disasm(alice[ip-base:ip-base+4],ip,1))
            if not inst: break
            i=inst[0]
            marker=' <== VERIFIED_CALLSITE' if ip==site else ''
            decoded.append('  %08X %-10s %-9s %-32s%s'%(ip,i.bytes.hex(),i.mnemonic,i.op_str,marker))
            ip+=i.size; count+=1
        lines.append('CANDIDATE_START=0x%08X DECODED=%d REACHES_CALLSITE=%s (not a proven function entry)'%(candidate,count,'YES' if any('VERIFIED_CALLSITE' in x for x in decoded) else 'NO'))
        lines.extend(decoded)
    # Pure static window: literals can be event labels but are NOT given semantics here.
    bx=alice[lo-base:hi-base]
    lines.append('RAW_WINDOW_RANGE=[0x%08X,0x%08X) SHA256=%s'%(lo,hi,hashlib.sha256(bx).hexdigest()))
    lines.append('RAW_WINDOW_HEX='+bx.hex())
    return lines

def selftest():
    assert len(SITES)==6 and 0x10343028 not in SITES
    assert len(set(SITES))==len(SITES)
    assert all(len(v)==4 for v in SITES.values())
    assert WINDOW_BEFORE >=0x40 and WINDOW_AFTER >=0x20
    print('A127_SELF_TEST=PASS_SIX_EXACT_CALLSITE_GUARDS')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true')
    p.add_argument('--root',type=Path)
    p.add_argument('--boot',type=Path)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:
        selftest()
        if not (a.root or a.boot or a.out):return 0
    if not (a.root and a.boot and a.out):p.error('--root --boot --out required')
    try:
        m=load_a121()
        alice=m.assert_canonical(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)
        zimage=m.assert_canonical(a.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)
        boot=m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA)
        m.check_inputs(alice,boot,zimage)
        md=m.make_decoder()
        confirmed=check_sites(alice,m.ALICE_BASE,md,m.immediate_dest)
        out=[
            'S13.5A.127 - SIX ADDITIONAL SELECTED-UI CONTINUATION CALLERS',
            'STRICTLY_OFFLINE=YES NO_USB_COM_DEVICE_EXECUTION_PATCH_FLASH=YES',
            'ALICE_GUARD=PASS SHA256='+m.ALICE_SHA,
            'ZIMAGE_GUARD=PASS SHA256='+m.ZIMAGE_SHA,
            'BOOT_ZIMAGE_GUARD=PASS SHA256='+m.BOOT_SHA,
            'A120_LITERAL_GUARD=PASS',
            'A126_SIX_CALLSITE_GUARD=PASS',
            'SOURCE=A126_EXACT_DIRECT_CALLS_NOT_FULL_RUNTIME_EVENT_TRACES',
            'CONTROL_ALREADY_STUDIED_CALL=0x10343028 (excluded here)',
            'DESTINATION=0x%08X'%DEST,
            'WINDOWS_ARE_INDEPENDENT_DECODES_NOT_FUNCTION_CFG_PROOFS',
            '', '=== A. EXACT CALLS AND MULTI-START DECODE CONTEXT ===',
        ]
        for site,raw in confirmed:
            out.extend(['','CALLSITE=0x%08X RAW=%s DEST=0x%08X'%(site,raw,DEST)])
            out.extend(one_context(md,alice,m.ALICE_BASE,site))
        out.extend(['','=== B. PATCH READINESS / HONEST LIMITATIONS ===',
            'SIX_CALLER_CONTEXTS_PRODUCED=YES',
            'REAL_OK_EVENT_PROVENANCE=UNPROVEN',
            'CALLER_FUNCTION_BOUNDARIES=UNPROVEN_IN_THIS_CONTEXT_ONLY_REPORT',
            'INDIRECT_CALLERS=NOT_ENUMERATED',
            'AUDIO_8928_LAUNCH=UNPROVEN',
            'B702_SAFE_RELOCATION=UNPROVEN',
            'PATCH_FLASH_READY=NO',
            'NEXT=REVIEW_CALLSITE_ARGUMENT_SETUP_AND_EVENT_PROVENANCE;DO_NOT_EQUATE_CALLSITE_WITH_OK',
        ])
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8',newline='\n') as fp:fp.write('\n'.join(out)+'\n')
        print('A127_REPORT_CREATED='+str(a.out.resolve()))
        print('A127_RESULT=SIX_CALLER_CONTEXTS_PRODUCED')
        return 0
    except (Exception) as exc:
        print('A127_ABORT=%s: %s'%(type(exc).__name__,exc),file=sys.stderr)
        return 1
if __name__=='__main__':sys.exit(main())
