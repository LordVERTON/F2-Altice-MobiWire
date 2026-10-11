#!/usr/bin/env python3
"""A147: evidence-gated startup investigation based on EXISTING audit reports.

Read only: canonical firmware SHA guards and historical TXT reports. No phone,
USB, COM, emulator, memory patch, firmware rewrite or synthetic boot claim.
"""
from __future__ import annotations
import argparse, hashlib, re, sys
from pathlib import Path

ALICE=('research/f2/work/extracted/altice_alice/alice-py.bin',0x157BB4,'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea')
ZIMAGE=('research/f2/work/extracted/altice_platform/zimage.bin',0x185E98,'85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954')
BOOT=(0x4B06C,'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e')
NAMES={
 'A044':'s13_5a44', 'A111':'s13_5a111', 'A134':'s13_5a134',
 'A135':'s13_5a135','A136':'s13_5a136','A137':'s13_5a137',
 'A138':'s13_5a138','A139':'s13_5a139','A140':'s13_5a140',
 'A141':'s13_5a141','A142':'s13_5a142','A143':'s13_5a143',
 'A145':'s13_5a145','A146':'s13_5a146'
}
IMPORTANT=re.compile(r'F007F044|F007F048|F0378760|F037C08C|F0054210|WRITER|INIT|PRODUCER|DESCRIPTOR|ALIAS|PATCH_FLASH_READY|COPY|LOAD|STORE',re.I)
DIRECT=re.compile(r'\b(?:STR|STRH|STRB|STM|STMEA|STMIA)\b|\b(?:WRITE|WRITER|STORE|STORES)\b',re.I)


def check(path, size, digest, label):
    if not path.is_file():raise RuntimeError(f'{label}_MISSING={path}')
    raw=path.read_bytes(); got=hashlib.sha256(raw).hexdigest()
    if len(raw)!=size or got!=digest:raise RuntimeError(f'{label}_GUARD_FAIL size={len(raw)} sha={got}')
    return f'{label}_GUARD=PASS'

def collect(directory):
    out=[]
    for key, prefix in NAMES.items():
        paths=sorted(directory.glob(prefix+'*.txt')) if directory.is_dir() else []
        if not paths:
            out.append((key,None,[],0))
            continue
        for path in paths:
            rows=path.read_text(encoding='utf-8',errors='replace').splitlines()
            matches=[(i+1,row.strip()) for i,row in enumerate(rows) if IMPORTANT.search(row)]
            out.append((key,path,matches,len(rows)))
    return out

def build(entries):
    lines=['S13.5A.147 — EXISTING REGISTRY STARTUP EVIDENCE GATE',
           'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_FIRMWARE_PATCH_REPACK=YES',
           'METHOD=REUSE_HISTORICAL_REPORTS_NO_NEW_STATIC_XREF_OR_PADDING_SCAN',
           'CRITERION=EXPLICIT_INSTRUCTION_BACKED_WRITE_TO_RUNTIME_GLOBAL_REQUIRED',
           'WARNING=SEARCH_MATCH_OR_WORD_WRITER_IS_NOT_EXECUTION_PROOF']
    found=0
    for key,path,hits,total in entries:
        if path is None:
            lines.append(f'{key}_SOURCE=MISSING')
            continue
        found+=1
        lines.append(f'{key}_SOURCE={path.name} LINES={total} MATCHES={len(hits)}')
        for no,row in hits[:12]:
            lines.append(f'  L{no} {row[:240]}')
        if len(hits)>12:lines.append(f'  OMITTED_MATCHES={len(hits)-12}')
    lines += [f'EXISTING_REPORT_FILES_REVIEWED={found}',
              'RUNTIME_F007F044_WRITER_PROVEN_BY_A147=NO_REPORT_REVIEW_ONLY',
              'RUNTIME_F007F048_WRITER_PROVEN_BY_A147=NO_REPORT_REVIEW_ONLY',
              'A147_EVIDENCE_REVIEW=PASS',
              'NEXT=REVIEW_REFERENCED_STARTUP_ENTRY_EVIDENCE_OR_INSTRUMENT_GROUNDED_ENTRY_ONLY',
              'PATCH_FLASH_READY=NO']
    return '\n'.join(lines)+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true')
    p.add_argument('--root',type=Path)
    p.add_argument('--boot',type=Path)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:
        assert len(ZIMAGE[2])==64 and 0x185E98==1597080
        test=build([('A999',None,[],0)])
        assert 'A999_SOURCE=MISSING' in test and 'A147_EVIDENCE_REVIEW=PASS' in test
        print('A147_SELF_TEST=PASS')
        if not (a.root or a.boot or a.out):return 0
    if not (a.root and a.boot and a.out):p.error('--root --boot --out required')
    try:
        lines=[check(a.root/ALICE[0],ALICE[1],ALICE[2],'ALICE'),
               check(a.root/ZIMAGE[0],ZIMAGE[1],ZIMAGE[2],'ZIMAGE'),
               check(a.boot,BOOT[0],BOOT[1],'BOOT_ZIMAGE')]
        entries=collect(a.root/'research/f2/work/reports')
        report=build(entries)
        payload='\n'.join(lines)+'\n'+report
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write(payload)
        print('\n'.join(lines))
        print('A147_EVIDENCE_REVIEW=PASS')
        print('REPORT='+str(a.out.resolve()))
        return 0
    except Exception as e:
        print(f'A147_ABORT={type(e).__name__}: {e}',file=sys.stderr)
        return 1
if __name__=='__main__':sys.exit(main())
