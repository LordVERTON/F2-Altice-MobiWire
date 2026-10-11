#!/usr/bin/env python3
"""A152: evidence-only audit of the unresolved physical OK -> Image Viewer action.

No raw firmware scans or CPU execution. Uses existing historical TXT reports,
with exact line references. Neither 0x6314 nor 0x6316 is assumed to be KEY_OK.
"""
from __future__ import annotations
import argparse, hashlib, re, sys
from pathlib import Path

HASHES={
 'ALICE':('research/f2/work/extracted/altice_alice/alice-py.bin',0x157BB4,'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'),
 'ZIMAGE':('research/f2/work/extracted/altice_platform/zimage.bin',0x185E98,'85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'),
 'BOOT_ZIMAGE':(None,0x4B06C,'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'),
}
STEMS={
 'A090':'s13_5a90_', 'A103':'s13_5a103_', 'A104':'s13_5a104_',
 'A105':'s13_5a105_', 'A110':'s13_5a110_',
 'A117':'s13_5a117_', 'A118':'s13_5a118_', 'A119':'s13_5a119_',
 'A125':'s13_5a125_', 'A126':'s13_5a126_', 'A127':'s13_5a127_',
 'A128':'s13_5a128_', 'A129':'s13_5a129_', 'A130':'s13_5a130_',
 'A150':'s13_5a150_',
}
KEY=re.compile(r'(?i)\b(?:key(?:board|pad|down|up|code)?|button|press|select|ok|enter|(?:0x)?6314|(?:0x)?6316|(?:0x)?87ed|(?:0x)?8928|(?:0x)?102ed240|(?:0x)?10345268|(?:0x)?10336788|(?:0x)?10342fc4|event)\b')
POSITIVE=re.compile(r'(?i)(?:physical|hardware|keyboard|keycode|keypress|key_down|key_up).{0,70}(?:ok|enter|87ed)|(?:ok|enter).{0,70}(?:physical|hardware|keyboard|keycode|keypress|87ed)')

def guard(path:Path,size:int,digest:str,label:str):
    if not path.is_file():raise RuntimeError(f'MISSING_{label}={path}')
    h=hashlib.sha256();n=0
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''): n+=len(block);h.update(block)
    if n!=size or h.hexdigest()!=digest:raise RuntimeError(f'{label}_MISMATCH size={n} sha={h.hexdigest()}')

def self_test():
    assert KEY.search('EVENT 0x6314')
    assert KEY.search('Image 0x87ED')
    assert POSITIVE.search('physical keycode OK')
    assert not POSITIVE.search('event 6314 means OK')
    print('A152_SELF_TEST=PASS')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true');p.add_argument('--root',type=Path)
    p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:self_test()
    if not any((a.root,a.boot,a.out)):return 0 if a.self_test else p.error('need --root --boot --out')
    if not all((a.root,a.boot,a.out)):p.error('--root --boot --out required')
    try:
        root=a.root.resolve(); reports=root/'research/f2/work/reports'
        for label,(relative,size,digest) in HASHES.items():
            path=a.boot if label=='BOOT_ZIMAGE' else root/relative
            guard(path,size,digest,label)
        result=['S13.5A.152 — HISTORICAL OK-KEY EVIDENCE MATRIX',
                'STRICTLY_OFFLINE=YES NO_USB_COM_PATCH_FLASH_REPACK=YES',
                'METHOD=TARGETED_REPORT_REVIEW_NOT_FIRMWARE_XREF_OR_KEYCODE_SCAN',
                'WARNING=KEYWORD_HIT_IS_NOT_KEYCODE_OR_RUNTIME_ACTIVATION_PROOF',
                'ALICE_GUARD=PASS','ZIMAGE_GUARD=PASS','BOOT_ZIMAGE_GUARD=PASS']
        files=0;hits=0;positives=0
        for tag,prefix in STEMS.items():
            matches=sorted(reports.glob(prefix+'*.txt')) if reports.is_dir() else []
            if not matches:
                result.append(f'{tag}_SOURCE=MISSING');continue
            for src in matches:
                files+=1
                rows=src.read_text(encoding='utf-8',errors='replace').splitlines()
                relevant=[(i,line.strip()) for i,line in enumerate(rows,1) if KEY.search(line)]
                candidate=[(i,line.strip()) for i,line in relevant if POSITIVE.search(line)]
                hits+=len(relevant);positives+=len(candidate)
                result.append(f'{tag}_SOURCE={src.name} LINES={len(rows)} MATCHES={len(relevant)} POSITIVE_KEYWORD_CANDIDATES={len(candidate)}')
                for i,line in (candidate[:5]+[x for x in relevant if x not in candidate][:9]):
                    result.append(f'  L{i} {line[:330]}')
                if len(relevant)>14:result.append(f'  TRUNCATED={max(0,len(relevant)-14)}')
        result.extend([f'EXISTING_REPORTS_REVIEWED={files}',f'RELEVANT_LINES={hits}',
                       f'POSITIVE_KEYWORD_CANDIDATES_UNVERIFIED={positives}',
                       'ACTUAL_PHYSICAL_OK_TO_87ED_PROVEN_BY_A152=NO_REPORT_REVIEW_ONLY',
                       'A152_HISTORICAL_KEY_EVIDENCE=PASS',
                       'NEXT=IF_REPORTS_CONTAIN_ACTUAL_KEYCODE_TRACE_VALIDATE_SOURCE_AND_EVENT_ABI;OTHERWISE_REQUIRE_NEW_GROUNDED_EXECUTION_BOUNDARY',
                       'PATCH_FLASH_READY=NO'])
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(result)+'\n')
        print('A152_HISTORICAL_KEY_EVIDENCE=PASS');print('REPORT='+str(a.out));return 0
    except Exception as e:
        print(f'A152_ABORT={type(e).__name__}: {e}',file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
