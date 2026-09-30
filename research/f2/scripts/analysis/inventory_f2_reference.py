#!/usr/bin/env python3
"""Read-only recursive inventory for the NIKITI/Altice F2 reference firmware."""
from pathlib import Path
import re
import struct
import json
import zipfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import REPO_ROOT, GHIDRA_REPORTS

ROOT = REPO_ROOT
TOKENS = (
    b'ELKI_DS_L_V01.2_181106_MP', b'ELKI_DS_L', b'181106_MP',
    b'MOBIWIRE_NAKAI_SS_L_V01.2_181214_MP', b'NAKAI_SS_L', b'181214_MP',
    b'DL188_GX1882_NIKITI_PCB01', b'DL188_GX1882_NIKITI',
    b'SAGETEL61M_11C_HW', b'ALTICE_F2_DS_V02.1_181023_MP'
)
NAME_RE = re.compile(r'elki|181106|nikiti|dl188|gx1882|altice.?f2|nakai|181214', re.I)
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules'}

def files_recursive():
    for directory, dirs, files in __import__('os').walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            yield Path(directory) / name

def scan_stream(path, needles):
    found = []
    overlap = max(map(len, needles)) - 1
    carry = b''
    with path.open('rb') as f:
        while True:
            data = f.read(4 * 1024 * 1024)
            if not data: break
            block = carry + data
            base = f.tell() - len(block)
            for token in needles:
                pos = block.lower().find(token.lower())
                if pos >= 0:
                    found.append((token.decode('ascii'), base + pos))
            carry = block[-overlap:]
    return found

def main():
    files = list(files_recursive())
    named = [p for p in files if NAME_RE.search(str(p.relative_to(ROOT)))]
    archives = [p for p in files if p.suffix.lower() in {'.zip','.rar','.7z'}]
    binaries = [p for p in files if p.suffix.lower() in {'.bin','.rom','.img','.dat'}]
    archive_rows=[]
    for p in archives:
        row={'path':str(p.relative_to(ROOT)),'size':p.stat().st_size,'zip_members':[]}
        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                row['zip_members']=[n for n in z.namelist()]
        archive_rows.append(row)
    marker_hits=[]
    print(f'Workspace: {ROOT}')
    print(f'Files indexed: {len(files)}; firmware-like binary files scanned: {len(binaries)}')
    print('\nNames matching ELKI/NIKITI/NAKAI/DL188/build identifiers:')
    for p in named: print(' ',p.relative_to(ROOT))
    print('\nArchives found:')
    for p in archives:
        print(' ',p.relative_to(ROOT),p.stat().st_size)
        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                print('   ZIP entries:',len(z.namelist()))
                for n in z.namelist():
                    if re.search(r'firmware|bootloader|(^|[/\\])rom$|(^|[/\\])viva$',n,re.I): print('   ',n)
    print('\nExact ASCII marker scan in .BIN/.ROM/.IMG/.DAT:')
    any_hit=False
    for p in binaries:
        hits=scan_stream(p,TOKENS)
        if hits:
            any_hit=True
            marker_hits.append({'path':str(p.relative_to(ROOT)),'hits':[{'marker':token,'offset':offset} for token,offset in hits]})
            print(' ',p.relative_to(ROOT))
            for token,offset in hits: print(f'   {token} @ 0x{offset:x}')
    if not any_hit: print('  No exact firmware/build marker found in any scanned binary.')
    report={'workspace':str(ROOT),'files_indexed':len(files),'firmware_binaries_scanned':len(binaries),
            'name_matches':[str(p.relative_to(ROOT)) for p in named],'archives':archive_rows,
            'binary_marker_hits':marker_hits,'exact_ELKI_firmware_found':any('ELKI_DS_L_V01.2_181106_MP' in h['marker'] for f in marker_hits for h in f['hits'])}
    out=GHIDRA_REPORTS/'reference_firmware_inventory.json'
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('\nInventory JSON:',out)

if __name__=='__main__': main()
