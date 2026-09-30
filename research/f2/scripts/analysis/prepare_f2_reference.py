#!/usr/bin/env python3
"""Stage an offline MediaTek reference image without altering its source.

Accepts a directory tree (recommended), ZIP, full dump, or standalone VIVA/ALICE.
RAR is intentionally not unpacked here: supply an extracted directory/ZIP instead.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import REPO_ROOT, GHIDRA_ROOT, UNALICE, GHIDRA_SCRIPTS

ROOT = REPO_ROOT
GFH = b'MMM\x01'
FILE_INFO = b'FILE_INFO'
VIVA_TYPE = 0x0108

def sha(data): return hashlib.sha256(data).hexdigest()
def u16(data, off): return struct.unpack_from('<H', data, off)[0]
def u32(data, off): return struct.unpack_from('<I', data, off)[0]

def read_source_tree(path):
    """Yield (logical name, bytes) for files, ZIP members, or directory trees."""
    if path.is_dir():
        for p in sorted(path.rglob('*')):
            if p.is_file(): yield str(p.relative_to(path)), p.read_bytes()
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir(): yield info.filename, z.read(info)
    elif path.suffix.lower() == '.rar':
        raise ValueError('RAR non extrait automatiquement. Dépose un ZIP ou le dossier extrait (Firmware/ROM, Firmware/VIVA).')
    elif path.is_file():
        yield path.name, path.read_bytes()
    else:
        raise FileNotFoundError(path)

def component(name):
    n=name.replace('\\','/').lower().rstrip('/')
    base=n.rsplit('/',1)[-1]
    if 'ext_bootloader' in n or 'extbootloader' in n: return 'EXT_BOOTLOADER'
    if 'bootloader' in base or '/bootloader/' in n or re.search(r'(^|[/])bl[0-9_.-]',base): return 'BOOTLOADER'
    if base=='viva' or '/firmware/viva/' in n or n.endswith('/firmware/viva'): return 'VIVA'
    if base=='rom' or '/firmware/rom/' in n or n.endswith('/firmware/rom'): return 'ROM'
    if base.endswith('.cfg') or 'scatter' in base: return 'CFG'
    return None

def find_gfh_viva(data):
    pos=0
    while True:
        off=data.find(GFH,pos)
        if off<0: return None
        pos=off+1
        if off+0x38>len(data) or data[off+8:off+17]!=FILE_INFO: continue
        if u16(data,off+0x18)!=VIVA_TYPE: continue
        length=u32(data,off+0x20)
        if length and off+length<=len(data): return off,length

def extract_alice(name,data,out):
    results=[]
    sigs=[]
    for sig in (b'ALICE_1',b'ALICE_2'):
        pos=0
        while True:
            hit=data.find(sig,pos)
            if hit<0: break
            sigs.append((hit,sig.decode('ascii'))); pos=hit+1
    if not sigs: return results
    container=find_gfh_viva(data)
    if container:
        v_off,v_len=container; v_start=v_off; v_end=v_off+v_len
        viva=data[v_start:v_end]
        vpath=out/'VIVA.bin'
        if not vpath.exists(): vpath.write_bytes(viva)
        selected=[(p,s) for p,s in sigs if v_start<=p<v_end]
    else:
        selected=sigs
        viva=data
        v_start=0; v_end=len(data)
    for index,(off,sig) in enumerate(selected,1):
        end=v_end
        if container and index<len(selected): end=selected[index][0]
        alice=data[off:end]
        if len(alice)<20: continue
        base=u32(alice,8)
        tag=f'{sig}_{index:02d}'
        adir=out/tag; adir.mkdir(parents=True,exist_ok=True)
        apath=adir/f'{tag}.bin'; apath.write_bytes(alice)
        record={'type':sig,'source':name,'offset':off,'size':len(alice),
                'base':base,'sha256':sha(alice),'path':str(apath)}
        results.append(record)
    return results

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',required=True,help='ZIP, dossier Firmware, dump complet, VIVA ou ALICE')
    ap.add_argument('--out',default=str(GHIDRA_ROOT/'references'/'ELKI_DS_L_V01.2_181106_MP'))
    ap.add_argument('--ghidra',default=r'C:\Tools\ghidra_12.1.4_PUBLIC')
    ap.add_argument('--analyze',action='store_true',help='Importer chaque alice-py dans Ghidra headless et exporter les fonctions')
    args=ap.parse_args()
    src=Path(args.input).resolve(); out=Path(args.out).resolve()
    out.mkdir(parents=True,exist_ok=True)
    if src==out or out in src.parents:
        raise SystemExit('Le dossier de sortie ne peut pas se trouver à l’intérieur de la source firmware.')
    comps={k:[] for k in ('BOOTLOADER','EXT_BOOTLOADER','ROM','VIVA','CFG')}
    alice=[]; markers={}; source_hashes=[]
    for name,data in read_source_tree(src):
        source_hashes.append({'name':name,'size':len(data),'sha256':sha(data)})
        kind=component(name)
        if kind:
            flat_name=name.replace('\\','__').replace('/','__')
            dest=out/'components'/kind/flat_name
            dest.parent.mkdir(parents=True,exist_ok=True)
            if not dest.exists(): dest.write_bytes(data)
            comps[kind].append({'source':name,'path':str(dest),'size':len(data),'sha256':sha(data)})
        decoded=data.decode('latin1',errors='ignore')
        for token in ('ELKI_DS_L_V01.2_181106_MP','MOBIWIRE_NAKAI_SS_L_V01.2_181214_MP',
                      'DL188_GX1882_NIKITI_PCB01','SAGETEL61M_11C_HW',
                      'ALTICE_F2_DS_V02.1_181023_MP'):
            if token in decoded: markers.setdefault(token,[]).append(name)
        alice.extend(extract_alice(name,data,out))
    manifest={'source':str(src),'reference_claim':'ELKI_DS_L_V01.2_181106_MP',
              'source_files':source_hashes,'identification_markers':markers,
              'components':comps,'alice':alice,'analysis':[]}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Input files inspected:',len(source_hashes))
    print('Components:',{k:len(v) for k,v in comps.items()})
    print('ALICE images found:',len(alice))
    for rec in alice: print(f"  {rec['type']} base=0x{rec['base']:08x} bytes={rec['size']} {rec['path']}")
    if not alice: print('No ALICE signature found. No firmware component was inferred.')
    if not alice: return
    for rec in alice:
        adir=Path(rec['path']).parent
        unalice=UNALICE
        run=subprocess.run([sys.executable,str(unalice),str(Path(rec['path']).resolve())],
                           cwd=adir,text=True,encoding='utf-8',errors='replace')
        if run.returncode: raise SystemExit(f'unalice.py failed for {rec["path"]}')
        translated=adir/'alice-py.bin'
        intermediate=adir/'alice-translated-py.bin'
        if not translated.exists() or not intermediate.exists():
            raise SystemExit('unalice.py did not produce both decompressed ALICE outputs')
        rec['decompressed']=str(translated); rec['decompressed_size']=translated.stat().st_size
        rec['decompressed_sha256']=sha(translated.read_bytes())
        rec['translated_intermediate']=str(intermediate)
        rec['translated_intermediate_sha256']=sha(intermediate.read_bytes())
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    if not args.analyze: return
    headless=Path(args.ghidra)/'support'/'analyzeHeadless.bat'
    scripts=GHIDRA_SCRIPTS; projects=out/'ghidra_projects'; reports=out/'reports'
    projects.mkdir(exist_ok=True); reports.mkdir(exist_ok=True)
    for idx,rec in enumerate(alice,1):
        adir=Path(rec['path']).parent
        translated=adir/'alice-py.bin'
        project=f'{src.stem}_{rec["type"]}_{idx}'
        export=reports/(project+'_functions.jsonl')
        log=reports/(project+'_ghidra.log')
        command=[str(headless),str(projects),project,'-import',str(translated.resolve()),
                 '-loader','BinaryLoader','-loader-baseAddr',f'{rec["base"]:08x}',
                 '-processor','ARM:LE:32:v5t','-cspec','default','-scriptPath',str(scripts),
                 '-preScript','DisassembleAliceThumb.java',
                 '-postScript','ExportAliceDetails.java',str(export),'-log',str(log)]
        run=subprocess.run(command,cwd=ROOT,text=True,encoding='utf-8',errors='replace')
        if run.returncode: raise SystemExit(f'Ghidra failed for {translated}; see {log}')
        rec['functions_export']=str(export); rec['ghidra_log']=str(log)
        print('Ghidra function export:',export)
    manifest['analysis'].append('ARM:LE:32:v5t; ALICE base from header offset 8; Thumb disassembly via DisassembleAliceThumb.java, then detailed function export.')
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Extraction and static analysis complete. Source firmware files were read only.')

if __name__=='__main__':
    main()
