#!/usr/bin/env python3
import argparse, hashlib, json, os, struct, zipfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import GHIDRA_ROOT

CANDIDATES = {
    'altice': [0x00046000, 0x0004A000, 0x002C5000, 0x002D5000, 0x002E0000],
    'qmobile_rom': [0x00007000,0x0003D000,0x0006B000,0x0008A000,0x000C3000,0x000C4000,0x000D4000,0x000D5000,0x000D7000,0x000D8000,0x000D9000,0x000E1000],
}
TERMS = [b'AUDPLY', b'AudioPlayer', b'Audio', b'DAF', b'MP3', b'AAC', b'AMR', b'WAV', b'FMradio', b'image']

def sha256(b): return hashlib.sha256(b).hexdigest()

def extract_qmobile_rom(zpath: Path):
    with zipfile.ZipFile(zpath,'r') as z:
        names = z.namelist()
        roms = [n for n in names if n.replace('\\','/').endswith('/ROM') or n == 'ROM']
        if not roms:
            raise SystemExit('ROM introuvable dans le ZIP QMobile')
        name = roms[0]
        return name, z.read(name)

def find_all(data, needle):
    out=[]; i=0
    while True:
        i=data.find(needle,i)
        if i<0: break
        out.append(i); i += 1
    return out

def dump_window(base_name, data, center, outdir, radius=0x8000):
    start=max(0, center-radius)
    end=min(len(data), center+radius)
    blob=data[start:end]
    p=outdir/f'{base_name}_0x{start:08X}_0x{end:08X}.bin'
    p.write_bytes(blob)
    return {'file':p.name,'start':start,'end':end,'size':len(blob),'sha256':sha256(blob)}

def ascii_strings(data, minlen=5):
    out=[]; s=bytearray(); start=0
    for i,b in enumerate(data):
        if 32 <= b <= 126:
            if not s: start=i
            s.append(b)
        else:
            if len(s)>=minlen: out.append((start,s.decode('ascii','replace')))
            s.clear()
    if len(s)>=minlen: out.append((start,s.decode('ascii','replace')))
    return out

def main():
    ap=argparse.ArgumentParser(description='Prépare des régions candidates Altice/QMobile pour Ghidra (lecture seule).')
    ap.add_argument('--altice-dump', required=True)
    ap.add_argument('--reference', required=True, help='ZIP QMobile F2')
    ap.add_argument('--out', default=str(GHIDRA_ROOT))
    ap.add_argument('--radius', default='0x8000', help='rayon de chaque fenêtre (défaut 0x8000 = 32 KiB)')
    args=ap.parse_args()
    radius=int(args.radius,0)
    out=Path(args.out); out.mkdir(parents=True, exist_ok=True)
    alt=Path(args.altice_dump).read_bytes()
    rom_name,qrom=extract_qmobile_rom(Path(args.reference))

    manifest={'altice':{'source':args.altice_dump,'size':len(alt),'sha256':sha256(alt)},
              'qmobile_rom':{'source':rom_name,'size':len(qrom),'sha256':sha256(qrom)},
              'windows':[], 'hits':{}}

    for label,data in [('altice',alt),('qmobile_rom',qrom)]:
        manifest['hits'][label]={}
        for term in TERMS:
            hits=find_all(data,term)
            if hits: manifest['hits'][label][term.decode('ascii')]=[f'0x{x:08X}' for x in hits[:50]]
        for center in CANDIDATES[label]:
            if center < len(data):
                manifest['windows'].append({'source':label, **dump_window(label,data,center,out,radius)})

    # Special 128 KiB QMobile region covering the strongest audio table
    start=0x000C0000; end=min(len(qrom),0x000E6000)
    p=out/f'qmobile_audio_superregion_0x{start:08X}_0x{end:08X}.bin'
    p.write_bytes(qrom[start:end])
    manifest['windows'].append({'source':'qmobile_rom','file':p.name,'start':start,'end':end,'size':end-start,'sha256':sha256(qrom[start:end])})

    # Human-readable string map for the superregion
    lines=[]
    for off,s in ascii_strings(qrom[start:end],5):
        low=s.lower()
        if any(k in low for k in ['audio','mp3','aac','amr','wav','midi','radio','image','video','daf']):
            lines.append(f'0x{start+off:08X}\t{s}')
    (out/'qmobile_audio_strings.tsv').write_text('\n'.join(lines)+'\n',encoding='utf-8')

    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    readme = f'''# Préparation Ghidra — F2\n\nLecture seule. Aucun fichier n'est destiné à être flashé.\n\n## Sources\n- Altice dump: {args.altice_dump}\n- QMobile ROM interne: {rom_name}\n\n## Recommandation Ghidra\n1. Créer un projet non partagé.\n2. Importer d'abord `qmobile_audio_superregion_0x000C0000_0x{end:08X}.bin`.\n3. Format: Raw Binary.\n4. Architecture à essayer: ARM little-endian, 32-bit. Sur MT6261, beaucoup de code applicatif est ARM/Thumb; laisser Ghidra analyser puis vérifier les désassemblages plausibles.\n5. Base address de cette super-région: `0x000C0000` si l'on veut conserver les offsets relatifs au fichier ROM QMobile.\n6. Chercher les chaînes `audio/mp3`, `FMradio`, `AT+EMAUDIO`, puis afficher leurs XREFs.\n7. Importer les fenêtres Altice séparément pour comparaison; ne pas supposer que les mêmes adresses ont les mêmes fonctions.\n\n## Point clé\nLes chaînes MIME autour de 0x000D5Axx prouvent surtout la gestion de types de fichiers. Les XREFs vers ces chaînes permettront de distinguer la table MIME de l'application AudioPlayer elle-même.\n'''
    (out/'README_GHIDRA.md').write_text(readme,encoding='utf-8')
    print(f'OK: {out.resolve()}')
    print(f'QMobile ROM: {rom_name} ({len(qrom)} bytes)')
    print(f'Fichiers générés: {len(list(out.iterdir()))}')

if __name__=='__main__': main()
