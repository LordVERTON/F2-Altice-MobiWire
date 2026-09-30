"""Read-only Altice path XREF discovery and bounded disassembly. No donor input.

Raw halfword scans are candidates, not proof of reachable instructions.
Use --disasm ADDRESS:SIZE to follow candidates with literal annotations.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import ALTICE_ALICE, ALTICE_PACKAGE, WORK_ROOT, GHIDRA_REPORTS, DUMP_MAIN

EXPECTED = {
    'dump': '2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922',
    'alice': '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea',
    'zimage': '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954',
    'boot_zimage': 'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e',
    'viva': '9903e1109a66e3d547f18dfad0d3e2cf0f63563ebd9072a2abbed98e2a945696',
    'compressed_alice': '8a06970667c6af37f7a6b1fb28dde0622e396fccd5c2a0b450bd795a0257988f',
}

def require(ok, message):
    if not ok:
        raise ValueError(message)

def checked(name, data):
    require(hashlib.sha256(data).hexdigest() == EXPECTED[name], 'Hash mismatch: ' + name)
    return data

def load_images():
    dump = checked('dump', DUMP_MAIN.read_bytes())
    require(len(dump) == 0x400000, 'Dump size')
    require(DUMP_MAIN.with_name('mobiwire_dump_3.bin').read_bytes() == dump, 'dump3 differs')
    viva = checked('viva', dump[0x4c20c:0x2950c8])
    checked('compressed_alice', dump[0x18129c:0x18129c+0x113e2c])
    package = ALTICE_PACKAGE / 'DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00'
    require((package / 'VIVA').read_bytes() == viva, 'Service VIVA differs from physical dump')
    root = WORK_ROOT / 'extracted/altice_platform'
    return [('alice', 0x1024ec00, checked('alice', (ALTICE_ALICE/'alice-py.bin').read_bytes())),
            ('zimage', 0xf023ca50, checked('zimage', (root/'zimage.bin').read_bytes())),
            ('boot_zimage', 0xf01f19e4, checked('boot_zimage', (root/'boot_zimage.bin').read_bytes())),
            ('physical_rom', 0x10000000, dump[:0x4c20c])]

def read(images, address, size):
    for _, base, data in images:
        if base <= address and address + size <= base + len(data):
            return data[address-base:address-base+size]
    raise ValueError(f'Unmapped {address:#x}')

def disasm(images, address, size):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    lines = []
    for ins in md.disasm(read(images, address, size), address):
        note = ''
        h = int.from_bytes(ins.bytes[:2], 'little')
        if ins.size == 2 and h & 0xf800 == 0x4800:
            loc = ((ins.address+4)&~3) + (h & 255)*4
            try:
                value = int.from_bytes(read(images,loc,4),'little')
                note = f' ; [{loc:#x}]={value:#x}'
            except ValueError:
                pass
        if ins.size == 2 and h & 0xf800 == 0xa000:
            note = f' ; ADR={((ins.address+4)&~3)+(h&255)*4:#x}'
        lines.append(f'{ins.address:08x} {ins.bytes.hex():10} {ins.mnemonic:8} {ins.op_str}{note}')
    return '\n'.join(lines)

def discover(images, extra_targets=()):
    strings = []
    for name, base, data in images:
        for label in ('%c:\\', 'Audios\\', '@Playlists', 'audio_play_list.sal'):
            for encoding in ('ascii', 'utf-16le'):
                pattern = (label+'\0').encode(encoding)
                pos = data.find(pattern)
                while pos >= 0:
                    strings.append(dict(image=name, offset=hex(pos), address=hex(base+pos), text=label, encoding=encoding))
                    pos = data.find(pattern, pos+1)
    targets = {int(s['address'],16) for s in strings} | set(extra_targets)
    refs = []
    for name, base, data in images:
        for target in sorted(targets):
            pattern = struct.pack('<I', target)
            pos = data.find(pattern)
            while pos >= 0:
                refs.append(dict(image=name, address=hex(base+pos), kind='pointer', target=hex(target)))
                pos = data.find(pattern,pos+1)
        for off in range(0,len(data)-4,2):
            h = struct.unpack_from('<H',data,off)[0]
            pc = (base+off+4)&~3
            target = pc + (h&255)*4
            if h&0xf800 == 0xa000 and target in targets:
                refs.append(dict(image=name,address=hex(base+off),kind='ADR candidate',target=hex(target)))
            if h&0xf800 == 0x4800 and base <= target <= base+len(data)-4:
                value = struct.unpack_from('<I',data,target-base)[0]
                if value in targets:
                    refs.append(dict(image=name,address=hex(base+off),kind='LDR literal candidate',target=hex(value),literal=hex(target)))
    return dict(hashes=EXPECTED, strings=strings, references=refs,
                limitations=['Halfword candidates require control-flow validation.', 'No handset execution.', 'No claim of exhaustive computed/MOVW-MOVT references.'])

def audit_paths(images):
    """Fixed byte anchors independently inspected along the path data flow."""
    anchors = {
        0xf02b3c56:'f27b33a103a879f7eaff33a103a82ef0d0fe',
        0xf02ba560:'10b5ffb004000a0085b019a101a873f761fb',
        0xf022dc56:'632917d0',
        0xf022dc8a:'01cd207000206070a41c',
        0xf02e2a08:'10b5c9f7fbfa10bd',
        0xf02ac004:'30b504000d0031f057fe40000019290031f006fb200030bd',
        0xf02b8fe8:'10b5084c0021607a5df71cff002801d1607a10bd18220221082070f715f90006000e10bd',
        0x10343c18:'b7f79cede073',
        0x10343bf6:'6072',
        0x103163fa:'30b500231a000124491c25009540054200d05b1c8b4202d0521c102af5db1006000edaf732fe30bd',
        0x102f1084:'102801d3002070470349c0004018408a0006000e7047',
        0x10300dbe:'012211000820fcf7c2eb',
        0x10300dd0:'012202210820fcf7baeb',
        0x10300de0:'012211001020fcf7b2eb',
        0x10300dce:'6082', 0x10300dde:'6083', 0x10300dee:'6084',
        0xf0229230:'10b5ecf71bfd10bd',
        0xf02eb482:'1822022108203df7d2fe2249e073',
    }
    checks=[]
    for address, expected in anchors.items():
        require(read(images,address,len(bytes.fromhex(expected))).hex()==expected, f'Instruction mismatch {address:#x}')
        checks.append(dict(address=hex(address),bytes=expected))
    for address, target in ((0x102fb754,0xf02b8fe9),(0x102fd54c,0xf0229231)):
        require(read(images,address,8)==struct.pack('<II',0xe51ff004,target),f'Veneer {address:#x}')
    for address in (0xf02b3d28,0xf02ba5d0,0xf02e9ce0,0xf02eb5c8,0xf02eb69c):
        require(read(images,address,5)==b'%c:\\\0',f'Format {address:#x}')
    require(read(images,0xf02b3d30,16)=='Audios\\\0'.encode('utf-16le'), 'Audio suffix')
    require(read(images,0xf02ba5d8,22)=='@Playlists\0'.encode('utf-16le'), 'Playlist directory')
    return dict(status='PASS',checks=checks,confirmed=dict(formatter='0xf022dc34',
        append_utf16='0xf02e2a08',present_drive_byte='0xf00ad8a3',preferred_drive_byte='0xf00ad89d',
        choose_present_drive='0xf02b8fe8',fs_get_drive_wrapper='0xf0229230',fs_get_drive_body='0xf0215c6c',
        drive_index_to_letter='0x102f1084',drive_table_init='0x10300da4',drive_table='0xf00ef090'),
        inferred=dict(sdk_names=['kal_wsprintf','mmi_ucs2cat','mmi_audply_get_current_list_drv','FS_GetDrive','FS_GetDevStatus'],
                      storage_labels='index 1 likely Phone/public; index 2 likely Memory card/removable; UI label linkage not proven'),
        limitations=['RAM table contents and mounted drives not observed.', 'No hardcoded SD letter.',
                     'Playlist builder can create directories: not suitable as read-only POC helper.'])

PATH_RANGES = [(0xf02b3c04,0x114),(0xf02ba560,0x70),(0xf022dc34,0xee),
    (0xf02e2a08,8),(0xf02ac004,0x18),(0xf02ddcbc,0x20),(0xf02dd624,0x4a),
    (0xf02b8fe8,0x24),(0xf0229230,8),(0xf0215c6c,0x200),
    (0x10300da4,0x74),(0x102f1084,0x16),(0x1030bc54,0x38),(0x103163fa,0x28),
    (0x103190b0,0x58),(0x10343b2c,0x14c),(0x10345ca0,0x5a),
    (0xf02eb3a6,0x7c),(0xf02eb438,0xd8),(0xf02eb554,0x70),(0xf02eb5ec,0xaa)]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--disasm', action='append', default=[])
    parser.add_argument('--xref', action='append', default=[])
    args = parser.parse_args()
    images = load_images()
    if args.disasm:
        output = '\n\n'.join(disasm(images,*[int(x,0) for x in spec.split(':')]) for spec in args.disasm)
        (GHIDRA_REPORTS/'audio_path_disasm.txt').write_text(output,encoding='utf-8')
        print(output)
    else:
        report = discover(images, [0xf00ad894,0xf00ef090]+[int(x,0) for x in args.xref])
        report['audit'] = audit_paths(images)
        (GHIDRA_REPORTS/'audio_path_audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        (GHIDRA_REPORTS/'audio_path_evidence.txt').write_text('\n\n'.join(disasm(images,a,n) for a,n in PATH_RANGES),encoding='utf-8')
        contexts = [disasm(images,int(r['address'],16),160) for r in report['references']
                    if r['target']=='0xf00ad894' and r['kind']=='LDR literal candidate']
        (GHIDRA_REPORTS/'audio_drive_contexts.txt').write_text('\n\n'.join(contexts),encoding='utf-8')
        print(f"PASS: hashes, {len(report['audit']['checks'])} byte anchors, {len(report['strings'])} strings, {len(report['references'])} XREF candidates")

if __name__ == '__main__':
    main()
