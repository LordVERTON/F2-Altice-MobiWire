"""Extract Altice ZIMAGE, BOOT_ZIMAGE and multi-trunk DCM from local backups.

Read-only inputs; invokes the reference SDK's 7lzma.exe decoder. No handset I/O.
Structures: viva.h, code_decompression_hal.c, dcmgr_comp.h in MT2503-2.
Type 3 ZIMAGE needs the decoded ALICE dictionary (7lzma dtp); DCM uses dt.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import ALTICE_PACKAGE, ALTICE_ALICE, WORK_ROOT, DUMP_MAIN


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded(data, offset, size):
    if offset < 0 or size <= 0 or offset + size > len(data):
        raise ValueError(f"Out-of-bounds range {offset:#x}+{size:#x}/{len(data):#x}")
    return data[offset:offset + size]


def unpack(data, offset, count):
    return struct.unpack('<' + 'I' * count, bounded(data, offset, count * 4))


def decode(tool, source, size, name, output, dictionary=None):
    if not 0 < size <= 16 * 1024 * 1024 or len(source) < 13:
        raise ValueError("Invalid decompressed length or missing LZMA header")
    if int.from_bytes(source[5:13], 'little') != size:
        raise ValueError("LZMA length disagrees with component metadata")
    compressed = output / (name + '.lzma')
    decoded = output / (name + '.bin')
    compressed.write_bytes(source)
    command = [str(tool), 'dtp' if dictionary else 'dt', str(compressed), str(decoded)]
    if dictionary:
        command.append(str(dictionary))
    result = subprocess.run(command, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{name}: decoder failed: {result.stdout!r} {result.stderr!r}")
    data = decoded.read_bytes()
    if len(data) != size:
        raise ValueError(f"{name}: output length mismatch: {len(data)} != {size}")
    return {'file': str(decoded), 'size': size, 'sha256': digest(data),
            'compressed_sha256': digest(source), 'decoder_mode': command[1]}


def main():
    package = ALTICE_PACKAGE / 'DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00'
    viva = (package / 'VIVA').read_bytes()
    rom = (package / 'ROM').read_bytes()
    dictionary = (ALTICE_ALICE / 'alice-py.bin').resolve()
    donor = WORK_ROOT / 'donor_repos/MT2503-2'
    tool = (donor / 'tools/7lzma.exe').resolve()
    output = (WORK_ROOT / 'extracted/altice_platform').resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = {'input_viva_sha256': digest(viva), 'input_rom_sha256': digest(rom),
                'dictionary_sha256': digest(dictionary.read_bytes()),
                'decoder_sha256': digest(tool.read_bytes()), 'components': [],
                'limitations': 'Static extraction only; no proof of working file playback or menu launch.'}
    if viva[:4] != b'MMM\x01' or viva[8:17] != b'FILE_INFO':
        raise ValueError('Unexpected GFH header')
    load, file_size = unpack(viva, 0x1c, 2)
    if file_size != len(viva):
        raise ValueError('GFH size disagrees with VIVA file size')
    info_offset = unpack(viva, 0x28, 1)[0]
    info = unpack(viva, info_offset, 5)
    if info[0] != load or sorted(info) != list(info):
        raise ValueError('Unexpected VIVAInfo layout')
    manifest['viva_info'] = dict(zip(('viva', 'zimage', 'boot_zimage', 'dcm', 'alice'),
                                    [f'0x{value:08X}' for value in info]))
    # Altice ROM literal table: base and size pairs, used by 0x1000FAF4.
    # Infer execution bases from the Altice binary, not the donor scatter file.
    boot_base, boot_length, z_base, z_length = unpack(rom, 0x5b88, 4)
    if boot_base + boot_length != z_base or boot_base >> 24 != 0xF0:
        raise ValueError('Altice execution-range table differs from analyzed layout')
    manifest['execution_range_evidence'] = {'rom_file_offset': '0x5B88',
        'consumer': '0x1000FAF4', 'boot_base': hex(boot_base), 'zimage_base': hex(z_base),
        'note': 'ZIMAGE includes four additional trailing bytes beyond the range-table length.'}
    dump = DUMP_MAIN.read_bytes()
    dump_offset = dump.find(viva)
    if dump_offset < 0:
        raise ValueError('Service VIVA not found verbatim in handset dump 2')
    manifest['handset_dump_match'] = {'file': str(DUMP_MAIN), 'offset': hex(dump_offset),
                                    'sha256': digest(dump), 'bytes_equal': True}
    for name, start, end, base, expected in (
            ('zimage', info[1] - load, info[2] - load, z_base, z_length + 4),
            ('boot_zimage', info[2] - load, info[3] - load, boot_base, boot_length)):
        section = bounded(viva, start, end - start)
        count = unpack(section, 0, 1)[0]
        if count != 1:
            raise ValueError('This validated Altice layout expects one partition per ZIMAGE')
        kind, offset, size, destination, output_size = unpack(section, 4, 5)
        if kind != 3 or destination != 0 or offset < 24 or output_size != expected:
            raise ValueError('Unexpected Altice ZIMAGE partition')
        item = decode(tool, bounded(section, offset, size), output_size, name, output, dictionary)
        item.update(name=name, execution_base=hex(base), source_offset=hex(start + offset), type=kind)
        manifest['components'].append(item)
    dcm_start, dcm_end = info[3] - load, info[4] - load
    dcm = bounded(viva, dcm_start, dcm_end - dcm_start)
    if dcm[:8] != b'DCMGBODY':
        raise ValueError('Missing DCM header')
    count = unpack(dcm, 136, 1)[0]
    if not 1 <= count <= 128:
        raise ValueError('Invalid DCM module count')
    for index in range(count):
        packed_id, base, output_size, size, position = unpack(dcm, 140 + index * 20, 5)
        if position < 140 + count * 20:
            raise ValueError('DCM payload overlaps table')
        trunks, trunk_size, trunk_compressed = unpack(dcm, position, 3)
        if (trunks, trunk_size, trunk_compressed) != (1, output_size, size):
            raise ValueError('Only the validated single-trunk DCM layout is supported')
        module_id = packed_id & 0xFFFF
        name = f'dcm_{module_id:04x}'
        item = decode(tool, bounded(dcm, position + 12, size), output_size, name, output)
        item.update(name=name, module_id=hex(module_id), pool=(packed_id >> 16) & 255,
                    group=packed_id >> 24, execution_base=hex(base),
                    source_offset=hex(dcm_start + position + 12))
        manifest['components'].append(item)
    manifest['menu_targets'] = []
    zimage = (output / 'zimage.bin').read_bytes()
    for address in (0xF02D8870, 0xF032ACDC):
        manifest['menu_targets'].append({'address': hex(address), 'component': 'zimage',
            'offset': hex(address - z_base), 'first_32_bytes': bounded(zimage, address - z_base, 32).hex()})
    signature = b'Fraunhofer IIS MP3 v04.01.02 (high quality)'
    at = zimage.find(signature)
    manifest['mp3_signature'] = {'found': at >= 0, 'component_offset': hex(at) if at >= 0 else None,
                                 'execution_address': hex(z_base + at) if at >= 0 else None}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    for item in manifest['components']:
        print(f"{item['name']}: {item['size']} bytes at {item['execution_base']} SHA256={item['sha256']}")
    print(f'Handset dump 2 match: {dump_offset:#x}; manifest: {output / "manifest.json"}')


if __name__ == '__main__':
    main()
