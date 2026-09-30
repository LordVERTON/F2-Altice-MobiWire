"""Offline evidence checks for aud_player_media -> DAF_Open -> DCM.

Capstone checks the original instructions, not decompiler-generated prototypes.
The external ROM switch helper remains explicitly unverified.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import ALTICE_ALICE, ALTICE_PACKAGE, WORK_ROOT, GHIDRA_REPORTS


def main():
    root = WORK_ROOT / 'extracted/altice_platform'
    manifest = json.loads((root / 'manifest.json').read_text())
    alice = (ALTICE_ALICE / 'alice-py.bin').read_bytes()
    assert hashlib.sha256(alice).hexdigest() == manifest['dictionary_sha256']
    images = [('ALICE', 0x1024ec00, alice)]
    for entry in manifest['components']:
        if entry['name'] not in ('zimage', 'boot_zimage', 'dcm_010c'):
            continue
        data = (root / (entry['name'] + '.bin')).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry['sha256']
        images.append((entry['name'], int(entry['execution_base'], 16), data))
    rom = (ALTICE_PACKAGE / 'DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00/ROM').read_bytes()
    assert hashlib.sha256(rom).hexdigest() == manifest['input_rom_sha256']
    images.append(('ROM', 0x1000a000, rom))

    def read(address, size):
        for _, base, data in images:
            if base <= address and address + size <= base + len(data):
                return data[address-base:address-base+size]
        raise ValueError(f'Unmapped {address:#x}')

    def word(address):
        return struct.unpack('<I', read(address, 4))[0]

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    checks = []

    def instruction(address, mnemonic, operands):
        item = next(md.disasm(read(address, 4), address))
        assert (item.mnemonic, item.op_str) == (mnemonic, operands), (hex(address), str(item))
        checks.append(dict(address=hex(address), bytes=item.bytes.hex(),
                           instruction=f'{item.mnemonic} {item.op_str}'))

    def veneer(address, target):
        assert word(address) == 0xe51ff004 and word(address+4) == target | 1

    # Constructor stores Open at interface offset 0.
    assert word(0x10303c50) == 0x1028d231
    instruction(0x10303bf8, 'ldr', 'r0, [pc, #0x54]')
    instruction(0x10303bfa, 'str', 'r0, [r4]')
    # Filename at cfg+4, FSAL at self+0x2c; file-open mode 4.
    instruction(0x1028d250, 'movs', 'r2, #4')
    instruction(0x1028d252, 'blx', '#0x102fd48c')
    veneer(0x102fd48c, 0xf020f04c)
    instruction(0x1028d25c, 'blx', '#0x102fbfc4')
    veneer(0x102fbfc4, 0xf02add64)
    # The detector compares UTF-16 .MP3 and returns 5 for equality.
    assert read(0xf02adeb0, 10) == '.MP3\0'.encode('utf-16le')
    instruction(0xf02addf8, 'adr', 'r1, #0xb4')
    assert ((0xf02addf8 + 4) & ~3) + 0xb4 == 0xf02adeb0
    instruction(0xf02addfa, 'bl', '#0xf020fa88')
    instruction(0xf02addfe, 'cmp', 'r0, #0')
    instruction(0xf02ade00, 'bne', '#0xf02ade06')
    instruction(0xf02ade02, 'movs', 'r0, #5')
    # DAF selection block and indirect call.
    assert word(0x1028d368) == 0x10358255
    instruction(0x1028d2e8, 'ldr', 'r6, [pc, #0x7c]')
    instruction(0x1028d2ea, 'b', '#0x1028d2f2')
    instruction(0x1028d32a, 'blx', 'r6')
    # The compact switch is kept as an inference, since its ROM helper is missing.
    assert word(0x10015bd8) == 0x70008c68
    switch = read(0x1028d29e, 20)
    assert switch.hex() == '110c0c0c1d37252914141414140c272727273700'
    inferred_case5 = 0x1028d29e + 2 * switch[1+5]
    assert inferred_case5 == 0x1028d2e8
    # DAF_Open computes tables instead of embedding their exact addresses.
    assert word(0x103582ec) == 0xf03b1b60
    assert read(0x103582f4, 39) == b'hal\\audio\\src\\v1\\cmpdrv\\daf_comp_drv.c\0'
    for address, mnemonic, operands in (
        (0x10358278, 'movs', 'r0, #3'),
        (0x1035827c, 'bl', '#0x103162a8'),
        (0x10358284, 'adds', 'r3, #0x54'),
        (0x10358286, 'movs', 'r2, r3'),
        (0x10358288, 'subs', 'r2, #0x10'),
        (0x1035828c, 'blx', '#0x102fc1bc'),
        (0x10358296, 'movs', 'r0, #3'),
        (0x1035829a, 'bl', '#0x103162bc'),
        (0x102bde68, 'cmp', 'r0, #3'),
        (0x102bde6c, 'movs', 'r0, #0xff'),
        (0x102bde6e, 'adds', 'r0, #0xd'),
        (0x102bde70, 'bx', 'lr'),
    ):
        instruction(address, mnemonic, operands)
    veneer(0x102fc1bc, 0xf02ae548)
    # DCM wrappers and their decompression callback.
    veneer(0x102f81a4, 0xf020b6c8)
    veneer(0x102f82ac, 0xf021a854)
    assert word(0x10321840) == 0x102cb0ad
    assert word(0x103217f8) == 0x102cb0ad
    report = dict(checks=checks,
        verified=dict(constructor='0x10303BE0', media_open='0x1028D230',
            file_type_detector='0xF02ADD64', mp3_format=5, daf_open='0x10358254',
            parser_table='0xF03B1BA4', decoder_table='0xF03B1BB4',
            dpmgr_region=3, dcm_module='0x010C', dcm_decompress_callback='0x102CB0AC'),
        switch=dict(table_address='0x1028D29E', bytes=switch.hex(),
            inferred_case5_target=hex(inferred_case5), helper='0x70008C68',
            status='SDK-consistent switch8 inference; helper body not in mapped inputs'),
        limitations=['No handset execution', 'DCM runtime registration state not observed',
                    'No UI launch, SD playback or hardware audio output demonstrated'])
    (GHIDRA_REPORTS / 'daf_open_audit.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'PASS: {len(checks)} instructions, input hashes, veneers, strings and tables; switch inference explicit')


if __name__ == '__main__':
    main()
