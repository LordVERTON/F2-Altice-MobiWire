"""Verify ALICE runtime base, MP3 veneers and decoder callbacks from local bytes.

Requires capstone (available in the repository .venv). No handset access.
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
    rom = (ALTICE_PACKAGE / 'DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00/ROM').read_bytes()
    alice = (ALTICE_ALICE / 'alice-py.bin').read_bytes()
    base, size = struct.unpack_from('<II', rom, 0x5ba8)
    assert (base, size) == (0x1024ec00, len(alice))
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    def word(address):
        return struct.unpack_from('<I', alice, address - base)[0]
    calls = []
    for callsite, veneer, target in (
        (0x10368b16, 0x102faf64, 0xf03d850c),
        (0x10368b62, 0x102faf64, 0xf03d850c),
        (0x10370bf2, 0x102fab2c, 0xf03d852c),
        (0x1037203c, 0x102fab84, 0xf03d8784),
    ):
        insn = next(md.disasm(alice[callsite-base:callsite-base+4], callsite))
        assert insn.mnemonic == 'blx' and int(insn.op_str[1:], 16) == veneer
        assert word(veneer) == 0xe51ff004 and word(veneer+4) == target | 1
        calls.append(dict(callsite=hex(callsite), veneer=hex(veneer), target=hex(target)))
    callbacks = {}
    for role, literal, target in (
        ('Start', 0x10368be0, 0x1036c4e0),
        ('Stop', 0x10368be4, 0x1036c526),
        ('Process', 0x10368be8, 0x1036c410),
        ('SetParameter', 0x10368bec, 0x1036c4c0),
    ):
        assert word(literal) == target | 1
        callbacks[role] = dict(literal=hex(literal), target=hex(target))
    zimage = (WORK_ROOT / 'extracted/altice_platform/zimage.bin').read_bytes()
    table_offset = 0xf03b1ba4 - 0xf023ca50
    table = struct.unpack_from('<8I', zimage, table_offset)
    assert table == (0x10368bf5, 0x10368bfd, 0x2000, 2,
                     0x10368b0d, 0x10368b45, 0x1200, 1)
    report = dict(alice_runtime_base=hex(base), alice_size=size,
        alice_sha256=hashlib.sha256(alice).hexdigest(),
        rom_sha256=hashlib.sha256(rom).hexdigest(),
        base_evidence='ROM file offset 0x5BA8: base/length; callback targets independently coherent',
        legacy_analysis_base='0x101812C4', legacy_to_runtime_delta=hex(base-0x101812c4),
        calls=calls, callbacks=callbacks,
        component_table=dict(zimage_offset=hex(table_offset),
            mapped_address='0xF03B1BA4', words=[hex(x) for x in table]),
        limitations='DAF_Open, DCM activation, aud_player_media path and handset playback remain unproven.')
    output = GHIDRA_REPORTS / 'mp3_bridge_audit.json'
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
