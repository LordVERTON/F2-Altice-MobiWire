#!/usr/bin/env python3
"""S13.5A.124: resolve A123 ARM veneer literals and rigorously classify mapped boundaries.

Offline read-only analysis: SHA-256 pinning, A121/A122/A123 edge guards, no USB,
phone, emulation, firmware patch, relocation, or flash. TXT report exclusive-create.
"""
from __future__ import annotations
import argparse
import hashlib
import struct
import sys
from pathlib import Path

ALICE_BASE, ALICE_SIZE = 0x1024EC00, 0x157BB4
BOOT_BASE, BOOT_SIZE = 0xF01F19E4, 0x4B06C
ZIMAGE_BASE, ZIMAGE_SIZE = 0xF023CA50, 0x185E98
SHAS = {
    'ALICE': '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea',
    'BOOT_ZIMAGE': 'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e',
    'ZIMAGE': '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954',
}
# Literal destinations are derived from A123, NOT interpreted as identified peripherals.
VENEERS = ((0xF0210420, 0x00000C11), (0xF02104D0, 0x00000BFD),
           (0xF02105A0, 0x70008785), (0xF02105A8, 0x70008749))
# A123 provides six independently confirmed Thumb BLX -> ARM veneer edges.
EDGES = ((0xF021819A, 0xF02105A8), (0xF02181C4, 0xF02105A0),
         (0xF02181CE, 0xF02105A8), (0xF02181EC, 0xF02105A0),
         (0xF020C188, 0xF02104D0), (0xF020C190, 0xF0210420))


def load_guard(path: Path, title: str, size: int) -> bytes:
    if not path.is_file():
        raise RuntimeError(f'MISSING_{title}={path}')
    b = path.read_bytes()
    got = hashlib.sha256(b).hexdigest()
    if len(b) != size or got != SHAS[title]:
        raise RuntimeError(f'{title}_MISMATCH size=0x{len(b):X} sha256={got}')
    return b


def loc(addr: int, size: int = 1) -> str:
    for name, base, count in (('ALICE', ALICE_BASE, ALICE_SIZE),
                              ('BOOT_ZIMAGE', BOOT_BASE, BOOT_SIZE),
                              ('ZIMAGE', ZIMAGE_BASE, ZIMAGE_SIZE)):
        if base <= addr and addr + size <= base + count:
            return f'{name}+0x{addr-base:X}'
    return 'UNMAPPED_IN_THE_THREE_CANONICAL_IMAGES'


def check_literals(boot: bytes) -> None:
    assert BOOT_BASE + BOOT_SIZE == ZIMAGE_BASE
    for at, dst in VENEERS:
        off = at - BOOT_BASE
        if boot[off:off+4] != bytes.fromhex('04f01fe5'):
            raise RuntimeError(f'ARM_VENEER_OPCODE_MISMATCH=0x{at:08X}')
        got = struct.unpack_from('<I', boot, off+4)[0]
        if got != dst:
            raise RuntimeError(f'ARM_VENEER_LITERAL_MISMATCH=0x{at:08X} got=0x{got:08X}')


def check_edges(boot: bytes) -> None:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
        from capstone.arm import ARM_OP_IMM
    except ImportError as e:
        raise RuntimeError('CAPSTONE_REQUIRED') from e
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    for src, expected in EDGES:
        off = src - BOOT_BASE
        instr = next(cs.disasm(boot[off:off+4], src, 1), None)
        if not instr or instr.mnemonic.split('.')[0].lower() != 'blx':
            raise RuntimeError(f'BLX_NOT_FOUND=0x{src:08X}')
        ops = instr.operands
        if not ops or ops[-1].type != ARM_OP_IMM or (ops[-1].imm & 0xFFFFFFFF) != expected:
            raise RuntimeError(f'BLX_TARGET_MISMATCH=0x{src:08X}')


def format_report(boot: bytes) -> str:
    check_literals(boot)
    check_edges(boot)
    lines = [
        'S13.5A.124 — POST-SELECTION BOOT ARM VENEER / MEMORY COVERAGE AUDIT',
        'STRICTLY_OFFLINE=YES IMAGES_READ_ONLY=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES',
        'NO_GUEST_EXECUTION=YES NO_REAL_OK_TRACE=YES',
        *[f'{k}_GUARD=PASS SHA256={SHAS[k]}' for k in ('ALICE', 'BOOT_ZIMAGE', 'ZIMAGE')],
        'A123_VENEER_LITERAL_GUARD=PASS', 'A123_SIX_BLX_EDGE_GUARD=PASS',
        '=== A. OBSERVED THUMB -> ARM -> DESTINATION EDGES ===',
    ]
    vmap = dict(VENEERS)
    for src, veneer in EDGES:
        dst = vmap[veneer]
        lines.append(f'EDGE=0x{src:08X} BLX_ARM_VENEER=0x{veneer:08X} '
                     f'VENEER_LITERAL=0x{dst:08X} DEST_MODE={"THUMB" if dst&1 else "ARM"} '
                     f'DEST_INSTRUCTION_ADDRESS=0x{dst&~1:08X} '
                     f'DEST_MAPPING={loc(dst&~1,4)}')
    lines.append('=== B. FOUR VENEERS AND ADDRESS-SPACE CLASSIFICATION ===')
    for at, dest in VENEERS:
        codeaddr = dest & ~1
        lines.extend([
            f'VENEER=0x{at:08X} IMAGE={loc(at,8)} LDR_PC_OPCODE=04f01fe5',
            f'CELL=0x{at+4:08X} CELL_IMAGE={loc(at+4,4)} RAW_LITERAL=0x{dest:08X}',
            f'INTERWORKING_LOW_BIT={dest&1} POTENTIAL_MODE={"THUMB" if dest&1 else "ARM"}',
            f'NORMALIZED_DEST=0x{codeaddr:08X} COVERAGE={loc(codeaddr,4)}',
            'RUNTIME_ADDRESS_VALIDITY=NOT_DETERMINED_BY_THREE_IMAGE_COVERAGE',
        ])
    lines.append('=== C. PAIRED DESTINATION DISTANCES / CONTEXT ===')
    lines.append('LOW_PAIR_DELTA=0x%X' % abs((VENEERS[0][1]&~1)-(VENEERS[1][1]&~1)))
    lines.append('HIGH_PAIR_DELTA=0x%X' % abs((VENEERS[2][1]&~1)-(VENEERS[3][1]&~1)))
    # Only inspect the small actual veneer contexts; do not scan unrelated ROM.
    for at, _ in VENEERS:
        off = at-BOOT_BASE
        left = max(0, off-16)
        right = min(len(boot), off+24)
        lines.append(f'VENEER_CONTEXT=0x{at:08X} WINDOW=[0x{BOOT_BASE+left:08X},0x{BOOT_BASE+right:08X}) HEX={boot[left:right].hex()}')
    lines.extend([
        '=== D. DECISION / PROOF BOUNDARIES ===',
        'FOUR_VENEER_LITERAL_DESTINATIONS_CLASSIFIED=YES',
        'ALL_FOUR_DESTINATIONS_OUTSIDE_THREE_CANONICAL_IMAGES=YES',
        'NO_CLAIM_THAT_DESTINATIONS_ARE_INVALID=YES',
        'DEVICE_MEMORY_MAP_AND_EXTERNAL_ROM_CONTENTS=NOT_AVAILABLE_IN_THIS_AUDIT',
        'POSTSELECTION_PATH_CONSISTENT_WITH_SYSTEM_TASK_STATE=HYPOTHESIS_ONLY',
        'REAL_OK_TO_AUDIO_8928_DISPATCH=UNPROVEN',
        'SAFE_MENU_B702_RELOCATION=UNPROVEN',
        'NO_HARDWARE_PATCH_AUTHORIZED=YES',
        'NEXT=STOP_THIS_GENERIC_POSTSELECTION_BRANCH_UNLESS_NEW_MEMORY_MAP_PROOF;FOCUS_KNOWN_87ED_OK_EVENT_PATH',
        'A124_RESULT=BOUNDARIES_CLASSIFIED_NOT_AUDIO_LAUNCH_PROOF',
    ])
    return '\n'.join(lines) + '\n'


def selftest():
    assert loc(BOOT_BASE) == 'BOOT_ZIMAGE+0x0'
    assert loc(ZIMAGE_BASE) == 'ZIMAGE+0x0'
    assert all(loc(dst&~1,4).startswith('UNMAPPED') for _,dst in VENEERS)
    b = bytearray(BOOT_SIZE)
    for at, dst in VENEERS:
        struct.pack_into('<II', b, at-BOOT_BASE, 0xE51FF004, dst)
    check_literals(bytes(b))
    b[VENEERS[0][0]-BOOT_BASE+4] ^= 1
    try:
        check_literals(bytes(b))
    except RuntimeError as ex:
        assert 'LITERAL_MISMATCH' in str(ex)
    else:
        raise AssertionError('Corrupt literal passed')
    print('A124_SELF_TEST=PASS_VENEER_AND_COVERAGE_NEGATIVE_CONTROL')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path)
    p.add_argument('--boot', type=Path)
    p.add_argument('--out', type=Path)
    p.add_argument('--self-test', action='store_true')
    a = p.parse_args()
    if a.self_test:
        selftest()
        if a.root is None and a.boot is None and a.out is None:
            return 0
    if not all((a.root,a.boot,a.out)):
        p.error('--root, --boot and --out required for audit')
    try:
        load_guard(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',ALICE_SIZE)
        load_guard(a.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',ZIMAGE_SIZE)
        boot = load_guard(a.boot,'BOOT_ZIMAGE',BOOT_SIZE)
        report = format_report(boot)
        a.out.parent.mkdir(parents=True, exist_ok=True)
        with a.out.open('x', encoding='utf-8', newline='\n') as f:
            f.write(report)
        print('A124_REPORT_CREATED='+str(a.out.resolve()))
        print('A124_RESULT=BOUNDARIES_CLASSIFIED_NOT_AUDIO_LAUNCH_PROOF')
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print('A124_ABORT='+str(exc),file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
