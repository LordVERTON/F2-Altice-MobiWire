#!/usr/bin/env python3
"""Offline bounded instruction audit and emulation; no device or flash APIs.

Execute the original Audio registration bytes, including ARM veneers and all
reachable helpers. Check registration state idempotence, NOT Audio init or UI
launch idempotence. Canonical images are required. No callee is mocked.
"""
from pathlib import Path
import hashlib
import itertools
import json
import random
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / 'research/f2/work/reports'
RAM = 0xF0000000
RAM_SIZE = 0x100000
STACK = 0x20000000
STOP = STACK + 0x100
ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50
EXPECTED_D = '778b89f149e0600dcdca38b8f878fa046fdbffa1ddbaec645af70f6b56324078'

# End-exclusive code intervals, excluding literal pools and adjacent functions.
THUMB = {
    'audio_registration': (0x1033D840, 0x1033D85C),
    'registrar_A': (0x1031F71A, 0x1031F724),
    'registrar_B': (0x1031E120, 0x1031E132),
    'registrar_C': (0x1031F81C, 0x1031F826),
    'core': (0x10301910, 0x10301954),
    'context_copy': (0x10316898, 0x103168DE),
    'slot_setter': (0x1031145C, 0x1031148E),
    'channel_2_copy': (0x10314468, 0x10314488),
    'table_setter_wrapper': (0x1031E680, 0x1031E688),
    'table_setter': (0x10318D80, 0x10318DA4),
    'mirror_A': (0xF02B9EF0, 0xF02B9EF6),
    'mirror_B': (0xF02D1EC8, 0xF02D1ECE),
    'mirror_C': (0xF02F5FC8, 0xF02F5FCE),
}
VENEERS = {0x102FB97C: 0xF02B9EF1, 0x102FBCE4: 0xF02D1EC9,
           0x102FB984: 0xF02F5FC9}


def require(ok, msg):
    if not ok:
        raise RuntimeError(msg)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # Remove no inputs; only this audit's report paths are written.
    alice = (ROOT / 'research/f2/work/extracted/altice_alice/alice-py.bin').read_bytes()
    zimage = (ROOT / 'research/f2/work/extracted/altice_platform/zimage.bin').read_bytes()
    require(hashlib.sha256(alice).hexdigest() ==
            '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea', 'ALICE hash')
    require(hashlib.sha256(zimage).hexdigest() ==
            '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954', 'ZIMAGE hash')
    candidate = (ROOT / 'research/f2/work/candidates/s13_4h/candidate_D_image_8313_8321_both_to_audio_callback.bin').read_bytes()
    require(hashlib.sha256(candidate).hexdigest() == EXPECTED_D, 'candidate D hash')
    require(len(candidate) == len(zimage), 'D length')
    require([i for i, (a, b) in enumerate(zip(zimage, candidate)) if a != b] ==
            list(range(0x10946C, 0x109470)) + list(range(0x109474, 0x109478)), 'D exact diff')

    def raw(addr, size):
        data, base = (alice, ALICE_BASE) if addr < 0xF0000000 else (zimage, ZIMAGE_BASE)
        offset = addr - base
        require(0 <= offset <= len(data)-size, f'image bounds {addr:08X}')
        return data[offset:offset+size]

    report = ['S13.4I: bounded registration audit; strictly offline',
              'No device I/O. No recompression/repack. No Audio init execution.']
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    for name, (start, end) in THUMB.items():
        insns = list(md.disasm(raw(start, end-start), start))
        require(sum(i.size for i in insns) == end-start, f'complete decode {name}')
        report.append(f'\n{name}: {start:08X}..{end-1:08X}')
        report.extend(f'{i.address:08X} {i.bytes.hex():10} {i.mnemonic} {i.op_str}' for i in insns)
    for addr, target in VENEERS.items():
        require(raw(addr, 8) == struct.pack('<II', 0xE51FF004, target), 'exact ARM veneer')
        report.append(f'ARM veneer {addr:08X} -> {target:08X}')

    for name, start, end in [('dispatcher', 0x10336788, 0x103367F8),
                             ('slot_getter', 0x103097E8, 0x103097FC),
                             ('resolver_wrapper', 0x1034C7E4, 0x1034C810),
                             ('static_resolver', 0xF0316D74, 0xF0316D90)]:
        report.append(f'\n{name}: {start:08X}..{end-1:08X} (static inspection only)')
        report.extend(f'{i.address:08X} {i.bytes.hex():10} {i.mnemonic} {i.op_str}'
                      for i in md.disasm(raw(start, end-start), start))
    require(raw(0x1033679E, 2) == raw(0x103367E6, 2) == bytes.fromhex('a047'),
            'two distinct BLX r4 sites')
    require(raw(0x103097FC, 4) == struct.pack('<I', 0xF00BAD6C), 'slot getter base')
    require(raw(0x10311494, 4) == struct.pack('<I', 0xF00BAD8C), 'slot setter base')
    report += [
        'Dispatcher 1033679E invokes resolved registration callback.',
        'Then it reads slot(channel=0,index=1), restores its saved value,',
        'and invokes newly captured init at 103367E6 only when nonzero and different.',
        'Thus one ID lookup selects one registration callback, not necessarily one total indirect call.',
        'These dispatcher observations are static; no init/launch is emulated.',
    ]

    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for base, data in [(ALICE_BASE, alice), (ZIMAGE_BASE, zimage)]:
        start = base & ~0xFFF
        size = ((base-start+len(data)+0xFFF)//0x1000)*0x1000
        u.mem_map(start, size)
        u.mem_write(base, data)
    u.mem_map(RAM, RAM_SIZE)
    u.mem_map(STACK, 0x10000)
    allowed = list(THUMB.values()) + [(v, v+4) for v in VENEERS]
    visited = set()
    writes = set()

    def on_code(uc, addr, size, _):
        require(any(start <= addr and addr+size <= end for start, end in allowed),
                f'execution escaped audited code at {addr:08X}')
        visited.add(addr)

    def on_write(uc, access, addr, size, value, _):
        if STACK <= addr and addr+size <= STACK+0x10000:
            return
        expected = ((0xF00BAD6C <= addr and addr+size <= 0xF00BAD9C)
                    or addr in (0xF00B1568, 0xF00B156C, 0xF00B1578)
                    or (0xF00B66BC <= addr and addr+size <= 0xF00B66E8))
        require(size == 4 and addr % 4 == 0 and expected,
                f'unexpected global store {addr:08X}/{size}')
        writes.add(addr)

    u.hook_add(UC_HOOK_CODE, on_code)
    u.hook_add(UC_HOOK_MEM_WRITE, on_write)
    rng = random.Random(0x1341)
    baseline = rng.randbytes(RAM_SIZE)

    def w32(addr, value):
        u.mem_write(addr, struct.pack('<I', value))

    def call():
        u.reg_write(UC_ARM_REG_SP, STACK+0xF000)
        u.reg_write(UC_ARM_REG_LR, STOP | 1)
        u.reg_write(UC_ARM_REG_R0, rng.getrandbits(32))
        u.emu_start(0x1033D841, STOP, count=10000)
        require(u.reg_read(UC_ARM_REG_PC) == STOP, 'registration returned within instruction limit')

    cases = 0
    # lock==1 makes core return; slot_setter blocks on ANY nonzero lock.
    # Cover all combinations of zero / one / other locks and four context
    # branch classes per channel, with fixed pseudo-random surrounding RAM.
    for locks in itertools.product((0, 1, 2), repeat=3):
        for modes in itertools.product(range(4), repeat=3):
            u.mem_write(RAM, baseline)
            u.mem_write(0xF00BAAB9, bytes(locks))
            for channel, mode in enumerate(modes):
                ctx = 0xF00BAACC + 0xE0*channel
                w32(ctx+0x30, (1 << 9) if mode == 3 else 0)
                w32(ctx+0x34, 0x12345679 if mode == 1 else 0)
                w32(ctx+0x74, 0x23456789 if mode >= 2 else 0)
            call()
            after_one = bytes(u.mem_read(RAM, RAM_SIZE))
            call()
            after_two = bytes(u.mem_read(RAM, RAM_SIZE))
            require(after_one == after_two, f'non-idempotent global state locks={locks}, modes={modes}')
            cases += 1
    report += [f'\nRegistration cases PASS: {cases}',
               'Original machine instructions executed; no helper mocks.',
               'Full 1 MiB global RAM identical after first and second calls.',
               'Stack scratch and CPU registers excluded from equivalence.',
               f'Unique instructions visited: {len(visited)}',
               'Global write addresses: '+', '.join(f'{x:08X}' for x in sorted(writes)),
               'RESULT: registration global-state idempotence PASS in tested domain.',
               'NOT PROVEN: repeated Audio init / launch, reentrancy, concurrent writes, user trigger.',
               'HARDWARE WRITE AUTHORIZED: NO']
    result = {
        'stage': 'S13.4I', 'status': 'REGISTRATION_STATE_IDEMPOTENCE_PASS_BOUNDED',
        'cases': cases, 'candidate_D_sha256': EXPECTED_D,
        'visited_instructions': len(visited),
        'global_write_addresses': [f'0x{x:08X}' for x in sorted(writes)],
        'scope': 'native registration callback and complete called helper closure; fixed RAM between calls',
        'limitations': ['not Audio init/launch idempotence', 'not concurrent/reentrant execution',
                        'no proof of runtime ID dispatch order or dynamic resolver overrides'],
        'hardware_write_authorized': False,
    }
    (OUT / 's13_4i_registration_state_audit.txt').write_text('\n'.join(report)+'\n', encoding='utf-8')
    (OUT / 's13_4i_registration_state_audit.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
