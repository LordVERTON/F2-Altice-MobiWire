#!/usr/bin/env python3
"""S13.5A.103: strictly read-only, bounded B702 child-array relocation feasibility.
Does not create firmware images, modify source binaries, or propose writable free space.
"""
from pathlib import Path
from hashlib import sha256
import struct
import json

ROOT = Path.cwd()
FILE = ROOT / 'research/f2/work/extracted/altice_platform/zimage.bin'
BASE = 0xF023CA50
EXPECTED_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
OLD = 0xF0378720
EXPECTED_CHILDREN = (0x8569, 0x87ED)
NEXT_CHILD = 0xA07B
PARENT = 0xB702
NEW_CHILD = 0x8928

def fail(reason):
    raise SystemExit('ABORT: ' + reason)

if not FILE.is_file():
    fail('canonical ZIMAGE missing: ' + str(FILE))
data = FILE.read_bytes()
actual = sha256(data).hexdigest()
if actual != EXPECTED_SHA:
    fail('canonical ZIMAGE SHA256 mismatch: ' + actual)
if len(data) != 0x185E98:
    fail('canonical ZIMAGE size mismatch')
start = OLD - BASE
if not 0 <= start <= len(data) - 6:
    fail('child array address outside canonical image')
existing = struct.unpack_from('<3H', data, start)
if existing != EXPECTED_CHILDREN + (NEXT_CHILD,):
    fail('packed B702/B703 boundary mismatch: ' + repr(existing))

old_ptr = struct.pack('<I', OLD)
refs = [BASE + p for p in range(0, len(data)-3, 4) if data[p:p+4] == old_ptr]
old_pair = struct.pack('<2H', *EXPECTED_CHILDREN)
child_occurrences = [BASE + p for p in range(0, len(data)-3, 2) if data[p:p+4] == old_pair]
virtual = EXPECTED_CHILDREN + (NEW_CHILD,)
plan = {
    'run': 'S13.5A.103', 'mode': 'STRICTLY_OFFLINE_READ_ONLY',
    'source': str(FILE), 'source_sha256': actual,
    'b702_record_id': f'0x{PARENT:04X}',
    'current_child_array_address': f'0x{OLD:08X}',
    'old_children': [f'0x{x:04X}' for x in EXPECTED_CHILDREN],
    'immediate_next_halfword': f'0x{NEXT_CHILD:04X}',
    'proposed_virtual_children': [f'0x{x:04X}' for x in virtual],
    'proposed_virtual_bytes_le': struct.pack('<3H', *virtual).hex(' '),
    'aligned_literal_pointer_occurrences': [f'0x{x:08X}' for x in refs],
    'old_child_pair_occurrences': [f'0x{x:08X}' for x in child_occurrences],
    'constraints': [
        'Do not overwrite F0378724 (B703 first child).',
        'No B702 count or pointer edits until canonical record location and initializer/consumer provenance are proven.',
        'Candidate relocation must respect compressed-image mapping, allocation and all relevant references.',
        'This virtual three-entry array is not an actual firmware patch and does not prove menu visibility or launching.'
    ],
    'verdict': 'STRUCTURAL_FEASIBILITY_ONLY__NO_PATCH_AUTHORIZED',
}
report_dir = ROOT / 'research/f2/work/reports'
report_dir.mkdir(parents=True, exist_ok=True)
out = report_dir / 's13_5a103_b702_relocation_feasibility.json'
out.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps(plan, indent=2, ensure_ascii=False))
print('\nREPORT:', out)
print('NO USB / NO PHONE / NO FLASH OR FIRMWARE WRITES')
