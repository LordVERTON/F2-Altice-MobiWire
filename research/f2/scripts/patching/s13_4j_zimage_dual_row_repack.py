#!/usr/bin/env python3
"""Canonical-baseline physical characterization only; NEVER accesses a device.

Requires exact canonical recompression before encoding candidate D. Keeps all
component addresses fixed, updates the ZIMAGE compressed-length field, and
pads the released tail with FF. Produces an experimental image and sector
comparison artifacts, not a payload authorized for use on the current phone.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[4]
MTK = Path(r'C:\Users\verto\mtkclient')
OUT = ROOT / 'research/f2/work/candidates/s13_4j'
REPORTS = ROOT / 'research/f2/work/reports'
TOOL = MTK / 'research/f2/work/donor_repos/MT2503-2/tools/7lzma.exe'
ALICE = ROOT / 'research/f2/work/extracted/altice_alice/alice-py.bin'
ZIMAGE = ROOT / 'research/f2/work/extracted/altice_platform/zimage.bin'
CANDIDATE = ROOT / 'research/f2/work/candidates/s13_4h/candidate_D_image_8313_8321_both_to_audio_callback.bin'
SECTION = 0x4C258
NEXT = 0x13D570
VIVA = 0x4C20C


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def codec(mode, source, target):
    result = subprocess.run([str(TOOL), mode, str(source), str(target), str(ALICE)],
                            capture_output=True, timeout=120)
    require(result.returncode == 0, f'7lzma {mode} failed: {result.stdout!r} {result.stderr!r}')
    return target.read_bytes()


def ranges(indices):
    out = []
    for index in indices:
        if out and out[-1][1] == index:
            out[-1][1] = index+1
        else:
            out.append([index, index+1])
    return out


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    gate = json.loads((REPORTS / 's13_4i_registration_state_audit.json').read_text())
    require(gate['status'] == 'REGISTRATION_STATE_IDEMPOTENCE_PASS_BOUNDED'
            and gate['cases'] == 1728, 'registration gate')
    require(sha(TOOL.read_bytes()) ==
            '092190b3504bd433019a8c211f16b4f8c01817c0464c9d178075470f228aabd8', 'codec hash')
    require(sha(ALICE.read_bytes()) ==
            '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea', 'preset hash')
    zimage = ZIMAGE.read_bytes()
    require(sha(zimage) == '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954', 'ZIMAGE hash')
    logical = CANDIDATE.read_bytes()
    require(sha(logical) == gate['candidate_D_sha256'] ==
            '778b89f149e0600dcdca38b8f878fa046fdbffa1ddbaec645af70f6b56324078', 'D hash')
    dump_path = MTK / 'research/f2/data/dumps/mobiwire_dump_2.bin'
    dump = dump_path.read_bytes()
    require(len(dump) == 0x400000 and sha(dump) ==
            '2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922', 'dump canonical')
    require(struct.unpack_from('<6I', dump, SECTION) ==
            (1, 3, 24, 0xF12FF, 0, 0x185E98), 'ZIMAGE partition geometry')
    require(struct.unpack_from('<5I', dump, VIVA+0x38) ==
            (0x1004C20C, 0x1004C258, 0x1013D570, 0x10162B6C, 0x1018129C), 'VIVAInfo addresses')
    start = SECTION+24
    old_length = 0xF12FF
    original = dump[start:start+old_length]
    require(sha(original) == 'f7152fde422628928e47e1a5cf6f60e538999367f56fba4f6a5bab07e778ae6a', 'original compressed stream')
    encoded = codec('etp', ZIMAGE, OUT / 'canonical_recompressed.lzma')
    require(encoded == original, 'canonical recompression must be byte-perfect')
    require(codec('dtp', OUT / 'canonical_recompressed.lzma', OUT / 'canonical_roundtrip.bin') == zimage,
            'canonical roundtrip')
    compressed = codec('etp', CANDIDATE, OUT / 'candidate_D_recompressed.lzma')
    require(codec('dtp', OUT / 'candidate_D_recompressed.lzma', OUT / 'candidate_D_roundtrip.bin') == logical,
            'D exact roundtrip')
    require(compressed[:13] == original[:13], 'LZMA properties/dictionary/output size unchanged')
    require(0 < len(compressed) <= old_length, 'D fits original slot; no relocation supported')

    image = bytearray(dump)
    image[start:start+old_length] = compressed + b'\xff'*(old_length-len(compressed))
    struct.pack_into('<I', image, SECTION+12, len(compressed))
    image = bytes(image)
    changes = [i for i,(a,b) in enumerate(zip(dump,image)) if a != b]
    allowed = lambda i: SECTION+12 <= i < SECTION+16 or start <= i < start+old_length
    require(len(image) == len(dump) and all(allowed(i) for i in changes), 'physical change allow-list')
    require(image[NEXT:] == dump[NEXT:], 'BOOT/DCM/ALICE/all later regions unchanged')
    require(image[VIVA:SECTION] == dump[VIVA:SECTION], 'VIVA header/address metadata unchanged')
    require(image[0x2C0000:] == dump[0x2C0000:], 'canonical user-data tail preserved')
    stored_length = struct.unpack_from('<I', image, SECTION+12)[0]
    require(image[start:start+stored_length] == compressed, 'embedded compressed slice exact')

    # Decode BOOT with the same unchanged preset as an independent dependency check.
    count, kind, offset, size, dest, usize = struct.unpack_from('<6I', image, NEXT)
    require((count,kind,dest,usize) == (1,3,0,0x4B06C) and offset >= 24
            and NEXT+offset+size <= 0x162B6C, 'BOOT geometry')
    boot_stream = OUT / 'boot_unchanged.lzma'
    boot_stream.write_bytes(image[NEXT+offset:NEXT+offset+size])
    boot = codec('dtp', boot_stream, OUT / 'boot_unchanged_roundtrip.bin')
    require(sha(boot) == 'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e',
            'BOOT exact decode with canonical ALICE preset')

    bundle = OUT / 'canonical_sector_comparison_NOT_FOR_WRITE'
    bundle.mkdir(exist_ok=True)
    sectors = []
    for addr in sorted({i & ~0xFFF for i in changes}):
        before, after = dump[addr:addr+0x1000], image[addr:addr+0x1000]
        changed = sum(a != b for a,b in zip(before,after))
        rising = sum(((~a)&b&255).bit_count() for a,b in zip(before,after))
        falling = sum((a&(~b)&255).bit_count() for a,b in zip(before,after))
        require(addr+0x1000 <= 0x2C0000, 'sector below data boundary')
        (bundle / f'{addr:06x}_canonical_before.bin').write_bytes(before)
        (bundle / f'{addr:06x}_candidate_after.bin').write_bytes(after)
        sectors.append({'address': f'0x{addr:06X}', 'size': 4096,
                        'before_sha256': sha(before), 'after_sha256': sha(after),
                        'changed_bytes': changed, 'bits_0_to_1': rising,
                        'bits_1_to_0': falling, 'erase_required': bool(rising)})
    image_path = OUT / 'candidate_D_CANONICAL_BASELINE_NOT_FOR_FLASH.bin'
    image_path.write_bytes(image)
    result = {
        'stage': 'S13.4J', 'status': 'OFFLINE_PHYSICAL_CHARACTERIZATION_PASS_NOT_FLASHABLE',
        'baseline': str(dump_path), 'baseline_sha256': sha(dump),
        'candidate_sha256': sha(image), 'candidate_path': str(image_path),
        'logical_D_sha256': sha(logical), 'compressed_D_sha256': sha(compressed),
        'canonical_byte_perfect_recompression': True, 'candidate_exact_decode': True,
        'boot_exact_decode': True, 'compressed_old_length': old_length,
        'compressed_new_length': len(compressed), 'freed_bytes_ff_padded': old_length-len(compressed),
        'compressed_length_field': f'0x{SECTION+12:06X}',
        'component_addresses_unchanged': True, 'alice_canonical_unchanged': True,
        'changed_bytes': len(changes), 'changed_sector_count': len(sectors),
        'diff_span': [f'0x{min(changes):06X}', f'0x{max(changes):06X}'],
        'diff_ranges_end_exclusive': [[f'0x{a:06X}',f'0x{b:06X}'] for a,b in ranges(changes)],
        'sectors': sectors, 'hardware_write_authorized': False,
        'limitations': ['canonical dump baseline, NOT verified current handset state',
                        'no live-data-preserving full image approval',
                        'no hardware write plan or atomic multi-sector recovery established',
                        'UI activation/repeated init not tested',
                        'dynamic resolver overrides not observed on device'],
    }
    (OUT / 'manifest.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    summary = {k:v for k,v in result.items() if k not in ('sectors','diff_ranges_end_exclusive')}
    text = json.dumps(summary, indent=2)+'\n\nSECTORS\n'+json.dumps(sectors, indent=2)+'\n'
    (REPORTS / 's13_4j_zimage_dual_row_repack.txt').write_text(text, encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
