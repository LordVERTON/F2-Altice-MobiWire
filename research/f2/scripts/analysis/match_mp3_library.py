"""Match SDK ELF32 archive functions against recovered Altice code, offline.

Relocation bytes are excluded; every other byte in the symbol must match.
Matches identify code, not runtime reachability. No firmware writes.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import WORK_ROOT, GHIDRA_REPORTS


def members(data):
    assert data[:8] == b'!<arch>\n'
    pos = 8
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        assert header[58:] == b'`\n'
        size = int(header[48:58])
        yield header[:16].decode().strip(), data[pos + 60:pos + 60 + size]
        pos += 60 + size + size % 2


def symbols(data):
    if data[:7] != b'\x7fELF\x01\x01\x01':
        return
    shoff = struct.unpack_from('<I', data, 32)[0]
    entsize, count = struct.unpack_from('<HH', data, 46)
    sections = [struct.unpack_from('<10I', data, shoff + i * entsize) for i in range(count)]
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = data[strings[4]:strings[4] + strings[5]]
        for pos in range(section[4], section[4] + section[5], section[9]):
            name, value, size, info, other, idx = struct.unpack_from('<IIIBBH', data, pos)
            if info & 15 != 2 or size < 24 or not 0 < idx < len(sections):
                continue
            value &= ~1
            sec = sections[idx]
            code = data[sec[4] + value:sec[4] + value + size]
            mask = bytearray(b'\x01' * size)
            for rel in sections:
                if rel[1] not in (4, 9) or rel[7] != idx:
                    continue
                for rpos in range(rel[4], rel[4] + rel[5], rel[9]):
                    offset, rinfo = struct.unpack_from('<II', data, rpos)
                    if rinfo & 255 == 0:
                        continue
                    for byte in range(max(0, offset - value), min(size, offset - value + 4)):
                        mask[byte] = 0
            yield names[name:].split(b'\0', 1)[0].decode(), code, mask


def main():
    folder = WORK_ROOT / 'extracted/altice_platform'
    manifest = json.loads((folder / 'manifest.json').read_text())
    components = []
    for item in manifest['components']:
        data = (folder / (item['name'] + '.bin')).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item['sha256']
        components.append((item['name'], int(item['execution_base'], 16), data))
    results = []
    provenance = {}
    for variant in ('', 'SLIM/'):
        lib = WORK_ROOT / ('donor_repos/MT2503-2/hal/audio/lib/MTKRVCT31/' + variant + 'mp3_dec.a')
        provenance[str(lib.relative_to(WORK_ROOT))] = hashlib.sha256(lib.read_bytes()).hexdigest()
        for member, obj in members(lib.read_bytes()):
            for symbol, code, mask in symbols(obj):
                runs = []
                start = 0
                for i in range(len(mask) + 1):
                    if i == len(mask) or not mask[i]:
                        runs.append((i - start, start))
                        start = i + 1
                length, anchor = max(runs)
                if length < 16:
                    continue
                for component, base, data in components:
                    pos = 0
                    while True:
                        hit = data.find(code[anchor:anchor + length], pos)
                        if hit < 0:
                            break
                        pos = hit + 1
                        offset = hit - anchor
                        if offset < 0 or offset + len(code) > len(data):
                            continue
                        if all(not mask[i] or code[i] == data[offset + i] for i in range(len(code))):
                            results.append(dict(variant=variant or 'normal', member=member,
                                symbol=symbol, component=component, address=hex(base + offset),
                                size=len(code), compared_bytes=sum(mask), anchor_bytes=length))
    output = GHIDRA_REPORTS / 'mp3_library_matches.json'
    output.write_text(json.dumps(results, indent=2), encoding='utf-8')
    (GHIDRA_REPORTS / 'mp3_library_provenance.json').write_text(
        json.dumps(provenance, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
