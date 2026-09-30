from pathlib import Path
import struct

p = Path(r"research/f2/work/extracted/altice_alice/alice-py.bin")
data = p.read_bytes()

BASE = 0x1024EC00

addresses = [
    0x1028D394,
    0x10358254,
    0x10358334,
]

print("ALICE")
print("  base :", hex(BASE))
print("  size :", len(data))
print()

for a in addresses:
    off = a - BASE
    print(f"0x{a:08X} -> file offset 0x{off:X}")

    if 0 <= off <= len(data) - 4:
        value = struct.unpack_from("<I", data, off)[0]
        raw = data[off:off + 32]

        print("  u32 :", hex(value))
        print("  raw :", raw.hex(" "))
    else:
        print("  HORS IMAGE")

    print()

lit = 0x10358334
off = lit - BASE
value = struct.unpack_from("<I", data, off)[0]
target = value & ~1

print("=== MHdl.Play ===")
print(f"literal address : 0x{lit:08X}")
print(f"raw value       : 0x{value:08X}")
print(f"thumb target    : 0x{target:08X}")
print(f"thumb bit       : {value & 1}")
print(f"in ALICE        : {BASE <= target < BASE + len(data)}")
