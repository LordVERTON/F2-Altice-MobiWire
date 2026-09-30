#!/usr/bin/env python3
"""Search exact byte encodings of the public MT6261 DAF parser tables in Altice images.

This is a narrow positive-evidence check only: compilers may transform/remove tables,
so a miss cannot establish decoder absence.
"""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "work/donor_repos/MT2503-2/media/audio/src/aud_daf_parser.c"
IMAGES = {
    "service_ROM": ROOT / "data/firmware-packages/altice-service/altice_service_package/DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00/ROM",
    "VIVA": ROOT / "work/extracted/altice_alice/altice_VIVA.bin",
    "ALICE_translated": ROOT / "work/extracted/altice_alice/alice-translated-py.bin",
    "flash_dump_2": ROOT / "data/dumps/mobiwire_dump_2.bin",
    "ZIMAGE_decompressed": ROOT / "work/extracted/altice_platform/zimage.bin",
    "BOOT_ZIMAGE_decompressed": ROOT / "work/extracted/altice_platform/boot_zimage.bin",
    "DCM_010c_DAF_candidate": ROOT / "work/extracted/altice_platform/dcm_010c.bin",
}

v1 = [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
      0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
      0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]
v2 = [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
      0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]
rates = [44100, 48000, 32000]

def enc(vals, endian, width):
    fmt = {("le", 2): "<H", ("be", 2): ">H", ("le", 4): "<I", ("be", 4): ">I"}[(endian, width)]
    return b"".join(struct.pack(fmt, n) for n in vals)

def scan(data, sig):
    hits, start = [], 0
    while True:
        at = data.find(sig, start)
        if at < 0:
            return hits
        hits.append(at)
        start = at + 1

def main():
    print(f"Reference source: {REFERENCE}")
    for image_name, path in IMAGES.items():
        if not path.exists():
            print(f"{image_name}: MISSING {path}")
            continue
        data = path.read_bytes()
        print(f"\n{image_name}: {len(data)} bytes ({path})")
        for name, values, width in (("DAF_V1_BITRATE_TAB", v1, 2),
                                    ("DAF_V2_BITRATE_TAB", v2, 2),
                                    ("DAF_SAMPLERATE_TAB", rates, 2)):
            for endian in ("le", "be"):
                sig = enc(values, endian, width)
                hits = scan(data, sig)
                print(f"  {name} {endian}: {len(hits)} exact hit(s)" +
                      (" at " + ", ".join(f"0x{x:X}" for x in hits[:12]) if hits else ""))
        # Some builds may store media tables as wider integers.
        for endian in ("le", "be"):
            sig = enc(rates, endian, 4)
            hits = scan(data, sig)
            print(f"  DAF_SAMPLERATE_TAB 32-bit {endian}: {len(hits)} exact hit(s)" +
                  (" at " + ", ".join(f"0x{x:X}" for x in hits[:12]) if hits else ""))

if __name__ == "__main__":
    main()
