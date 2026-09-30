#!/usr/bin/env python3
"""Scan only local Altice firmware artifacts for app/resource name markers.

String hits are leads, not proof of an app registration or launch path.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "data/firmware-packages/altice-service/altice_service_package/DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00"
FILES = {
    "dump_2": ROOT / "data/dumps/mobiwire_dump_2.bin",
    "service_image": SERVICE.with_name("DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00.ALTICE_F2_DS_V02_1_181023_MP.bin"),
    "ROM": SERVICE / "ROM",
    "VIVA": ROOT / "work/extracted/altice_alice/altice_VIVA.bin",
    "ALICE_compressed": ROOT / "work/extracted/altice_alice/altice_ALICE_2.bin",
    "ALICE_decompressed": ROOT / "work/extracted/altice_alice/alice-py.bin",
    "ALICE_translated": ROOT / "work/extracted/altice_alice/alice-translated-py.bin",
}
TERMS = (
    "Image Viewer", "ImageViewer", "ImageView", "Photo Viewer", "PhotoViewer",
    "FM Radio", "FMRadio", "FMradio", "FmRadio", "Radio",
    "Audio Player", "AudioPlayer", "AudioPlay", "APP_AUDIOPLAYER",
    "mmi_audply_entry_main", "aud_player_media", "audio_play_list", "Playlist",
)

def variants(term: str):
    return (("ASCII", term.encode("ascii")),
            ("UTF16LE", term.encode("utf-16le")),
            ("UTF16BE", term.encode("utf-16be")))

def main():
    for label, path in FILES.items():
        if not path.is_file():
            print(f"[{label}] MISSING {path}")
            continue
        blob = path.read_bytes()
        print(f"[{label}] {len(blob)} bytes: {path}")
        for term in TERMS:
            for encoding, needle in variants(term):
                start = 0
                while True:
                    offset = blob.find(needle, start)
                    if offset < 0:
                        break
                    lo, hi = max(0, offset - 12), min(len(blob), offset + len(needle) + 12)
                    context = blob[lo:hi].hex(" ")
                    print(f"  {term!r} {encoding} +0x{offset:08X} context[{lo:#x}:{hi:#x}]={context}")
                    start = offset + 1

if __name__ == "__main__":
    main()
