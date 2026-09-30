#!/usr/bin/env python3
import argparse
from pathlib import Path

DEFAULT_PATTERNS = [
    "AudioPlayer",
    "Audio Player",
    "AUDPLY",
    "audply",
    "mmi_audply",
    "InitAudioPlayerApp",
    "playlist",
    "Play list",
    "MP3",
    "DAF",
    "AAC",
    "audio/mp3",
    "audio/mpeg3",
    "audio/x-mp3",
    "audio/aac",
    "audio/x-mpeg-aac",
    r"media\audio",
    "AudioPlayerSrc",
    "AudioPlayerRes",
    "FMRadio",
    "FMradio",
    "fmrdo",
    "ImageViewer",
    "imgview",
    "SndRec",
    "sndrec",
    "DYNAMIC_COMP_DAF",
    "DYNAMIC_COMP",
    "DCMCMP",
]

def find_all(data: bytes, needle: bytes):
    pos = 0
    while True:
        i = data.find(needle, pos)
        if i < 0:
            return
        yield i
        pos = i + 1

def scan_file(path: Path, base=None):
    data = path.read_bytes()
    hits = []

    for pat in DEFAULT_PATTERNS:
        encodings = [
            ("ASCII", pat.encode("ascii", errors="ignore")),
            ("UTF16LE", pat.encode("utf-16le")),
        ]
        for encname, needle in encodings:
            if not needle:
                continue
            for off in find_all(data, needle):
                addr = (base + off) if base is not None else None
                hits.append((pat, encname, off, addr))

    return data, hits

def print_hits(label, path, base=None):
    data, hits = scan_file(path, base)

    print("=" * 88)
    print(label)
    print("Fichier :", path)
    print("Taille  :", len(data), f"(0x{len(data):X})")
    if base is not None:
        print("Base    :", f"0x{base:08X}")
    print("=" * 88)

    by_pattern = {}
    for pat, enc, off, addr in hits:
        by_pattern.setdefault(pat, []).append((enc, off, addr))

    for pat in DEFAULT_PATTERNS:
        vals = by_pattern.get(pat, [])
        if not vals:
            continue
        print(f"\n[{pat}] {len(vals)} occurrence(s)")
        for enc, off, addr in vals[:30]:
            if addr is None:
                print(f"  {enc:7s} offset=0x{off:08X}")
            else:
                print(f"  {enc:7s} offset=0x{off:08X}  addr=0x{addr:08X}")
        if len(vals) > 30:
            print(f"  ... {len(vals)-30} occurrence(s) supplémentaire(s)")

    present = sorted(by_pattern.keys(), key=str.lower)
    print("\n--- Résumé signatures présentes ---")
    if present:
        print(", ".join(present))
    else:
        print("(aucune des signatures ciblées)")

    return set(present)

def parse_int(x):
    return int(x, 0)

def main():
    ap = argparse.ArgumentParser(
        description="Compare les signatures AudioPlayer/MP3/FM dans les ALICE/VIVA QMobile et Altice."
    )
    ap.add_argument("--qmobile-alice", required=True)
    ap.add_argument("--altice-alice", required=True)
    ap.add_argument("--qmobile-base", type=parse_int, default=0x1018A598)
    ap.add_argument("--altice-base", type=parse_int, default=0x101812C4)
    ap.add_argument("--qmobile-viva")
    ap.add_argument("--altice-viva")
    args = ap.parse_args()

    qset = print_hits(
        "QMobile ALICE décompressée",
        Path(args.qmobile_alice),
        args.qmobile_base
    )
    print()
    aset = print_hits(
        "Altice ALICE décompressée",
        Path(args.altice_alice),
        args.altice_base
    )

    print("\n" + "=" * 88)
    print("DIFFÉRENCES ALICE")
    print("=" * 88)
    only_q = sorted(qset - aset, key=str.lower)
    only_a = sorted(aset - qset, key=str.lower)
    common = sorted(qset & aset, key=str.lower)

    print("Présent QMobile seulement :", ", ".join(only_q) if only_q else "(rien)")
    print("Présent Altice seulement  :", ", ".join(only_a) if only_a else "(rien)")
    print("Présent dans les deux     :", ", ".join(common) if common else "(rien)")

    if args.qmobile_viva and args.altice_viva:
        print()
        qv = print_hits("QMobile VIVA", Path(args.qmobile_viva))
        print()
        av = print_hits("Altice VIVA", Path(args.altice_viva))

        print("\n" + "=" * 88)
        print("DIFFÉRENCES VIVA")
        print("=" * 88)
        only_qv = sorted(qv - av, key=str.lower)
        only_av = sorted(av - qv, key=str.lower)
        commonv = sorted(qv & av, key=str.lower)

        print("Présent QMobile seulement :", ", ".join(only_qv) if only_qv else "(rien)")
        print("Présent Altice seulement  :", ", ".join(only_av) if only_av else "(rien)")
        print("Présent dans les deux     :", ", ".join(commonv) if commonv else "(rien)")

if __name__ == "__main__":
    main()
