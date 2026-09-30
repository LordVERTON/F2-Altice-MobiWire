#!/usr/bin/env python3
"""Read-only inventory of file-extension/type clues in local F2 firmware images.

String hits are clues only. This script does not infer that a handler exists.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[4]
SERVICE = ROOT / "research/f2/data/firmware-packages/altice-service/altice_service_package"
ALTICE = SERVICE / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00"
SOURCES = [
    ("Altice service image", SERVICE / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00.ALTICE_F2_DS_V02_1_181023_MP.bin"),
    ("Altice ROM", ALTICE / "ROM"),
    ("Altice VIVA", ALTICE / "VIVA"),
    ("Altice ALICE translated", ROOT / "research/f2/work/extracted/altice_alice/alice-translated-py.bin"),
    ("Altice ALICE raw", ROOT / "research/f2/work/extracted/altice_alice/alice-py.bin"),
    ("Altice ALICE container", ROOT / "research/f2/work/extracted/altice_alice/altice_ALICE_2.bin"),
    ("Handset dump 2", ROOT / "research/f2/data/dumps/mobiwire_dump_2.bin"),
    ("QMobile ROM comparison", ROOT / "research/f2/work/ghidra/qmobile_ROM_complete.bin"),
]
TERMS = (".mp3", "mp3", ".wav", "wav", ".amr", "amr", ".mid", "midi", ".3gp", "3gp",
         ".mp4", "mp4", ".jpg", "jpeg", "jpg", ".gif", "gif", ".bmp", "bmp",
         "FILE_TYPE", "filetype", "extension", "mime", "Audio Player", "Playlist")
OUT = ROOT / "research/f2/work/ghidra/alice_reports/filetype_mp3_dispatch.txt"


def hits(data: bytes, term: str):
    for label, needle in (("ASCII", term.encode("ascii")), ("UTF-16LE", term.encode("utf-16le"))):
        start = 0
        while True:
            off = data.lower().find(needle.lower(), start)
            if off < 0:
                break
            yield off, label
            start = off + 1


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    lines = [
        "ALTICE F2 — EXTENSION / FILE-TYPE / LAUNCHER INVENTORY",
        "Read-only byte scan. A token hit alone does not prove a dispatch table or usable handler.",
        "Offsets below are file offsets; no firmware writes performed.", "",
    ]
    for label, path in SOURCES:
        if not path.exists():
            lines += [f"SOURCE ABSENTE: {label}: {path}", ""]
            continue
        data = path.read_bytes()
        found = []
        seen = set()
        for term in TERMS:
            for off, enc in hits(data, term):
                key = (off, term.lower())
                if key not in seen:
                    found.append((off, term, enc))
                    seen.add(key)
        lines.append(f"{label}: {path.name}, {len(data)} octets, {len(found)} hits candidats")
        for off, term, enc in sorted(found):
            lo, hi = max(0, off - 20), min(len(data), off + len(term.encode("utf-16le")) + 28)
            raw = data[lo:hi]
            context = raw.decode("ascii", errors="replace").replace("\x00", "·").replace("\r", "\\r").replace("\n", "\\n")
            lines.append(f"  +0x{off:08X} [{enc}] {term!r}: {context!r}")
        if not found:
            lines.append("  Aucun hit des termes ciblés.")
        lines.append("")
    lines += [
        "CONTRÔLES / INTERPRÉTATION",
        "- Le contrôle physique utilisateur (2026-09-28): un petit .mp3 sélectionné dans File Manager n'offrait pas Lire/Ouvrir; seules des actions Bluetooth (envoyer/déplacer) étaient proposées.",
        "- Cela établit qu'aucune action de lecture n'est exposée par ce parcours File Manager observé. Cela ne prouve pas l'absence d'un décodeur ou d'un autre launch path.",
        "- Le contrôle statique Image Viewer reste incomplet: écran visible, mais aucun handler binaire d'initialisation/lancement attribué dans imageviewer_positive_control.txt.",
        "- Hit ALICE Altice traduit +0x000F0D1E: chaîne UTF-16 commençant par `Playlist\\\\audio_play_list\\\\...`; ressource candidate, sans xref/launch target établi.",
        "- Hit ALICE Altice traduit +0x00105DC0: extensions UTF-16 `.3GP`, `.MP4`, `.AVI`; aucune entrée `.MP3` n'apparaît dans cette liste scannée.",
        "- Les chaînes `audio/x-mp3`, `audio/mp3` et la liste d'extensions MP3 sont dans le binaire QMobile de comparaison, pas dans ALICE Altice; ne pas transférer cette preuve entre builds.",
        "- Pour prouver .mp3 -> handler, il faut relier une entrée de type/extension à une cible/callback puis à une fonction de lecture; de simples chaînes d'extension ne suffisent pas.",
        "",
        "VERDICT: ASSOCIATION .MP3 -> HANDLER = UNKNOWN (aucun dispatcher/handler établi).",
        "DÉCISION: la route File Manager directe n'est pas disponible dans le test utilisateur; ne pas déduire MP3 DECODER = ABSENT. Le décodeur reste UNKNOWN/UNCERTAIN.",
        "NEXT: retrouver les références de la ressource Playlist dans Ghidra et identifier si elle mène à une UI AudioPlayer; ensuite relier un éventuel handler au backend open/play. Si ce lien manque, rester UNKNOWN et comparer un donneur exact avant tout patch UI.",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nSaved {OUT}")


if __name__ == "__main__":
    main()
