#!/usr/bin/env python3
"""Read-only signature inventory for MP3/decoder markers in local Altice F2 images."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
SERVICE_DIR = ROOT / "research/f2/data/firmware-packages/altice-service/altice_service_package"
ALTICE = SERVICE_DIR / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00"
SOURCES = [
    ("Altice service image", SERVICE_DIR / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00.ALTICE_F2_DS_V02_1_181023_MP.bin", None),
    ("Altice ROM", ALTICE / "ROM", None),
    ("Altice VIVA", ALTICE / "VIVA", None),
    ("Altice ALICE decompressed", ROOT / "research/f2/work/extracted/altice_alice/alice-translated-py.bin", 0x101812C4),
    ("Altice ALICE container", ROOT / "research/f2/work/extracted/altice_alice/altice_ALICE_2.bin", None),
    ("QMobile ROM comparison", ROOT / "research/f2/work/ghidra/qmobile_ROM_complete.bin", None),
    ("handset dump 2", ROOT / "research/f2/data/dumps/mobiwire_dump_2.bin", None),
]
TERMS = (
    "MP3", "MPEG", "MPEG LAYER III", "AUDIO/MPEG", "AUDIO/MP3", "AUDIO/X-MP3",
    "DAF", "MPEG_AUDIO", "MEDIA_FORMAT", "DYNAMIC_COMP_DAF", "MP3DEC", "MP3_DEC",
    "MP3_DECODER", "CODEC_MP3", "LAYER3", "MPEG_LAYER_III",
)
OUT = ROOT / "research/f2/work/ghidra/alice_reports/mp3_decoder_verdict.txt"


def occurrences(data, needle):
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return
        yield pos
        start = pos + 1


def main():
    lines = [
        "ALTICE F2 — INVENTAIRE MP3 / DÉCODEUR (analyse statique ciblée)",
        "Aucune chaîne isolée ne suffit à prouver la présence ou l'absence d'un décodeur.",
        "Sources scannées en ASCII et UTF-16LE; offsets seulement, aucune écriture firmware.",
        "",
    ]
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    any_hits = False
    for label, path, base in SOURCES:
        if not path.exists():
            lines += [f"SOURCE ABSENTE: {label}: {path}", ""]
            continue
        data = path.read_bytes()
        if label in ("Altice ROM", "QMobile ROM comparison"):
            import re
            tags = [(m.start(), m.group().decode("ascii")) for m in re.finditer(rb"(?:MP|MM)[A-Z0-9]{2}", data)]
            lines += [f"{label}: {len(tags)} tokens matching the same MPxx/MMxx pattern; identities unverified."]
            for off, tag in tags:
                if tag in ("MP33", "MP36"):
                    version = data[off + 5:off + 8].decode("ascii", errors="replace")
                    lines.append(f"  +0x{off:08X} {tag}, adjacent version-like field={version!r} (meaning unknown)")
            if label == "QMobile ROM comparison":
                ext = data.find(b"MP3\x00MP4\x00AAC\x00")
                if ext >= 0:
                    lines.append(f"  +0x{ext:08X} plain file-type/extension text list contains MP3, MP4, AAC; not decoder evidence.")
            lines.append("")
        hits = []
        for term in TERMS:
            for enc, needle in (("ASCII", term.encode("ascii")), ("UTF16LE", term.encode("utf-16le"))):
                for off in occurrences(data, needle):
                    hits.append((off, term, enc))
        lines.append(f"{label}: {path.name}, {len(data)} bytes, marqueurs={len(hits)}")
        for off, term, enc in sorted(hits):
            runtime = f", adresse fichier mappée candidate=0x{base + off:08X}" if base else ""
            lo, hi = max(0, off - 12), min(len(data), off + len(term) + 20)
            snippet = data[lo:hi]
            context = snippet.decode("ascii", errors="replace").replace("\x00", "·")
            lines.append(f"  {enc} +0x{off:08X}{runtime}: {term}; contexte={context!r}; hex={snippet.hex(' ')}")
        if hits:
            any_hits = True
        else:
            lines.append("  Aucun des marqueurs ciblés.")
        lines.append("")

    lines += [
        "ANALYSE DU CHEMIN DE CODE DÉJÀ EXPORTÉ",
        "- 0x102362A4 construit une interface de callbacks nommée aud_player_media.",
        "- L'appelant direct démontré est 0x101B31FC, depuis le contexte 0x10214940, dont la suite observée est orientée liaison audio Bluetooth/A2DP.",
        "- Relecture des callbacks 0x1028D394/0x1028D378 et callees : 0x1024EDD8 crée/configure un objet générique, 0x1024D162 écrit un champ, 0x1024B758 résout une courte chaîne/ressource, 0x102474C6 est un retour vide, puis 0x1024EDA0 finalise l'objet. Ce chemin n'établit pas des opérations de lecture fichier ou de décodage.",
        "- Le callback UI 0x1028D114 atteint des services génériques de ressources/UI; il ne prouve pas une application AudioPlayer ni un décodeur.",
        "- Les exports actuels ne donnent pas de trace d'un parcours MP3 complet.",
        "- Les tokens Altice `MP33`/`MP36` sont noyés dans une série d'identifiants de forme MPxx/MMxx; `MP33` existe aussi dans le ROM QMobile. Leur sens n'est pas établi et ils ne prouvent pas un décodeur MP3.",
        "- La liste QMobile qui contient le texte `MP3` est une liste de types/extensions; elle concerne un autre build et ne prouve pas le décodage dans Altice.",
        "",
        "VERDICT PROVISOIRE: UNCERTAIN.",
        "Le backend/interface audio est présent; le chemin callback étudié est surtout état/configuration/ressources et ne démontre même pas une ouverture de fichier audio. Le décodeur MP3 exploitable reste indéterminé. Les marqueurs négatifs ne prouvent pas ABSENT; les tokens MP33/MP36 ne prouvent pas PRESENT. Ne pas patcher le menu avant d'avoir relié un codec/dispatcher au playback ou d'avoir testé un MP3 sur le téléphone.",
        "",
        "Next: inspecter les tables de composants/format et les dispatchers média dans les composants non ALICE, puis arrêter cette passe si aucune chaîne de sélection/init MP3 ne peut être reliée au playback.",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nSaved {OUT}")


if __name__ == "__main__":
    main()
