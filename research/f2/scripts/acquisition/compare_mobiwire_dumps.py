#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
compare_mobiwire_dumps.py

Compare deux dumps NOR MobiWire/MT6261 de 4 MiB :
- vérifie la taille ;
- calcule SHA-256 ;
- compte les octets différents ;
- affiche la première et la dernière différence ;
- regroupe les différences en plages contiguës ;
- compare par blocs de 4 KiB et 64 KiB ;
- écrit un rapport texte.

Usage :
    python -u .\compare_mobiwire_dumps.py .\mobiwire_dump_1.bin .\mobiwire_dump_2.bin
"""

import hashlib
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import REPORTS_ROOT

EXPECTED_SIZE = 0x00400000
BLOCK4K = 0x1000
BLOCK64K = 0x10000
MAX_RANGES_TO_PRINT = 200


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fmt_off(x):
    return f"0x{x:08X}"


def main():
    if len(sys.argv) != 3:
        print(
            "Usage : python -u .\\compare_mobiwire_dumps.py "
            ".\\mobiwire_dump_1.bin .\\mobiwire_dump_2.bin"
        )
        raise SystemExit(2)

    p1 = Path(sys.argv[1]).resolve()
    p2 = Path(sys.argv[2]).resolve()

    if not p1.exists():
        raise SystemExit(f"Fichier introuvable : {p1}")
    if not p2.exists():
        raise SystemExit(f"Fichier introuvable : {p2}")

    b1 = p1.read_bytes()
    b2 = p2.read_bytes()

    report_path = REPORTS_ROOT / "acquisition" / "mobiwire_dump_compare.txt"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    lines = []

    def log(s=""):
        print(s, flush=True)
        lines.append(s)

    log("============================================================")
    log(" COMPARAISON DUMPS MOBIWIRE / MT6261")
    log("============================================================")
    log("")
    log(f"Dump 1 : {p1}")
    log(f"Dump 2 : {p2}")
    log(f"Taille 1 : {len(b1)} octets")
    log(f"Taille 2 : {len(b2)} octets")
    log(f"SHA256 1 : {sha256_file(p1)}")
    log(f"SHA256 2 : {sha256_file(p2)}")
    log("")

    if len(b1) != len(b2):
        log("ERREUR : les fichiers n'ont pas la même taille.")
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        raise SystemExit(1)

    if len(b1) != EXPECTED_SIZE:
        log(
            f"ATTENTION : taille inattendue. "
            f"Attendu {EXPECTED_SIZE}, obtenu {len(b1)}."
        )
        log("")

    diffs = [i for i, (a, b) in enumerate(zip(b1, b2)) if a != b]
    n = len(diffs)

    log(f"Octets différents : {n}")
    log(f"Octets identiques : {len(b1) - n}")
    log(f"Pourcentage différent : {n * 100.0 / len(b1):.6f}%")

    if not diffs:
        log("")
        log("RESULTAT : dumps strictement identiques.")
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    log(f"Première différence : {fmt_off(diffs[0])}")
    log(f"Dernière différence  : {fmt_off(diffs[-1])}")
    log("")

    # Regrouper les différences contiguës
    ranges = []
    start = prev = diffs[0]
    for pos in diffs[1:]:
        if pos == prev + 1:
            prev = pos
        else:
            ranges.append((start, prev))
            start = prev = pos
    ranges.append((start, prev))

    log(f"Nombre de plages contiguës différentes : {len(ranges)}")
    log("")
    log("Premières plages différentes :")

    for idx, (a, b) in enumerate(ranges[:MAX_RANGES_TO_PRINT], 1):
        log(
            f"{idx:4d}. {fmt_off(a)} -> {fmt_off(b)} "
            f"({b - a + 1} octets)"
        )

    if len(ranges) > MAX_RANGES_TO_PRINT:
        log(
            f"... {len(ranges) - MAX_RANGES_TO_PRINT} plages supplémentaires "
            "non affichées."
        )

    log("")

    # Blocs 4 KiB différents
    diff4k = []
    for off in range(0, len(b1), BLOCK4K):
        if b1[off:off + BLOCK4K] != b2[off:off + BLOCK4K]:
            diff4k.append(off)

    log(f"Blocs 4 KiB différents : {len(diff4k)} / {len(b1) // BLOCK4K}")
    if diff4k:
        log("Offsets des blocs 4 KiB différents :")
        log(" ".join(fmt_off(x) for x in diff4k[:256]))
        if len(diff4k) > 256:
            log(f"... +{len(diff4k) - 256} autres blocs")
    log("")

    # Résumé par blocs 64 KiB
    log("Résumé par blocs de 64 KiB :")
    changed64 = 0

    for off in range(0, len(b1), BLOCK64K):
        c1 = b1[off:off + BLOCK64K]
        c2 = b2[off:off + BLOCK64K]
        diff_count = sum(a != b for a, b in zip(c1, c2))

        if diff_count:
            changed64 += 1
            h1 = hashlib.sha256(c1).hexdigest()[:16]
            h2 = hashlib.sha256(c2).hexdigest()[:16]
            log(
                f"{fmt_off(off)}-{fmt_off(off + len(c1) - 1)} : "
                f"{diff_count:6d} octets différents | "
                f"SHA1={h1} SHA2={h2}"
            )

    log("")
    log(f"Blocs 64 KiB différents : {changed64} / {len(b1) // BLOCK64K}")
    log("")
    log("Rapport écrit dans : " + str(report_path))

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
