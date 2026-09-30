"""Append the 2026-09-28 Multimedia positive-control findings to research docs."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPDATES = {
    ROOT / "ROADMAP_MP3.md": r"""

## Controles positifs Multimedia (2026-09-28)

- [x] Inventorier et scanner le dump, image service, ROM, VIVA, ALICE compressee/decompressee/traduite pour les noms Image Viewer, FM Radio, AudioPlayer et les marqueurs connus. Reproducteur : `scripts/analysis/scan_multimedia_resource_markers.py`.
- [x] Separer les hits QMobile des preuves Altice : `FMradio` et les MIME `audio/mp3` de `qmobile_audio_superregion.bin` sont exclus comme preuves pour ce telephone.
- [x] Relier le resultat aux rapports Ghidra : les IDs enfants sont demandes aux APIs systeme `0xF032ACDC` / `0xF02D8870`; handlers feuille et registre non resolus, cibles F0 unmapped dans les composants fournis.
- [x] Conclure sans surinterpreter les chaines : noms Image Viewer/FM et AudioPlayer non trouves dans les images Altice scannees; `aud_player_media` et la ressource Playlist existent mais aucun XREF/launch MP3 n'est etabli.
- [!] Le controle positif statique est bloque par le registre/ROM systeme externe absent. IDs, ressources d'app et launch restent UNKNOWN; ne pas patcher le menu. Rapport `work/ghidra/alice_reports/multimedia_positive_controls.txt`.
- [ ] Reprendre cette branche seulement si une ROM systeme/export de plateforme ou un build donneur vraiment compatible est acquis; conserver MP3 decoder = UNKNOWN.
""",
    ROOT / "STATUS.md": r"""

MISE A JOUR 2026-09-28 — CONTROLES MULTIMEDIA
Image Viewer et FM Radio sont confirmes presents par observation utilisateur, mais leur ID, ressource et launch binaire restent UNKNOWN. Le scan des composants Altice n'a trouve aucun de leurs noms; les hits FMradio/MIME audio/mp3 du rapport audio_refs sont QMobile et exclus. Les marqueurs `aud_player_media` et `Playlist\audio_play_list.sal` dans ALICE ne prouvent pas un launch/player. Le registre est fourni par APIs plateforme F0 non mappees dans les composants locaux. AudioPlayer et decoder restent UNKNOWN; aucun patch menu. Rapport `work/ghidra/alice_reports/multimedia_positive_controls.txt`. Prochaine action statique : obtenir ROM systeme ou temoin compatible; la comparaison locale est a sa limite.
""",
    ROOT / "EVIDENCE.md": r"""

- **Controles positifs Multimedia, 2026-09-28 :** scan reproductible ASCII/UTF-16LE/BE du dump 2, image service, ROM, VIVA, ALICE compressee/decompressee/traduite. Aucun nom d'app Image Viewer/FM/AudioPlayer dans les composants Altice scannes. Les hits `aud_player_media` (ALICE +0x3E500, +0x3E61C, +0x3E808, +0x3E904, +0xB5038) renvoient au contexte audio generique/A2DP deja etudie; `Playlist\\audio_play_list.sal` a +0xF0D1E n'a pas de XREF Ghidra ni pointeur absolu reconnu. Les APIs d'enumeration menu se branchent sur `0xF032ACDC` / `0xF02D8870`, non mappees dans le package; le launch feuille n'est pas resolu. Les hits FMradio/MIME du `audio_refs.log` appartiennent a QMobile, pas Altice. Conclusion : IDs/launch des deux apps visibles, slot AudioPlayer, frontend et decoder Altice restent UNKNOWN; ne pas patcher. Rapport `work/ghidra/alice_reports/multimedia_positive_controls.txt`; scan `scripts/analysis/scan_multimedia_resource_markers.py`.
""",
}

for path, addition in UPDATES.items():
    old = path.read_text(encoding="utf-8")
    marker = "## Controles positifs Multimedia (2026-09-28)" if path.name == "ROADMAP_MP3.md" else "MISE A JOUR 2026-09-28 — CONTROLES MULTIMEDIA" if path.name == "STATUS.md" else "Controles positifs Multimedia, 2026-09-28"
    if marker in old:
        continue
    path.write_text(old.rstrip() + addition + "\n", encoding="utf-8")
    print(f"updated {path}")
