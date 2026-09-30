# Workflow Ghidra local

> **Correction 2026-09-29 :** utiliser ALICE brute `alice-py.bin` à la base
> d'exécution `0x1024EC00` dans `Altice_MP3_Runtime_20260929`. La base historique
> `0x101812C4` citée plus bas n'est pas une base d'exécution. Les adresses de
> positions ALICE sont translatées de `+0xCD93C`; les adresses F0 ne changent pas.
> Voir [la preuve et les scripts](mp3-decoder-verdict-2026-09-29.md).

Cette analyse porte sur des copies locales décompressées. Les firmwares et exports restent dans les emplacements ignorés par Git.

## Chemins canoniques

- ALICE Altice : `research/f2/work/extracted/altice_alice/alice-py.bin`, base `0x101812C4`.
- ALICE QMobile : `research/f2/work/extracted/qmobile_alice/alice-py.bin`, base `0x1018A598`.
- Scripts Ghidra : `research/f2/scripts/ghidra/`.
- Projets et exports : `research/f2/work/ghidra/`.
- Résumés Ghidra : `research/f2/work/ghidra/alice_reports/`.

Architecture utilisée : ARM little-endian 32 bits, processeur `ARM:LE:32:v5t`, code Thumb. Les adresses candidates doivent être validées contre les octets, frontières de fonctions et références ; l’auto-analyse peut interpréter des données comme du code.

## Scripts

- `DisassembleAliceThumb.java` force le décodage Thumb sur l’image importée.
- `ExportAliceFunctions.java` et `ExportAliceDetails.java` exportent les fonctions et références.
- `TraceMenuDescriptor.py` et les utilitaires Python du même dossier produisent des rapports ciblés.
- `scripts/_paths.py` centralise les chemins des scripts locaux.

Les scripts `run_*.ps1` reçoivent le chemin de Ghidra/Python en paramètres ou utilisent les valeurs par défaut définies dans leur en-tête. Exécuter depuis la racine du dépôt et vérifier que les fichiers sources locaux existent. Ne pas remplacer les bases Ghidra ni lancer d’écriture de firmware depuis ces workflows.

Les anciens modes d’emploi sont archivés dans `docs/archive/` et peuvent contenir des chemins obsolètes.
