# Reprise — Altice F2 / MobiWire NIKITI

Mis à jour le 29 septembre 2026. **Unique état courant**, à lire avant toute
reprise avec AGENTS.md. Firmware ALTICE_F2_DS_V02.1_181023_MP, MT6261.
Objectif : lecture MP3 SD avec backend natif, puis frontend minimal et File Manager.
Phase OFFLINE : aucun flash, écriture NVRAM, changement de pilote ou accès téléphone.

## État validé

- Dump2 canonique et dump3 identiques, 0x400000 octets, SHA256
  2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922.
- ALICE base runtime 0x1024EC00; header compressé 0x101812C4 distinct.
- VIVA du package identique aux octets du dump2; hashes ALICE/ZIMAGE/BOOT vérifiés.
- S01/S02 : décodeur MP3, DAF_Open, reconnaissance MP3=5 et DPMGR 3→0x010C.
- ABI construct/Open/Play recoupée; WAV construit un objet média, VM est un stub.
- Play 0x1035FB00 appelle DPMGR puis AudioDrain 0xF02AE5F0. Sortie physique inconnue.
- Switch8 0x70008C68 absent : sélection des cas et retours publics restent inférés.
- S09.7 : construction numérique du chemin et provenance du drive établies.
  Format ASCII racine à 0xF02B3D28, suffixe Audios UTF-16 à 0xF02B3D30;
  formatter 0xF022DC34, concaténation 0xF02E2A08.
- Drive courant RAM 0xF00AD8A3, préférence 0xF00AD89D; getter 0xF02B8FE8.
  Il utilise la préférence disponible sinon native_get_drive(8,2,0x18).
  Table 0xF00EF090, initialiseur 0x10300DA4, index→lettre 0x102F1084.
- Labels Phone/Memory Card associés aux catégories/index : INFÉRÉS SDK.
  Aucune lettre SD effective observée ou hardcodée.
- Lecture appareil, UI utilisable, hook, cave et recovery d'écriture non démontrés.

## Étape active et prochaine action unique

S09.7 documentée; POC_SPEC créé comme brouillon, **non prêt pour injection**.
Tracer la construction DAF avec callback NULL : 0x10358254 → veneer
0x102FC1B4 → 0xF02E1B00 → 0xF0297DC4. Comparer les champs construits aux
accès MHdl.Play 0x1035FB00, puis suivre leur fermeture/destruction.

Pourquoi : Open accepte cb_fct=NULL, mais DAF_Open choisit alors une autre
construction que le chemin composant avec callback. La lecture n'est pas
prouvée pour ce POC. Ne pas remplacer cette incertitude par une hypothèse SDK.
Conserver player/cfg/path jusqu'à quiescence établie; Stop déréférence MHdl,
Destroy n'appelle pas implicitement Close. Aucun patch à préparer maintenant.

## Dernière action et traitements actifs

Audits chemins et ABI terminés : 19 et 31 ancrages d'octets; 9 callbacks;
12 suffixes; 7 cas switch interprétés. Rapports sous alice_reports.
Aucune commande longue, aucun Ghidra ni accès téléphone lancé pour S09.7.
Les contrôles finaux et leur résultat sont consignés dans le journal.

## Documents à lire

- [Rapport S09, preuves et limites](docs/reverse-engineering/s09-file-path-and-minimal-player-2026-09-29.md).
- [POC_SPEC](docs/reverse-engineering/POC_SPEC.md).
- [Journal](docs/JOURNAL.md), [roadmap](docs/roadmap.md), [preuves](EVIDENCE.md).
- [S02](docs/reverse-engineering/daf-open-dispatch-2026-09-29.md) et
  [S01](docs/reverse-engineering/mp3-decoder-verdict-2026-09-29.md).

## Reproduction et continuité

Python : .venv/Scripts/python.exe. Scripts sous research/f2/scripts/analysis :
analyze_audio_paths.py, audit_minimal_player_abi.py, audit_daf_open.py.
Sorties locales ignorées Git : work/ghidra/alice_reports/audio_path_audit.json,
audio_path_evidence.txt, audio_drive_contexts.txt, minimal_player_abi.json,
minimal_player_abi_disasm.txt. Les preuves durables sont résumées dans S09.

Projet Ghidra existant : work/ghidra/Altice_MP3_Runtime_20260929.
Entrées : work/extracted/altice_alice/alice-py.bin et altice_platform/.
Donor : work/donor_repos/MT2503-2, référence de nommage seulement.
Vérifier les artefacts et processus avant reprise; mettre ce checkpoint à jour
avant travail long, après preuve nouvelle et en fin d'étape. Détails séparés,
progression au journal; suivre docs/ORGANISATION.md.

Les pages Notion ont été synchronisées avant cette phase et ne reflètent pas
encore S09.7; aucune écriture Notion effectuée pendant cette analyse.
Le checkpoint précédent est conservé dans docs/archive/pre-s09-final-2026-09-29/.
