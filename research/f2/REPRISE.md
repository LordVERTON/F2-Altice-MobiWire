# Reprise - Altice F2 / MobiWire NIKITI

**Etat courant au 1 octobre 2026.** Lire ce checkpoint avant les notes historiques.

## Checkpoint S12.3-S12.6 - ALICE extension / LZMA / candidat offline

Mis a jour le 1 octobre 2026.

Branche active : `s12-alice-extension`.

Statut : **OFFLINE - AUCUN FLASH AUTORISE**.

### S12.3 - valide

Le repack ALICE_2 est maintenant reproductible byte-perfect.

Original :

- U size : `0x157BB4`
- U SHA256 : `7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea`
- ALICE_2 size : `0x113E2C`
- ALICE_2 SHA256 : `8a06970667c6af37f7a6b1fb28dde0622e396fccd5c2a0b450bd795a0257988f`
- mapping : `11001`

Extension controlee :

- U size : `0x158BB4`
- U SHA256 : `c2fedce8a8f6621dcd617e87502922031ffa6574e01d2539b67fa56f9fdc3a31`
- ALICE_2 size : `0x1151AC`
- ALICE_2 SHA256 : `3f55d808d834076865c992200b1294fb84d1dd5be83f9d39cb917e79da12424b`
- stream : `0x106DC0`
- mapping : `11033`
- mapping addr : `0x10288084`
- dictionary addr : `0x10292CE8`
- physical headroom : `0x29BB8`

Tests PASS :

- original byte-perfect repack
- original exact decode
- +0x1000 exact decode
- original U prefix preserved
- appended payload preserved
- dictionary preserved

### S12.4 / S12.4b - preset LZMA

ZIMAGE canonical :

- size `0x185E98`
- SHA256 `85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954`

BOOT_ZIMAGE canonical :

- size `0x4B06C`
- SHA256 `aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e`

Experiences donor `7lzma dtp` :

- original U -> canonical
- U + 0x1000 -> Data error
- U + 0x1000 zero -> Data error
- tail original modifie -> Data error
- 0x1000 zero + U -> canonical
- 0x1000 pattern + U -> canonical

Conclusion STRONGLY SUPPORTED :

le preset LZMA est ancre sur la FIN du preset fourni.

Decision :

- `D+0xC188 = 0x1024EC00` KEEP
- `D+0xC18C = 0x103A67B4` KEEP
- preset size `0x157BB4` KEEP

La fenetre LZMA ne doit PAS etre agrandie avec la fenetre ALICE generale.

### S12.5 - matrice runtime validee

Changements :

| Offset | Old | New | Role |
|---|---|---|---|
| `0xB918` | `0x00157BB4` | `0x00158BB4` | ALICE size getter |
| `0xEC54` | `0x00157BB4` | `0x00158BB4` | ALICE config size |
| `0xECC8` | `0x00157BB4` | `0x00158BB4` | ALICE HW/window size |
| `0xFBAC` | `0x00157BB4` | `0x00158BB4` | address range size |
| `0x110DC` | `0x103A67B4` | `0x103A77B4` | region descriptor end |
| `0xC18C` | `0x103A67B4` | KEEP | LZMA preset end |
| `0x4C22C` | `0x00248EBC` | `0x0024A23C` | VIVA file_len |

Bases conservees :

- `B910 = 0x1024EC00`
- `C188 = 0x1024EC00`
- `EC50 = 0x1024EC00`
- `ECC4 = 0x1024EC00`
- `FBA8 = 0x1024EC00`
- `110D8 = 0x1024EC00`
- `4C254 = 0x1018129C`
- `1812A4 = 0x101812C4`

Nouvelle geometrie :

- runtime end : `0x103A77B4`
- HW rounded end : `0x103A77C0`
- group end : `0x103A7800`
- VIVA file_len : `0x24A23C`
- VIVA physical end : `0x296448`
- next occupied region : `0x2C0000`
- headroom : `0x29BB8`

### S12.6 - valide

Script :

`research/f2/scripts/patching/build_s12_6_candidate.py`

Le run corrige passe tous les gates.

Invariants ALICE :

- stable stream bytes : `0x105A6E`
- stable mapping entries : `10999`
- last old group U start : `0x157B80`
- last old real bytes : `0x34`
- replaced old padding : `0x4C`
- dictionary/codebook preserved : PASS

Patch matrix :

- `D+0x00B918` : `0x00157BB4 -> 0x00158BB4`
- `D+0x00EC54` : `0x00157BB4 -> 0x00158BB4`
- `D+0x00ECC8` : `0x00157BB4 -> 0x00158BB4`
- `D+0x00FBAC` : `0x00157BB4 -> 0x00158BB4`
- `D+0x0110DC` : `0x103A67B4 -> 0x103A77B4`
- `D+0x04C22C` : `0x00248EBC -> 0x0024A23C`

LZMA preset :

- base `0x1024EC00` : unchanged
- end `0x103A67B4` : unchanged

Physical layout :

- new VIVA end : `0x296448`
- next region : `0x2C0000`
- remaining headroom : `0x29BB8`

Exhaustive diff audit :

- changed bytes : `62429`
- diff ranges : `792`
- unauthorized changed bytes : `0`
- all ranges : ALLOWED

Candidate self-check :

- candidate VIVA file_len : PASS
- candidate ALICE extract : PASS
- candidate ALICE decode : PASS

Final S12.6 gates :

- CANONICAL INPUTS : PASS
- DETERMINISTIC +0x1000 ALICE : PASS
- STABLE STREAM PREFIX : PASS
- STABLE MAPPINGS : PASS
- DICTIONARY PRESERVED : PASS
- APPROVED METADATA PATCHES : PASS
- LZMA PRESET BOUND UNCHANGED : PASS
- PHYSICAL GAP / NEXT REGION : PASS
- EXHAUSTIVE DIFF ALLOW-LIST : PASS
- CANDIDATE SELF-DECODE : PASS

Candidate dump SHA256 :

`15299fe668390f5d14dc110b5c1f9444fad2c9be09c2ee86a245ad3c853c5298`

Candidate VIVA SHA256 :

`f2f7edad0f2e20160df81d3b4bec37d8f308f0d78aada6ba1480deac98dd4a2a`

Status :

`OFFLINE CANDIDATE - NOT FLASH APPROVED`

### Prochaine action unique

1. auditer independamment le candidat S12.6
2. valider recovery / read-back / restauration
3. seulement ensuite remplacer le payload test par le stub Thumb MP3
4. aucun write handset avant validation des gates recovery


### Backend MP3

Adresses de reference :

- `aud_player_media_construct = 0x10303BE0`
- Open `0x1028D230`
- Play `0x1028D394`
- Stop `0x1028D4C0`
- Close `0x1029D3BC`
- Pause `0x1028D378`
- Resume `0x1028D41C`
- Destroy `0x1028D0D4`

POC vise :

`<drive>:\Audios\test.mp3`

Cycle minimal :

`construct -> Open -> Play -> Stop -> Close -> Destroy`

### Synchronisation documentaire

Notion synchronise le 1 octobre 2026 :

- Projet MobiWire / Altice F2 : ajouter un lecteur MP3
- Documentation technique - Reverse engineering MP3 Altice F2 / MT6261
- last update (a prompter sur codex)
- S12.3-S12.6 - ALICE extension, LZMA preset et candidat offline

GitHub :

- repo `LordVERTON/F2-Altice-MobiWire`
- branche `s12-alice-extension`
- dernier commit S12.3 confirme avant sync : `5b717fe`


---

## Historique precedent

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
