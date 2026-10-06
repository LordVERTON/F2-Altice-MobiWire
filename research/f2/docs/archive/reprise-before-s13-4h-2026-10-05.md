# Reprise - Altice F2 / MobiWire NIKITI

<!-- CURRENT-S13.3A-2026-10-02 -->

## S13 checkpoint â€” 2 October 2026 â€” native Audio Player one-sector POC

Current state:

- S13.1 dispatcher / resolver analysis: **CLOSED**
- S13.2A logical hook: **PASS**
- S13.2B physical repack / sector manifest: **PASS**
- S13.2C target-sector D6 baseline rehearsal: **PASS**
- S13.2C.1 local post-crash validation: **PASS**
- S13.3A proven S12.10B7 harness import / audit: **PASS**
- target firmware sector has **not** been modified yet

Do not redo Image Viewer â†” Audio Player comparison, frontend discovery,
registration discovery, or dispatcher discovery.

### Confirmed native chain

```text
0x8928
  -> F0316D74 / F0316D75
  -> 0x1033D841
  -> 0x1033D840      registration stub
  -> 0x1033E815      selected Thumb init entry
  -> 0x1033F83C      Audio Player init
```

Dispatcher framework already closed:

- `1034C7E4`: dynamic lookup + static fallback
- `10336788`: resolve + invoke callback
- `10336F84`: installs `10336789` into `F00EF124`
- `102D9DC8`: ctx/ID bridge to global dispatcher
- `10366100/22/36`: ID-family mapping/configuration, not launch

### S13.2A â€” logical hook

```text
hook function  0x1035578C
hook literal   0x10355888
U offset       0x106C88
old pointer    F0301C8D
new pointer    1033E815
```

Canonical decompressed ALICE:

- size `0x157BB4`
- SHA256 `7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea`

S13.2A candidate:

- SHA256 `b12f67211e1a55263af6a75e65b7caa471c15df381ae39757f179dda7a84332d`
- logical diff: exactly 4 bytes

### S13.2B â€” physical repack

- original ALICE repack byte-perfect: PASS
- patched compressed ALICE size: `0x113E2C`, unchanged
- patched compressed ALICE SHA256:
  `9ed53778084cb1dd05609d47688e6c965f8c0f0874f6d02ac2cc64b2062f35eb`
- VIVA length: `0x248EBC`, unchanged
- VIVA end: `0x2950C8`, unchanged
- candidate 4 MiB SHA256:
  `9099c7bbbbd88c1dcc718fdb12de83af9852eb8f7d8f3f9aa3daba1420c28216`
- physical diff: 37 bytes
- one diff range: `0x249AEF..0x249B13`
- one changed 4 KiB sector: `0x249000..0x249FFF`
- changed bytes `>= 0x2C0000`: 0

Target sector:

```text
BEFORE dc8cc6b5be54d1554d71d60539f10a8077a375a3d7ddf92efe6149610ecffb1b
AFTER  29a21401b84442554dc051edd16ec561bbd842e01e048344e30ca547f78bb7f9
```

NOR transitions:

- 0 -> 1 bits: 68
- 1 -> 0 bits: 66
- erase required: yes

### S13.2C / S13.2C.1 â€” real-device D6 pre-write gate

Two fresh native D6 reads of `0x249000..0x249FFF` both matched the BEFORE
sector exactly.

Rollback saved:

`research/f2/work/repro/s13_2c_target_sector_d6_gate/rollback_sector_249000_fresh.bin`

Rollback SHA256:

`dc8cc6b5be54d1554d71d60539f10a8077a375a3d7ddf92efe6149610ecffb1b`

No D3, D5, erase, or firmware write occurred.

The process later exited with Windows `0xC0000005` during native USB teardown,
after PASS and artifact creation. S13.2C.1 validated A == B == rollback,
4096-byte sizes, exact hashes, and the JSON state. This remains a PASS.

### S13.3A â€” proven write harness reference: PASS

Source:

```text
C:\Users\verto\mtkclient\research\f2\scripts\hardware\s12_10b7_sacrificial_gate.py
```

Committed repo reference:

```text
research/f2/scripts/hardware/reference/s12_10b7_sacrificial_gate_v4_reference.py
```

Source/copy SHA256:

`255a00f49b99c72871cd3a9ca9e66f4d5284590d9844ff58c3c7c5796e9616eb`

Commit containing the reference:

`5c7f83bbf01fa425a1a768dd5c49dbdc14577414`

The audit confirms these proven primitives:

- `d6_read_4k_native()`
- `d6_read_sector_range()`
- `d3_set_memblock()`
- `d5_write_until_processinfo()`
- Sequential Erase
- exactly one 4 KiB D5 data frame
- additive 16-bit frame checksum
- recovery ACK
- ProcessInfo ACK
- deliberate stop before final image checksum verifier
- mutation lock requiring `--execute` plus exact confirmation token
- no generic `writeflash()/0x62`

The proven `mutate()` pattern is already:

```text
fresh D6 pre-read
 -> exact expected-before check
 -> guard check
 -> D3
 -> D5
 -> recovery / ProcessInfo
 -> close DA session
```

S13.3A was local-only:

- harness executed: NO
- phone accessed: NO
- D3: NO
- D5: NO
- erase: NO
- flash modified: NO

### Exact restart point â€” S13.3B

Build a dedicated one-sector firmware harness derived from the proven v4
reference.

Mandatory invariants:

1. hardcoded target `0x249000..0x249FFF`
2. hardcoded BEFORE SHA256
   `dc8cc6b5be54d1554d71d60539f10a8077a375a3d7ddf92efe6149610ecffb1b`
3. hardcoded AFTER SHA256
   `29a21401b84442554dc051edd16ec561bbd842e01e048344e30ca547f78bb7f9`
4. exact 4096-byte AFTER payload only
5. fresh D6 before mutation in the same DA session
6. save another fresh rollback before D3
7. D3 GFH fixed to `0x0108`
8. D5 Sequential Erase/write/recovery/ProcessInfo
9. stop before final checksum verifier
10. new DA session for AFTER D6 verification
11. new confirmation token specific to firmware sector `0x249000`
12. no code path that can select another target address

Until the S13.3B local safety audit passes, do not execute a firmware write.

Permanent rules:

- never generic mtkclient `writeflash()/0x62`
- never whole-image or SAV flash
- never write `>= 0x2C0000`
- never target another sector for this POC
- preserve rollback until full functional validation

Detailed note:
`docs/reverse-engineering/s13-native-audio-launch-poc-2026-10-02.md`


<!-- CURRENT-S12.10B7-2026-10-02 -->

## État courant — 2 octobre 2026

### S12.10B7 — hardware write / erase / recovery gate : PASS

Le gate sacrificiel matériel est terminé sur le téléphone réel.

Matériel :

- MT6261 / HW code `0x6261`
- NOR 4 MiB
- device code `00EF/0070/0016`
- loader SHA256 `b14620c0131a269279e89830f661e39dc4f5a773d700ce56561c6f9e8e84dc8a`

Secteur sacrificiel :

`0x002A0000..0x002A0FFF`

Résultats :

- D6 READ : HARDWARE PASS
- D5 WRITE FF→AA : HARDWARE PASS
- D5 erase+write AA→55 : HARDWARE PASS
- recovery / ProcessInfo : HARDWARE PASS
- restore → FF : HARDWARE PASS
- guard `0x280000..0x2BFFFF` : byte-identical hors cible
- S12.10B7 SACRIFICIAL GATE : PASS

Hashes :

- FF : `f47a8ec3e9aff2318d896942282ad4fe37d6391c82914f54a5da8a37de1300c6`
- AA : `c622005493c4cb75f3e08eda4cc0bfe172e2c5eeca661ec4908c5490fc3d6994`
- 55 : `0561079e4fe3390bc1d8bb706edb7d80243eeca7ddf876cefbaa8c1684db80c3`
- stable guard : `caac124c9e376fdf13f854555937eff52ae28f4872f71d3216c6b773693de3e4`

Le téléphone a été restauré à l'état FF initial.

Détail :

`docs/reverse-engineering/s12-10b7-hardware-write-gate-2026-10-02.md`

### Baselines physiques déjà disponibles

Un nouveau dump complet 4 MiB n'est PAS requis pour commencer S13.

Baseline historique :

- dump2 == dump3
- taille `0x400000`
- SHA256 `2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922`

Readbacks live ultérieurs :

- deux readbacks complets A/B
- cycles batterie indépendants
- byte-identical
- SHA256 `c571f3852f4a70d1845cc79abaa95007f8826ec858a1db1ad501c4a2a7b35ce6`

Candidat S12.8E live-preserving :

`47b41c572d7d9f09ac5b9562dff5977e9ea99a16b9f8e126247992b493144fd4`

Règle permanente :

aucune modification à partir de `0x2C0000`.

### Étape active : S13

Ne pas refaire l'analyse « frontend Audio Player présent ou absent ».

Le frontend natif est déjà confirmé.

Registration :

`0x8928 → 0x1033D841`

Chaîne applicative :

`0x1033D840 → 0x1033E815 → 0x1033F83C`

Playlist native :

`@Playlists\audio_play_list.sal`

Contrôle positif Image Viewer :

`0x8313 / 0x8321 → F02F3F85`

Objectif S13 :

identifier le plus petit mécanisme permettant d'exposer / lancer l'Audio Player
natif déjà compilé.

Avant toute écriture firmware réelle :

1. construire le candidat reproductiblement ;
2. calculer exactement les secteurs 4 KiB modifiés ;
3. refuser toute cible `>= 0x2C0000` ;
4. relire fraîchement chaque secteur cible en D6 ;
5. exiger son égalité avec les octets originaux attendus ;
6. sauvegarder ces secteurs comme rollback ;
7. écrire uniquement via D3+D5 ;
8. power-cycle ;
9. relire chaque secteur en D6 et comparer au candidat.

Interdictions :

- pas de generic mtkclient `writeflash()` / `0x62`
- pas de flash complet 4 MiB
- pas de SAV complet
- aucune écriture `>= 0x2C0000`


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

# Reprise â€” Altice F2 / MobiWire NIKITI

Mis Ã  jour le 29 septembre 2026. **Unique Ã©tat courant**, Ã  lire avant toute
reprise avec AGENTS.md. Firmware ALTICE_F2_DS_V02.1_181023_MP, MT6261.
Objectif : lecture MP3 SD avec backend natif, puis frontend minimal et File Manager.
Phase OFFLINE : aucun flash, Ã©criture NVRAM, changement de pilote ou accÃ¨s tÃ©lÃ©phone.

## Ã‰tat validÃ©

- Dump2 canonique et dump3 identiques, 0x400000 octets, SHA256
  2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922.
- ALICE base runtime 0x1024EC00; header compressÃ© 0x101812C4 distinct.
- VIVA du package identique aux octets du dump2; hashes ALICE/ZIMAGE/BOOT vÃ©rifiÃ©s.
- S01/S02 : dÃ©codeur MP3, DAF_Open, reconnaissance MP3=5 et DPMGR 3â†’0x010C.
- ABI construct/Open/Play recoupÃ©e; WAV construit un objet mÃ©dia, VM est un stub.
- Play 0x1035FB00 appelle DPMGR puis AudioDrain 0xF02AE5F0. Sortie physique inconnue.
- Switch8 0x70008C68 absent : sÃ©lection des cas et retours publics restent infÃ©rÃ©s.
- S09.7 : construction numÃ©rique du chemin et provenance du drive Ã©tablies.
  Format ASCII racine Ã  0xF02B3D28, suffixe Audios UTF-16 Ã  0xF02B3D30;
  formatter 0xF022DC34, concatÃ©nation 0xF02E2A08.
- Drive courant RAM 0xF00AD8A3, prÃ©fÃ©rence 0xF00AD89D; getter 0xF02B8FE8.
  Il utilise la prÃ©fÃ©rence disponible sinon native_get_drive(8,2,0x18).
  Table 0xF00EF090, initialiseur 0x10300DA4, indexâ†’lettre 0x102F1084.
- Labels Phone/Memory Card associÃ©s aux catÃ©gories/index : INFÃ‰RÃ‰S SDK.
  Aucune lettre SD effective observÃ©e ou hardcodÃ©e.
- Lecture appareil, UI utilisable, hook, cave et recovery d'Ã©criture non dÃ©montrÃ©s.

## Ã‰tape active et prochaine action unique

S09.7 documentÃ©e; POC_SPEC crÃ©Ã© comme brouillon, **non prÃªt pour injection**.
Tracer la construction DAF avec callback NULL : 0x10358254 â†’ veneer
0x102FC1B4 â†’ 0xF02E1B00 â†’ 0xF0297DC4. Comparer les champs construits aux
accÃ¨s MHdl.Play 0x1035FB00, puis suivre leur fermeture/destruction.

Pourquoi : Open accepte cb_fct=NULL, mais DAF_Open choisit alors une autre
construction que le chemin composant avec callback. La lecture n'est pas
prouvÃ©e pour ce POC. Ne pas remplacer cette incertitude par une hypothÃ¨se SDK.
Conserver player/cfg/path jusqu'Ã  quiescence Ã©tablie; Stop dÃ©rÃ©fÃ©rence MHdl,
Destroy n'appelle pas implicitement Close. Aucun patch Ã  prÃ©parer maintenant.

## DerniÃ¨re action et traitements actifs

Audits chemins et ABI terminÃ©s : 19 et 31 ancrages d'octets; 9 callbacks;
12 suffixes; 7 cas switch interprÃ©tÃ©s. Rapports sous alice_reports.
Aucune commande longue, aucun Ghidra ni accÃ¨s tÃ©lÃ©phone lancÃ© pour S09.7.
Les contrÃ´les finaux et leur rÃ©sultat sont consignÃ©s dans le journal.

## Documents Ã  lire

- [Rapport S09, preuves et limites](docs/reverse-engineering/s09-file-path-and-minimal-player-2026-09-29.md).
- [POC_SPEC](docs/reverse-engineering/POC_SPEC.md).
- [Journal](docs/JOURNAL.md), [roadmap](docs/roadmap.md), [preuves](EVIDENCE.md).
- [S02](docs/reverse-engineering/daf-open-dispatch-2026-09-29.md) et
  [S01](docs/reverse-engineering/mp3-decoder-verdict-2026-09-29.md).

## Reproduction et continuitÃ©

Python : .venv/Scripts/python.exe. Scripts sous research/f2/scripts/analysis :
analyze_audio_paths.py, audit_minimal_player_abi.py, audit_daf_open.py.
Sorties locales ignorÃ©es Git : work/ghidra/alice_reports/audio_path_audit.json,
audio_path_evidence.txt, audio_drive_contexts.txt, minimal_player_abi.json,
minimal_player_abi_disasm.txt. Les preuves durables sont rÃ©sumÃ©es dans S09.

Projet Ghidra existant : work/ghidra/Altice_MP3_Runtime_20260929.
EntrÃ©es : work/extracted/altice_alice/alice-py.bin et altice_platform/.
Donor : work/donor_repos/MT2503-2, rÃ©fÃ©rence de nommage seulement.
VÃ©rifier les artefacts et processus avant reprise; mettre ce checkpoint Ã  jour
avant travail long, aprÃ¨s preuve nouvelle et en fin d'Ã©tape. DÃ©tails sÃ©parÃ©s,
progression au journal; suivre docs/ORGANISATION.md.

Les pages Notion ont Ã©tÃ© synchronisÃ©es avant cette phase et ne reflÃ¨tent pas
encore S09.7; aucune Ã©criture Notion effectuÃ©e pendant cette analyse.
Le checkpoint prÃ©cÃ©dent est conservÃ© dans docs/archive/pre-s09-final-2026-09-29/.
