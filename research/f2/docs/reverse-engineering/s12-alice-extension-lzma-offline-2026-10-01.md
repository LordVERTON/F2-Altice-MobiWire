# S12 - ALICE extension, preset LZMA et candidat offline

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

### S12.6 - en cours

Script :

`research/f2/scripts/patching/build_s12_6_candidate.py`

Le premier run reconstruit correctement l'ALICE et retrouve les hashes S12.3,
puis s'arrete avant toute ecriture du candidat sur un invariant trop strict :

`new_stream_prefix == old_stream`

Cause comprise :

- U exact end : `0x157BB4`
- dernier groupe start : `0x157B80`
- donnees reelles : `0x34`
- padding zero original : `0x4C`

L'extension remplace les `0x4C` octets de padding par du payload reel.

Donc il est normal que :

- le dernier groupe compresse original change
- le dernier data mapping original change
- l'ancienne sentinelle change

Invariant corrige :

- `10999` premiers mappings identiques
- dernier data mapping : changement autorise
- ancienne sentinelle : changement autorise
- `+32` nouveaux groupes
- dictionnaire identique
- stream avant dernier groupe original identique
- `new_U[:0x157BB4] == old_U`

Le premier run S12.6 n'a produit aucun candidat final.

### Prochaine action unique

Relancer `build_s12_6_candidate.py` avec l'invariant corrige.

Gate attendu :

- `EXHAUSTIVE DIFF ALLOW-LIST : PASS`
- `CANDIDATE SELF-DECODE : PASS`
- `unauthorized changed bytes = 0`

Ensuite seulement :

1. consigner SHA et diff ranges
2. audit independant du candidat
3. remplacer le payload test par le stub Thumb MP3
4. valider recovery/read-back
5. seulement ensuite envisager un test telephone

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

