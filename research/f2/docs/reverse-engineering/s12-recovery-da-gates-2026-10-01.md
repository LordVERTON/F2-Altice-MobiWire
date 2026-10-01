# S12.7-S12.9R — Recovery, live read-back et Download Agent MT6261

Date : 2026-10-01  
Firmware : `ALTICE_F2_DS_V02.1_181023_MP`  
Plateforme : MediaTek MT6261  
Branche : `s12-alice-extension`

> Statut global : **OFFLINE / RECOVERY PREPARED / FLASH NOT AUTHORIZED**

Ce document reprend les gates postérieurs au candidat S12.6 et remplace les
anciennes conclusions qui indiquaient encore que le read-back/recovery restait à
faire.

## 1. Candidat de référence

Le candidat historique S12.6 reste utile comme référence d'audit, mais il ne
doit pas être utilisé directement sur le téléphone car la partie live du dump a
évolué depuis le dump historique.

Candidat live-preserving S12.8E :

- taille : `0x400000`
- SHA256 : `47b41c572d7d9f09ac5b9562dff5977e9ea99a16b9f8e126247992b493144fd4`
- `0x000000..0x2BFFFF` : identique au candidat S12.6 audité
- `0x2C0000..0x3FFFFF` : identique au read-back live A/B
- changed bytes vs live : `62429`
- diff ranges : `792`
- aucun octet modifié à partir de `0x2C0000`

Le candidat S12.8E est le seul candidat pertinent pour cet exemplaire.

## 2. S12.7 — audit indépendant

L'audit indépendant du candidat S12.6 a reconstruit séparément les hashes
d'entrée, la patch matrix, le layout physique, le changed-byte count / diff
ranges, le décodage ALICE et les invariants manifest.

Résultat : **PASS**.

Ce gate valide la construction offline, pas le flash physique.

## 3. S12.8 — read-back live reproductible

Deux dumps série indépendants ont été réalisés via BROM READ32 :

- `s12_8_serial_readback_A.bin`
- `s12_8_serial_readback_B.bin`

SHA256 des deux :

`c571f3852f4a70d1845cc79abaa95007f8826ec858a1db1ad501c4a2a7b35ce6`

Résultats :

- A == B : PASS
- `0x000000..0x2BFFFF` live == dump historique : PASS
- divergence uniquement à partir de `0x2C0000`
- `0x300000..0x3FFFFF` est actuellement identique au dump historique
- `0x2C0000..0x2FFFFF` est appelée **live tail / mutable-looking tail**,
  sans lui attribuer de rôle NVRAM/filesystem non prouvé

Conséquence de sécurité : **ne jamais full-flasher l'ancien dump historique**
sur cet exemplaire.

## 4. S12.8E — candidat live-preserving

Le candidat S12.8E combine le préfixe firmware audité S12.6 jusqu'à `0x2BFFFF`
et la live tail A/B à partir de `0x2C0000`.

Checks :

- footprint exact S12.6 : PASS
- live tail conservée : PASS
- changed bytes : `62429`
- changed ranges : `792`
- aucun changement dans la live tail : PASS

Statut : **NOT FLASH APPROVED**.

## 5. S12.9A — préparation rollback sectorielle

Le footprint touche :

- `23` secteurs si géométrie 4 KiB ;
- `6` secteurs si géométrie 64 KiB.

Le rollback live <- candidate et le patch candidate <- live ont été vérifiés
offline pour ces hypothèses.

## 6. S12.9B-S12.9H — protocole d'écriture

Audit du mtkclient exact utilisé localement :

- MT6261 : `iot=True`, `dacode=0x6261`
- NOR-IoT read : framing spécial 32 bits
- generic `sdmmc_write_data()` : adresse/longueur 64 bits, aucune branche IoT
- `formatflash()` : pas de branche NOR/SF

Conclusion : **ne pas utiliser le write générique mtkclient 0x62 sur le F2**.

Les sources MediaTek de downloader compatibles MT6260/MT6261 montrent un
workflow NOR/SF où `D5` est utilisé avec sauvegarde des blocs inchangés, erase
séquentiel, transfert de données puis restauration des blocs inchangés.

Classification actuelle :

- erase-before-program dans la famille native MT6260/MT6261 : **FACT**
- applicabilité au DA Altice F2 exact : **STRONGLY SUPPORTED**
- generic mtkclient 0x62 : **NOT VALIDATED / DO NOT USE**

## 7. S12.9C-S12.9G — Serial Flash et géométrie

Le package service Altice exact est cohérent avec une Serial Flash :

- platform : MT6261
- `flash_type: SF`
- six JEDEC IDs autorisés :
  - `C2 25 36`
  - `EF 40 16`
  - `C2 20 16`
  - `EF 70 16`
  - `C8 60 16`
  - `C2 25 38`

Les structures binaires contiennent six records identiques de stride `0x88`.
Valeurs répétées :

- `+0x00 = 0x00400000`
- `+0x0C = 0x00001000`
- `+0x48 = 0x00300000`

Interprétation prudente :

- valeur `0x00400000` : FACT
- champ fixe `0x1000` : FACT
- interprétation `0x1000 = erase/block size` : STRONGLY SUPPORTED
- capacité physique exacte d'une puce particulière : à ne pas déduire de ce
  tableau seul sans lire l'ID matériel

## 8. S12.9I-S12.9O — correction de la piste ROM

Le scan Capstone initial avait interprété des données comme du code.
La zone `ROM+0x3DBxx` est en réalité une table de records `0x0C`, avec des
targets `0xF03Axxxx` et des valeurs halfword.

Une table plus large de `220` records a été identifiée :

- range : `ROM+0x3DACC..0x3E51B`
- values : 16 bits
- targets : espace `0xF03Axxxx`

Les sources build donor contiennent les hooks ROMSA/rompatch mais pas les blobs
propriétaires eux-mêmes.

Correction importante : le composant `PKG/ROM` est mappé côté firmware à
`0x1000A000`, donc les targets `0xF03Axxxx` appartiennent à un autre espace
d'adressage. Cette table n'est plus utilisée comme piste principale du
protocole DA.

## 9. S12.9Q — recovery-sector gate

Inputs :

- live A/B SHA256 :
  `c571f3852f4a70d1845cc79abaa95007f8826ec858a1db1ad501c4a2a7b35ce6`
- candidate SHA256 :
  `47b41c572d7d9f09ac5b9562dff5977e9ea99a16b9f8e126247992b493144fd4`

Footprint :

- changed bytes : `62429`
- changed sectors 4 KiB : `23`
- first change : `0x00B919`
- last change : `0x296447`

Analyse NOR bit à bit :

- transitions `0 -> 1` : **97412**
- transitions `1 -> 0` : **120975**

Conclusion : **un erase est réellement nécessaire** pour produire le candidat.

Gap sûr :

- `0x297000..0x2BFFFF`
- `41` secteurs 4 KiB entièrement FF dans live A, live B et candidat

Secteur sacrificiel retenu : `0x2A0000`.

Envelope offline :

- erase 4 KiB : PASS
- erase 64 KiB : PASS
- erase 128 KiB : PASS
- erase 256 KiB aligné `0x280000..0x2BFFFF` : **FAIL / UNSAFE**

## 10. S12.9R — vrai Download Agent MT6261 trouvé

Scan offline :

- fichiers inspectés : `1287`
- fichiers contenant DADA : `8`
- entrées plausibles : `163`

Un unique candidat exact MT6261 est présent :

`mtkclient/Loader/MTK_AllInOne_DA_iot.bin`

Entrée DADA :

- offset : `0x2718`
- hw_code : `0x6261`
- hw_sub_code : `0x8000`
- hw_version : `0xCA00`
- sw_version : `0x0000`
- entry_region_index : `2`
- entry_region_count : `6`

Régions pertinentes :

| Région | Rôle | File offset | Taille | Load address | Sig |
|---|---|---:|---:|---:|---:|
| 2 | DA1 | `0x5A0FE4` | `0x718` | `0x70007000` | `0x100` |
| 3 | DA2 | `0x5A16FC` | `0x1E5E0` | `0x10020000` | `0x100` |
| 4 | DA3 / chip data | `0x5BFCDC` | `0x2520` | `0xF0000000` | `0` |
| 5 | aux data | `0x5C21FC` | `0x17F8` | `0xF1000000` | `0` |

Cross-check du code mtkclient :

- pour MT6261 IoT, `stage1 = entry_region_index`
- région stage1 = DA1
- région stage1+1 = DA2
- région stage1+2 = DA3/chip-data
- DA1 et DA2 sont envoyés avant le `jump_da(DA1)`
- DA3 est ensuite utilisé pendant l'initialisation/configuration IoT
- `read_flash_info_iot()` récupère les informations flash après sync

Le petit `mt6261_payload.bin` :

- taille : `0x250`
- SHA256 :
  `cb3b04e1fbce58cf12adf61f78558ae5879d693f468f2681bfc948be5f25b06e`

Il est auxiliaire et **ne doit pas être confondu avec le DA complet**.

## 11. Classification actuelle

### FACT

- ALICE repack et extension +0x1000 validés offline.
- candidat S12.8E live-preserving construit et audité.
- deux readbacks live A/B identiques.
- live tail différente du dump historique à partir de `0x2C0000`.
- footprint candidat : 62429 bytes / 792 ranges.
- le candidat contient des transitions NOR 0->1 et nécessite un erase.
- secteur `0x2A0000` entièrement FF dans live A/B/candidat.
- un conteneur DA local possède une entrée MT6261 à deux stages valide.
- structure DA1/DA2/DA3 cohérente avec le chemin IoT mtkclient.

### STRONGLY SUPPORTED

- Serial Flash erase/block de 4 KiB.
- le DA IoT MT6261 local est compatible avec le F2.
- workflow D5 natif : save unchanged -> erase -> program -> restore.

### UNKNOWN / NOT YET PROVEN

- JEDEC exact réellement soudé sur ce handset.
- compatibilité byte-exacte du DA local avec le service package Altice.
- upload/jump DA réussi sur ce handset.
- write puis recovery réel sur un secteur sacrificiel.
- erase granularity physique réelle au moment du test.

## 12. Gate courant

**FLASH AUTHORIZED: NO**

Avant toute écriture firmware :

1. extraire et auditer DA1/DA2/DA3 offline ;
2. vérifier la couverture des six JEDEC IDs Altice dans le DA/chip-data ;
3. seulement ensuite envisager un upload DA + identification flash strictement
   read-only ;
4. ne jamais envoyer `D5`, format ou erase durant ce premier test ;
5. seulement après un handshake read-only réussi, concevoir un test sacrificiel
   write -> readback -> restore/erase -> readback sur `0x2A0000` ;
6. le flash du candidat S12.8E reste interdit tant que ce cycle recovery réel
   n'a pas été démontré.

## 13. Prochaine étape : S12.9S

Audit offline du DA MT6261 exact trouvé localement :

- extraire DA1 / DA2 / DA3 ;
- calculer hashes payload/signatures ;
- rechercher les six JEDEC IDs du package Altice ;
- rechercher les primitives / dispatch D5-D6 ;
- aucun accès device ;
- aucun upload DA ;
- aucun write/erase.
