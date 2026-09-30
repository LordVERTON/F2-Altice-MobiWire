# S12.2 — Audit local ALICE Altice / MobiWire F2 MT6261

Date : 2026-10-01. Racine : `C:/Users/verto/mtkclient`.

## 1. Executive summary

**FACT — Le premier aller-retour demandé a réussi entièrement en mémoire.** À partir du décompressé original, traduction BL/BLX, réencodage avec le dictionnaire original, reconstruction du stream et de la mapping table : le conteneur obtenu est **identique octet pour octet à l'ALICE_2 originale**, SHA-256 `8a06970667c6af37f7a6b1fb28dde0622e396fccd5c2a0b450bd795a0257988f`. Les fonctions de `unalice.py`, exécutées avec des buffers RAM et sans leur programme principal, restituent ensuite exactement `alice-py.bin`, taille `0x157BB4`, SHA-256 `7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea`. Reproducteur intégral en section 11. Aucun fichier binaire de repack n'a été créé.

**FACT — Un encodeur MediaTek de distribution donor est présent :** `research/f2/work/donor_repos/MT2503-2/tools/ALICE.exe`, 277 504 octets, SHA-256 `27071e163bd93f915bcd2f72c566fcb2f747fe8f4a1aaf2db989c688d0edd5a3`. Son aide embarquée cite explicitement MT6261, `-cBase`, `-dBase`, `-cBlock`, `-iDict` et `-oDict`. Il n'a pas été exécuté. Sa provenance locale est établie, pas son authenticité cryptographique ni sa réussite sur Altice. Preuves : binaire offsets `0x2C21C`, `0x2C319`, `0x2C419`, `0x2C560`; `tools/aliceProcess.pm:119` dans le donor.

**FACT — Capacité physique avant collision à `0x2C0000` :** `0x13ED64` = **1 305 956 octets** pour le conteneur ALICE_2 complet, header + stream + mapping + dictionnaire. Taille actuelle `0x113E2C`; marge `0x2AF38` = **175 928 octets**, soit **171,805 KiB** et non 176 KiB au sens binaire. Les FF sont hors du VIVA actuel, dont la longueur GFH se termine à `0x2950C8`. Ce plafond physique ne prouve pas à lui seul l'acceptation runtime d'une image agrandie. Preuve : dump canonique offsets `0x4C22C`, `0x18129C`, `[0x2950C8,0x2C0000)`.

**FACT — `0x101812C4` et `0x1024EC00` sont deux valeurs légitimes.** La première est l'adresse flash mappée du début du stream compressé, après le header de 40 octets. La seconde est la base de la fenêtre d'exécution décompressée configurée par la ROM. La traduction BL/BLX travaille sur les positions de demi-mots dans l'image, pas en ajoutant leur différence. Preuves : ALICE_2 `+8`; ROM/dump `0xB910`, `0xEC50`, `0xECC4`, `0xFBA8`; décodeur `unalice.py:228`, `:144`; loader à `0x1000F340`.

**STRONGLY SUPPORTED — Agrandir proprement est réalisable au niveau du format, mais pas encore validé sur toute la chaîne de boot.** Les inconnues prioritaires sont l'extension de la fenêtre runtime et surtout le preset LZMA de ZIMAGE/BOOT_ZIMAGE : ils utilisent l'ALICE décompressée comme dictionnaire. Deux constantes de fin `0x103A67B4` existent en plus des quatre tailles explicites. Il serait incorrect de modifier tous les mots trouvés sans analyser leur consommateur. Preuves : dump `0xC18C`, `0x110DC`; code à `0x1000C11A`; donor `hal/system/compression/src/code_decompression_hal.c:355`.

### Portée et méthode

Lecture préalable de `research/f2/REPRISE.md`, puis `research/f2/AGENTS.md`, et de `docs/ORGANISATION.md`. L'interdiction explicite de modification prime sur leur demande de mise à jour : checkpoint et journal laissés intacts. **Seul ce rapport est écrit**, conformément à la demande finale. Aucun flash, port série, commande MTKClient, exécution donor, lancement Ghidra ou modification de firmware.

Inventaire récursif initial : **22 003 fichiers**, 1 939 206 352 octets, incluant fichiers ignorés/cachés et environnement Python. Recherche de noms et de contenu dans le dépôt, sources/scripts/configurations, rapports existants, paquets et historiques locaux; analyse binaire et désassemblage Capstone en mémoire. L'audit est exhaustif sur les candidats identifiés, pas une preuve mathématique d'absence de code caché dans chaque binaire arbitraire.

Trois dépôts Git : racine MTKClient, `work/vendor-metadata/mtk_fw_tools`, `work/donor_repos/MT2503-2`. Le dernier est **shallow, sparse et partial (`blob:none`)** : 27 947 chemins dans son arbre, mais seulement 5 476 objets Git résidents. Une commande `ls-tree --long` a tenté implicitement de charger un objet manquant depuis le promisor remote et a échoué sur la connexion; aucun contenu n'a été récupéré. La suite a utilisé l'inventaire des objets résidents et `GIT_NO_LAZY_FETCH=1`. Aucun fetch explicite ni checkout.

Les termes du rapport : **FACT** = octets/code/comparaison directement observés; **STRONGLY SUPPORTED** = recoupement solide mais preuve runtime incomplète; **HYPOTHESIS** = piste; **UNKNOWN** = non établi. Un commentaire source donor n'est jamais assimilé à une preuve d'exécution Altice.

### Notation des références

Tous les chemins sont relatifs à la racine. Pour alléger les tables :

- `D` = `research/f2/data/dumps/mobiwire_dump_2.bin`.
- `A` = `research/f2/work/extracted/altice_alice/altice_ALICE_2.bin`.
- `U` = `research/f2/work/extracted/altice_alice/alice-py.bin`.
- `T` = `research/f2/work/extracted/altice_alice/alice-translated-py.bin`.
- `SDK/` = `research/f2/work/donor_repos/MT2503-2/`.
- `FW/` = `research/f2/work/vendor-metadata/mtk_fw_tools/`.
- `PY/` = `research/f2/tools/unalice/`.
- `PKG/` = `research/f2/data/firmware-packages/altice-service/altice_service_package/DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00/`.

Ainsi `SDK/tools/aliceProcess.pm:119` désigne un fichier et une ligne précis. Pour le code ROM, adresse CPU = `0x10000000 + offset D`; offset dans `PKG/ROM` = `offset D - 0xA000`. Les adresses x86 désignent l'image PE de `SDK/tools/ALICE.exe`, image base `0x400000`; dans sa section `.text`, offset fichier = VA - `0x400C00`.

## 2. Carte complète de la chaîne ALICE

```text
U : code/données décompressés, base d'exécution 0x1024EC00
  -> traduction des paires Thumb BL/BLX, par position dans l'image
T : représentation intermédiaire, mêmes longueur et positions, non exécutable telle quelle
  -> sélection de codes du dictionnaire, ou échappement raw 111 + demi-mot
  -> bitpacking MSB-first; alignement octet par 32 demi-mots
  -> mapping tous les 64 demi-mots + entrée terminale
A : header 0x28 | stream | mapping | dictionnaire
  -> dernier composant VIVA; adresses physiques mappées sous 0x10000000
VIVA : GFH FILE_INFO | VIVAInfo | ZIMAGE | BOOT_ZIMAGE | DCM | A
  -> ROM configure le moteur ALICE à 0xA0520000 et sa fenêtre runtime
  -> accès au code via 0x1024EC00, pas via le début physique du stream

Autre dépendance : U -> preset de compression/décompression LZMA type 3
                        de ZIMAGE et BOOT_ZIMAGE.
```

**FACT :** le loader ne se résume pas à « copier 1,4 MiB en RAM ». Il écrit les registres `0xA0520000` : base/fin de fenêtre, mapping, ranges, dictionnaire, configuration et remapping. Voir D/code `0x1000F3FE`, `0x1000F458`, `0x1000F54E`, `0x1000F586`, `0x1000F59C`, pool D `0xF644`. **STRONGLY SUPPORTED :** décompression matérielle à la demande / fenêtre ALICE, compatible avec le scatter donor en `OVERLAY`; fonctionnement matériel exact au-delà des registres non observé sur téléphone.

### Quatre sens différents de « base / translation »

| Concept | Valeur Altice | Sens et preuve |
|---|---:|---|
| Début physique du conteneur | `D+0x18129C` | Magic `ALICE_2\0`; VIVAInfo `D+0x4C254 = 0x1018129C` |
| `-cBase` / adresse mappée du header | `0x1018129C` | CLI « start address of compressed binary », `ALICE.exe+0x2C3B9`; wrapper `SDK/tools/aliceProcess.pm:95`, `:119` |
| Base du stream dans le format | `0x101812C4` | `A+8`; exactement `0x10000000 + 0x18129C + 0x28` |
| Base de l'image traduite T | pas de nouvelle base runtime enregistrée dans T | T est un fichier brut de demi-mots transformés; `PY/unalice.py:301`, `:309`. L'assigner à `0x101812C4` dans Ghidra était une convention historique d'analyse |
| Destination / fenêtre runtime | `0x1024EC00` | constantes ROM; configuration `0x1000EBE4` / `0x1000EC58`, puis `0x1000F340` |
| Remapping des banques | header `+0x22 = 9`, `+0x23 = 1` | writer x86 `0x411D1E` extrait les bits 31..28 des champs source/destination; ce sont des banques, pas les deux bases complètes |
| Rebasage des anciens rapports Ghidra | `+0xCD93C` | différence entre deux bases d'analyse; à appliquer seulement aux adresses ALICE historiques, pas aux mots du firmware |
| Transformation BL/BLX | dépend de l'index du demi-mot | `PY/alice.py:55`, `PY/unalice.py:144`; ni relocation générale ni addition de `0xCD93C` |

`-dBase` est bien une option acceptée par l'EXE, mais son aide n'établit pas à elle seule tout son effet interne. Le format observé ne contient pas de champ 32 bits stockant `0x1024EC00`; la ROM configure cette destination séparément. **Ne pas remplacer `A+8` par cette destination.**

## 3. ALICE.exe / repacker inventory

### Candidats utilisables ou proches

| Chemin | Rôle; entrée -> sortie; CLI | Confiance |
|---|---|---|
| `SDK/tools/ALICE.exe` | Encodeur C++ compilé : image brute de demi-mots -> ALICE_1/2 selon profil. `-chip MT6261 -iBin INPUT -oBin OUTPUT -cBase 0x1018129C -dBase 0x1024EC00 -cBlock 64`; options `-iDict`, `-oDict`, `-statistics`, `-debugLevel` | FACT pour présence, CLI, writer ALICE_1/2; fonctionnement Altice de cet EXE UNKNOWN, non exécuté |
| `PY/alice.py` et `FW/alice.py` | Prototype Python : `python alice.py INPUT [magic.bin before_encode.bin]`; produit `translated-py.bin`, `magic-py.bin`, `before_encode-py.bin`, puis **stream nu** `alice-py` | FACT : pas un conteneur complet; fichiers identiques |
| `PY/unalice.py` et `FW/unalice.py` | `python unalice.py [-t] ALICE`; conteneur -> `alice-translated-py.bin` et `alice-py.bin`; `-t` désactive l'inverse BL/BLX | FACT pour lecture du format; EOF heuristique à traiter |
| `SDK/tools/aliceProcess.pm` | Wrapper Perl du build; `Process(binaryFolder, availableStartAddress, startAddressRef, sizeRef)` sauvegarde ALICE brut en ALICE.bin, encode et met à jour adresse/taille | FACT, lignes 85–127; ce n'est pas le source de l'encodeur |
| Réencodage en mémoire de la section 11 | U + codebook A -> A; utilisation de la transformation du prototype mais writer stream/mapping minimal indépendant | FACT : reproduction binaire exacte de l'original pendant cet audit; pas de CLI/script installé |
| `SDK/tools/7lzma.exe` | Repack des composants **LZMA**, pas ALICE_2. `etp input output preset` / `dtp input output preset` pour type 3; `et` / `dt` sans preset | FACT, `SDK/tools/zImageProcess.pm:285`, `:293`; extraction `scripts/analysis/extract_viva_components.py:38` |
| `SDK/tools/GFH_Head.exe` | Outil auxiliaire GFH; ne remplace pas un encodeur ALICE. Entrée/sortie détaillées et CLI non établies ici | Présence FACT, pertinence auxiliaire; pas exécuté |

L'ancienne commande commentée `-base ... -statistics ... -debugLevel 3` dans `SDK/tools/aliceProcess.pm:183` appartient à une autre interface historique. La commande **active** ligne 119 et les chaînes de l'EXE présent utilisent `-cBase/-dBase`. Ne pas reprendre `-base` sans preuve qu'il est accepté.

| Fichier binaire | Taille | SHA-256 |
|---|---:|---|
| `SDK/tools/ALICE.exe` | `0x43C00` | `27071e163bd93f915bcd2f72c566fcb2f747fe8f4a1aaf2db989c688d0edd5a3` |
| `SDK/tools/7lzma.exe` | 89 088 | `092190b3504bd433019a8c211f16b4f8c01817c0464c9d178075470f228aabd8` |
| `SDK/tools/GFH_Head.exe` | 30 720 | `71e2f1a6f235c7cbbe402afc0dcde3c3dd7648611fb655d6150d85edd6b0dc93` |

Hashes des scripts checkout : `PY/alice.py`, 9 983 octets, `562790005328e416cbc45a6fd83421902b47dfb330286a690373103452e381c2`; `PY/unalice.py`, 13 032 octets, `1f0cef389bb63302970437d056f24ccb255c0d0b58d5baeabc731bc68daf123f`. Les blobs Git ont des tailles différentes à cause de LF/CRLF; identité confirmée après normalisation des fins de ligne.

### Build, scatter, sources originales et fichiers non checkout

| Preuve | Apport |
|---|---|
| `SDK/tools/vivaProcess.pl:66`, `:89`, `:186`, `:199` | Enchaîne les traitements, réécrit VIVAInfo, padding global à 4 octets |
| `SDK/tools/vivaHelper.pm:479`, `:543` | Lit/écrit les cinq bases VIVA; parsing FILE_INFO lignes 299–336 |
| `SDK/tools/vivaConfig.pl:112`, `:400`, `:432`, `:624`, `:736` | Allocation du budget compressé, `CONFIG_ALICE_MAX_COMPRESSED_SIZE`, taille de région, alignement de calcul 256 |
| `SDK/tools/auto_adjust_mem.pl:259` | Recaclul des budgets de configuration; pas une garantie pour le linker Altice absent |
| `SDK/tools/vivaPrelink.pl:126`, `:136` | Prélink et listes d'objets ALICE |
| `SDK/tools/GLBOptionSwtichRef/GXQ03D_M2M_11C_GPRS.mak:5426` | `ALICE_SUPPORT = TRUE` |
| `SDK@b25f121:make/GXQ03D_M2M_11C_GPRS.mak:5471` | Même option; blob `1297bed3458a1b1916db328244d74d902b99c079` présent, fichier non checkout. Alias `..._JM10.mak` identique |
| `SDK/custom/system/GXQ03D_M2M_11C_BB/scatGXQ03D_M2M_11C.txt:136`, `:587`, `:752` | Objets `alice.obj`, `alice_internal.obj`, zone `EXTSRAM_ALICE` de dictionnaire, région ALICE OVERLAY alignée 1024 |
| `SDK/custom/system/Template/scat_config/FeatureBased/ObjListGen/AliceForbidList.csv:3` | Associe `alice.obj` et `alice_internal.obj` à `sys_sec.lib`; sources originales correspondantes non présentes |
| `SDK/tools/CAT/INI/VIVA.ini:6` | Dépendance de build `tools/ALICE.exe` |
| `SDK/tools/DebuggingSuite/Misc/Template.cmm:64` | Chargement debug et comparaison de dictionnaire; utilise une formule historique `+0x24`, donc pas un writer Altice sûr |

**Sources originales effectivement présentes :** `code_decompression.c` orchestre ZIMAGE (`SDK/init/src/code_decompression.c:215`); `code_decompression_hal.c` décrit ZIMAGEPartition et LZMA (`:176`, `:221`, `:355`); `code_decompression.h:69` expose l'API ZIMAGE; `viva.h:80` et `viva.c:101` définissent les bases. **Ces fichiers ne sont pas le décodeur bitstream ALICE.**

**Pas de source C/C++ original de l'encodeur ALICE retrouvé.** L'EXE référence `source/Dictionary.cpp`, `DictionaryMaker.cpp`, `AliceDictionaryReader.cpp`, `AliceDictionaryWriter.cpp`, `AliceHeaderWriter.cpp`, `PostProcessor.cpp`, mais ces sources ne sont pas dans l'arbre local inspecté. Voir chaînes EXE `+0x2CAE0`, `+0x2D438`, `+0x2D7E0`, `+0x2D9E4`, `+0x2DACC`.

**Loader runtime disponible sous forme machine dans D**, analysé à `0x1000EBE4`, `0x1000EC58`, `0x1000F290`, `0x1000F340`, `0x100104F8`. Pas de source original ALICE complet dans les blobs résidents. Le matériel réalise le décodage; la présence d'un loader ne signifie pas que son implémentation de décompression matérielle soit du code C disponible.

Objets référencés mais **absents du magasin Git local**, donc taille/SHA-256 et contenu inconnus :

| Chemin dans `SDK@b25f121` | OID Git du blob, pas un SHA-256 de binaire | Rôle potentiel |
|---|---|---|
| `mtk_lib/MT6261/S00/gprs/sys_sec.lib` | `14e0333321578b06ed23d6e46141de6bccc977bb` | Loader/contrôle ALICE compilé possible |
| `mtk_lib/MT6261/S00/gprs/GEMINI/2/sys_sec.lib` | `a2778a1147fa2fb0c7f968bd1ea8b95a6158f644` | Variante GEMINI |
| `mtk_lib/MT6261/S00/gprs/GEMINI/FALSE/sys_sec.lib` | `77f635af42c4b1f9ca909019dd3b4bd8f7d88d29` | Variante sans GEMINI |
| `hal/system/GFH/public/br_GFH_flash_info.h` | `19284b5482d7c29867cc75f764cdd821b5a57498` | Nommage exact des champs GFH_FLASH_INFO |
| `make/Gsm2.mak` | `a15491a536c34265598eea66c23dd2c97a0d9950` | Commandes globales du build non lisibles localement |
| `make/system/system.mak` | `22f46ea67e3117e08664affcf494cf1a6e53d0eb` | Configuration système non lisible localement |

Aucun outil caché dans ces bibliothèques ne peut être déclaré disponible sur la seule présence du chemin dans `ls-tree`. Le scan a aussi lu 2 787 blobs résidents de moins de 2 Mo, avec recherche de `ALICE.exe`, `ALICE_1/2`, `alice_internal`, `DictionaryMaker`, `AliceHeaderWriter`, `RangeRegisters`; aucun encodeur source supplémentaire identifié.

## 4. ALICE_2 format map

### Header et régions exactes

Tous les entiers du conteneur sont little-endian; le stream est lu MSB-first. Header observé :

```text
414c4943455f3200 c4121810 846d2810 68192910
0400 0500 0700 0800 0900 0b00 0c00 09 01 4000 ffff
```

| Offset A | Taille | Valeur / signification | Lecteur / écrivain / preuve |
|---:|---:|---|---|
| `+0x00` | 7 | `ALICE_2` version | `PY/unalice.py:211`; EXE VA `0x411C55`–`0x411C88`; runtime `0x1000F35C`–`0x1000F3AC` |
| `+0x07` | 1 | NUL | EXE `0x411CA2`; A+7 |
| `+0x08` | 4 | `0x101812C4`, début stream compressé en adresse mappée | `PY/unalice.py:229`, `:232`; EXE `0x411C8D`, `0x411C96` |
| `+0x0C` | 4 | `0x10286D84`, adresse mapping | `PY/unalice.py:229`, `:232`; EXE `0x411C93`, `0x411CA7`; runtime `0x1000F586`–`0x1000F594` |
| `+0x10` | 4 | `0x10291968`, adresse dictionnaire | `PY/unalice.py:229`, `:233`; EXE `0x411C90`, `0x411C9E`; runtime `0x1000F458`, `0x1000F4E4` |
| `+0x14` | 2 | range 0 = 4 bits de payload | `PY/unalice.py:236`–`:244`; writer `0x411CB2`–`0x411CD8`; runtime `0x1000F3B2` |
| `+0x16` | 2 | range 1 = 5 | mêmes boucles; runtime `0x1000F3C2` |
| `+0x18` | 2 | range 2 = 7 | mêmes boucles; runtime `0x1000F3CC` |
| `+0x1A` | 2 | range 3 = 8 | mêmes boucles; runtime `0x1000F3D6` |
| `+0x1C` | 2 | range 4 = 9 | mêmes boucles; runtime `0x1000F3E0` |
| `+0x1E` | 2 | range 5 = 11 | mêmes boucles; runtime `0x1000F3EA` |
| `+0x20` | 2 | range 6 = 12 | mêmes boucles; runtime `0x1000F3F4` |
| `+0x22` | 1 | 9 : banque source de remapping | EXE `0x411CDA`, `0x411D1E`, `0x411D2E`; `unalice.py` ignore ce champ |
| `+0x23` | 1 | 1 : banque destination de remapping | EXE `0x411CFC`, `0x411D21`, `0x411D32`; pas une taille |
| `+0x24` | 2 | `0x40` : nombre de demi-mots par groupe mapping côté CLI/writer; 128 octets décompressés par entrée | EXE `0x411C9A`, `0x411CAB`; CLI `+0x2C47D`; runtime `0x1000F46C`–`0x1000F4D2` |
| `+0x26` | 2 | `0xFFFF`, fin réservée/padding observé | A+0x26; aucun sens checksum établi. Writer écrit 40 octets à `0x411D58`; ces deux octets ne sont pas explicitement initialisés dans la fonction inspectée : généralisation UNKNOWN |
| `+0x28` | `0x105AC0` | stream, finit à `+0x105AE8` | `PY/unalice.py:234`, `:263`; D `[0x1812C4,0x286D84)` |
| `+0x105AE8` | `0xABE4` | 11 001 mots mapping, dont une sentinelle | `PY/unalice.py:267`; D `[0x286D84,0x291968)` |
| `+0x1106CC` | `0x3760` | 7 088 demi-mots du dictionnaire | `PY/unalice.py:284`; D `[0x291968,0x2950C8)` |

**FACT :** les deux adresses de table sont absolues dans l'espace flash mappé, pas des offsets. Conversion : `offset_A = adresse - A.base_stream + 0x28`. Le header ne stocke **ni longueur décompressée exacte, ni CRC/SHA explicite** dans les champs décodés.

### Range coding et raw

Ce « range encoding » est un code de classes à préfixes, pas le range coder arithmétique LZMA. Pour un préfixe `s` de 3 bits, lire `r[s]` bits; si `s<7`, index du dictionnaire = `sum(2**r[j], j<s) + payload`. Si `s==7`, lire directement un demi-mot de 16 bits : `111 || u16`, soit 19 bits. Preuve exécutable : `PY/unalice.py:64`, `:124`, `:131`; reproduction du stream original en section 11.

| Classe | Bits payload | Bits totaux | Index de dictionnaire |
|---:|---:|---:|---|
| 0 | 4 | 7 | `[0x0000,0x0010)` |
| 1 | 5 | 8 | `[0x0010,0x0030)` |
| 2 | 7 | 10 | `[0x0030,0x00B0)` |
| 3 | 8 | 11 | `[0x00B0,0x01B0)` |
| 4 | 9 | 12 | `[0x01B0,0x03B0)` |
| 5 | 11 | 14 | `[0x03B0,0x0BB0)` |
| 6 | 12 | 15 | `[0x0BB0,0x1BB0)` |
| 7 | 16 | 19 | valeur raw, aucun lookup |

Le dictionnaire contient exactement `0x1BB0 = 7088` entrées. L'ordre des entrées n'a pas à reproduire un histogramme officiel pour être décodable si toutes les références sont cohérentes; en revanche conserver l'ordre original simplifie la compatibilité et permet ici l'identité binaire.

### Mapping, blocksize et padding — correction importante du prototype

**FACT pour cet Altice :** le stream est aligné à l'octet après chaque **32 demi-mots = 64 octets décompressés**; une entrée mapping couvre **64 demi-mots = 128 octets**. `unalice.py` nomme `blocksize` la valeur 64 et l'utilise comme nombre d'octets entre alignements; l'EXE nomme `-cBlock 64` le nombre d'instructions du groupe. Ces descriptions ne sont pas interchangeables pour les autres tailles sans validation.

Pour chaque groupe Altice, avec `B=0x101812C4`, `o` son offset dans le stream et `h` la longueur compressée de sa première moitié :

```text
mapping = ((B + o) & 0x03FFFFFF) | ((h - 13) << 26)
sentinelle = (B + stream_length) & 0x03FFFFFF
```

**FACT observé sur les 11 000 entrées de données :** bits 31..26 = hint de longueur; `h = (mapping >> 26) + 13`. Bits 25..24 valent zéro dans cet échantillon. Le masque `0x00FFFFFF` de `unalice.py:269` fonctionne donc ici; la capacité générale à 26 bits est **STRONGLY SUPPORTED** par le partage des bits et le code EXE `0x40FF03`–`0x40FF34`, ainsi que les registres de banque runtime `0x1000F574`. La formule a reproduit tous les mots originaux.

Premières entrées : `0x781812C4`, `0xA8181328`, `0x8C181396`. Débuts des demi-blocs stream : `0,43,100,155,210,258,311`. Première longueur `43 = 30+13`; longueur du groupe 100. Sentinelle finale : `0x00286D84`.

**Bug constaté :** `PY/unalice.py:272` calcule `hint + 25`, soit **12 octets de trop**, pour chaque première moitié de cet Altice. Le décodage séquentiel réussit car cette longueur n'est pas utilisée pour sauter aux blocs et la dernière entrée a un hint nul. Un repacker ne doit pas recopier cette formule de longueur. La phrase « low byte unknown » du README ne décrit pas correctement le packing réellement observé.

Taille exacte U `0x157BB4`; décodage complet des 11 000 groupes : `0x157C00`, dont **0x4C octets zéro** après U. Ces zéros sont encodés dans le stream; ce ne sont pas des octets FF après A. Le lecteur historique s'arrête avant eux grâce à son heuristique EOF. Le stream complet ainsi décodé finit exactement à la mapping table. Les tables sont alignées à 4 octets dans cet original; le build aligne également les composants et la sortie VIVA à 4 (`SDK/tools/aliceProcess.pm:95`; `SDK/tools/vivaProcess.pl:199`).

**UNKNOWN pour une image arbitraire :** EOF exact sans longueur externe; généralisation des hints/paddings à d'autres `-cBlock`, versions et banques. Le lecteur doit accepter une longueur attendue pour tester une extension qui peut légitimement se terminer par des zéros.

### BL/BLX translate / untranslate

`PY/alice.py:55` et `PY/unalice.py:144` scannent les demi-mots. Ils ignorent une paire qui commencerait au dernier demi-mot d'un bloc de 32 (`(p+1)%32 == 0`). Paire candidate : premier mot masqué par `0xF800` égal à `0xF000`; second égal à `0xF800` pour BL ou `0xE800` pour BLX. Après traitement, sautent le second mot. Ces règles s'appliquent aussi à des données qui ressemblent à ces opcodes; il faut reproduire l'algorithme du format, pas sélectionner seulement les fonctions désassemblées.

Soit `x=((w1&0x7FF)<<11)|(w2&0x7FF)` et `p` l'index du premier demi-mot. La traduction encode, modulo les 22 bits significatifs, `x' = x + p + 1`; elle réassemble les 11 bits hauts/bas en préservant le type BL/BLX. L'inverse encode `x = x' - p - 1` modulo ces bits. Les branches signées dans le Python utilisent de grandes constantes, mais la troncature lors du réassemblage donne cette même relation modulaire. Le commentaire « J2 » du prototype ne doit pas être pris comme spécification Thumb-2 de ce firmware ARMv5.

**FACT :** exécution en mémoire de la fonction de traduction du prototype sur U produit exactement T (hash section 8); l'inverse restitue U. Les compteurs imprimés `67724 bl / 40014 blx` sont multipliés par deux par le script : ils correspondent à 33 862 paires BL et 20 007 paires BLX, pas au double de branches réelles.

### Ce qui manque exactement dans `alice.py`

1. Header ALICE_2 complet et sérialisation des adresses, ranges, banques et taille de groupe : **aucun writer**, sortie finale uniquement `buff` (`PY/alice.py:259`).
2. Mapping table, hints de demi-blocs et sentinelle : décrits dans l'introduction, **non implémentés**. Aucun append de table après le stream.
3. Append du dictionnaire de décodage dans l'ordre des indices. `magic-py.bin` et `before_encode-py.bin` sont des **tables de l'encodeur**, pas ce dictionnaire.
4. Ranges dynamiques ou chargement cohérent des ranges originaux. Les bornes codées en dur à `:182` impliquent notamment 64 entrées en classe 1, alors que cet Altice en a 32. `codes` et `starts` sont également figés (`:184`, `:185`).
5. Padding du dernier groupe, terminaison et alignement des tables : TODO explicite `:257`; l'original exige ici 0x4C octets décompressés de padding.
6. Robustesse histogramme : la boucle `:190` indexe jusqu'aux bornes figées sans vérifier le nombre de symboles distincts; un petit fichier peut provoquer IndexError. Tri `:177` par octets little-endian, pas nécessairement l'ordre officiel. Reproduire ce tri n'est pas indispensable à la validité si le codebook est cohérent.
7. Paramètres de version, bases et blocksize; validation des offsets, capacités des hints, longueurs paires, dictionnaire, padding. La traduction et la boucle de bitpacking figent 32 demi-mots (`:61`, `:247`).
8. Une séparation CLI/bibliothèque : l'import exécute les écritures. Pour l'audit, seules les définitions de fonctions nécessaires ont été chargées via AST; le programme principal n'a jamais été lancé.

L'option de fournir deux tables externes (`:222`) arrive **après** génération de l'histogramme et écritures intermédiaires : elle n'évite pas les erreurs précédentes et ne construit toujours pas de conteneur.

## 5. Physical flash/VIVA layout

### Chaîne physique vérifiée

Intervalles demi-ouverts, fin exclue :

| Région | Début D | Fin D | Nature / niveau |
|---|---:|---:|---|
| Préambule avant premier GFH | `0` | `0x800` | Données de boot; pas renommées abusivement partition GPT |
| Premier bootloader GFH | `0x800` | `0x235C` | FILE_INFO type 1, longueur `0x1B5C`, hash SHA-1 terminal validé |
| Alignement | `0x235C` | `0x2400` | Intervalle entre les deux images |
| EXT_BOOTLOADER | `0x2400` | `0x9BD4` | FILE_INFO type 2, longueur `0x77D4`, hash SHA-1 terminal validé |
| Intervalle avant ROM | `0x9BD4` | `0xA000` | Alignement physique |
| ROM | `0xA000` | `0x4BE0C` | FILE_INFO type `0x100`, longueur `0x41E0C`, contenu à +`0x5B0` |
| Intervalle ROM/VIVA | `0x4BE0C` | `0x4C20C` | 0x400 octets hors FILE_INFO ROM |
| VIVA GFH | `0x4C20C` | `0x4C244` | FILE_INFO seul, 0x38 octets |
| VIVAInfo | `0x4C244` | `0x4C258` | 5 adresses 32 bits |
| ZIMAGE | `0x4C258` | `0x13D570` | LZMA type 3 utilisant preset U |
| BOOT_ZIMAGE | `0x13D570` | `0x162B6C` | LZMA type 3 utilisant preset U |
| DCM | `0x162B6C` | `0x18129C` | En-tête `DCMGBODY`, modules compressés |
| ALICE_2 | `0x18129C` | `0x2950C8` | Dernier composant VIVA |
| Plage entièrement FF | `0x2950C8` | `0x2C0000` | 0x2AF38 octets, **hors longueur VIVA courante** |
| Région suivante | `0x2C0000` | au-delà | Données occupées; début très probablement filesystem/FDM; structure précise non entièrement résolue |

Preuves : headers D aux débuts indiqués; VIVAInfo D+`0x4C244` contient `1004C20C,1004C258,1013D570,10162B6C,1018129C`; `scripts/acquisition/extract_altice_alice_from_dump.py:36`; `scripts/analysis/extract_viva_components.py:82`.

### FILE_INFO VIVA, décodage champ par champ

| Offset relatif VIVA | Taille | Champ | Valeur |
|---:|---:|---|---:|
| `0x00` | 4 | magic/version GFH | `MMM\x01` |
| `0x04` | 2 | taille record | `0x38` |
| `0x06` | 2 | type GFH | `0` FILE_INFO |
| `0x08` | 12 | identifiant | `FILE_INFO`, tableau 12 octets; dernier octet observé `0x01` après les NUL, à préserver |
| `0x14` | 4 | file_ver | `0` |
| `0x18` | 2 | file_type | `0x0108` VIVA |
| `0x1A` | 1 | flash_dev | `7` serial flash |
| `0x1B` | 1 | sig_type | `0` SIG_NONE |
| `0x1C` | 4 | load_addr | `0x1004C20C` |
| `0x20` | 4 | file_len | `0x248EBC` |
| `0x24` | 4 | max_size | `0xFFFFFFFF` = limite ignorée, **pas une réserve de 4 Go** |
| `0x28` | 4 | content_offset | `0x38` |
| `0x2C` | 4 | sig_len | `0` |
| `0x30` | 4 | jump_offset | `0` |
| `0x34` | 4 | attr | `3` = post-build done + XIP |

Structure/énumérations : `SDK/tools/CardDownload/XIM_Maker_SRC/_External/inc_customer/br_GFH_file_info.h:94`, `:149`, `:165`, `:168`, `:171`; parsing `SDK/tools/vivaHelper.pm:299`–`:337`; valeurs binaires D+`0x4C20C`.

### Que commence-t-il à 0x2C0000 ?

**FACT :** ni `ALICE`, ni `MMM`, ni VIVA. Les premiers mots little-endian sont `0x3900006A`, puis sept fois `0x0000005C`, suivis de FF dans la fin des 0x100 premiers octets. Il s'agit de données persistantes déjà occupées, à conserver.

**STRONGLY SUPPORTED :** début de la région filesystem/FDM NOR. Le GFH ROM de type `0x0207` (GFH_FLASH_INFO, nom défini dans `SDK/tools/CardDownload/XIM_Maker_SRC/_External/inc_customer/br_GFH.h:94`) commence à D+`0xA168`; il contient `0x002C0000` à +`0x1C` et `0x00040000` à +`0x20`, après l'identification flash. Les sources `SDK/custom/common/hal/custom_flash.c:619`, `:692`, `:900` emploient une base NOR dédiée au filesystem. **UNKNOWN :** nom exact du champ à +0x1C et interprétation des premiers mots FDM; le header GFH original qui permettrait de les nommer est seulement référencé dans le Git partiel, blob absent. Ne pas présenter `0x40000` comme taille de toute la région restante sans ce décodage.

La plage FF est donc **FACT : espace inutilisé entre fin actuelle du fichier VIVA et région suivante**; **STRONGLY SUPPORTED : marge de la zone firmware jusqu'au filesystem**, plutôt qu'un composant indépendant identifié. Aucune table locale ne démontre un « slot ALICE » autonome avec taille déclarée. Le `max_size` VIVA ne fixe aucune limite exploitable.

Plafonds physiques sans déplacer cette région :

```text
ALICE_max = 0x2C0000 - 0x18129C = 0x13ED64
VIVA_max  = 0x2C0000 - 0x04C20C = 0x273DF4
VIVA_new.file_len = 0x135090 + len(ALICE_new)
```

La marge inclut la croissance du stream **et** de la mapping table/dictionnaire; ce n'est pas une marge de code décompressé. Aucun effacement de bloc n'est étudié ou autorisé dans cet audit.

## 6. Runtime loader constants

### Occurrences significatives du dump, avec consommateurs

| Offset D / offset ROM | Valeur | Fonction / désassemblage pertinent | Agrandissement à `0x158BB4` |
|---|---|---|---|
| `0xB910 / 0x1910` | base `0x1024EC00` | `0x1000B90C: ldr r0,[pc,#0]; bx lr`. Getter base, comparable à `SDK/custom/system/GXQ03D_M2M_11C_BB/custom_scatstruct.c:1403` | conserver si append; FACT rôle getter, nom donor STRONGLY SUPPORTED |
| `0xB918 / 0x1918` | taille `0x157BB4` | getter `0x1000B914: ldr r0,[pc,#0]; bx lr`; analogue donor `custom_scatstruct.c:1421` | probablement `0x158BB4`; FACT retour taille |
| `0xC188 / 0x2188` | base `0x1024EC00` | branche type 3 `0x1000C11A`; `ldr r0`, `ldr r1`, `subs r1,r1,r0`, min avec `0x400000`; paramètres preset LZMA | conserver base; FACT |
| `0xC18C / 0x218C` | limite `0x103A67B4` | même branche, appel `0x10011AC8` à `0x1000C156`; corroboration donor `code_decompression_hal.c:355` | **décision spécifique au preset** : extension cohérente = `0x103A77B4`, mais préserver l'ancienne longueur pourrait être nécessaire pour conserver les flux LZMA inchangés. Ne pas changer aveuglément |
| `0xEC50 / 0x4C50` | base `0x1024EC00` | fonction `0x1000EBE4`, load `0x1000EBF4`, `str [sp,#8]` | conserver |
| `0xEC54 / 0x4C54` | taille `0x157BB4` | load `0x1000EBFA`, `str [sp,#0xC]`; passe config à `0x1000F290` via `0x1000EC46` | probablement `0x158BB4`, cohérence de configuration; FACT |
| `0xECC4 / 0x4CC4` | base `0x1024EC00` | fonction `0x1000EC58`, load `0x1000EC68` | conserver |
| `0xECC8 / 0x4CC8` | taille `0x157BB4` | load `0x1000EC6E`, `str [sp,#0xC]`; appel d'initialisation `0x1000F340` à `0x1000ECBA` | probablement `0x158BB4`; étend la fenêtre matérielle |
| `0xFBA8 / 0x5BA8` | base `0x1024EC00` | `0x1000FAF4`, load `0x1000FB30`, stocke entrée de table à +0x30 | conserver |
| `0xFBAC / 0x5BAC` | taille `0x157BB4` | load `0x1000FB34`, table +0x34; boucle `0x1000FB52` vérifie `base <= adresse < base+taille` | probablement `0x158BB4` pour reconnaître la nouvelle plage; ce n'est pas une simple copie de loader |
| `0x110D8 / 0x70D8` | base `0x1024EC00` | fonction `0x10011014`, `str r0,[r4,#8]` | conserver |
| `0x110DC / 0x70DC` | fin `0x103A67B4` | `0x10011024: ldr r1`; `subs r0,r1,r0`; `str [r4,#0xC]`, construit des descripteurs de régions | probablement `0x103A77B4`; rôle descripteur FACT, nom précis UNKNOWN |
| `0x1812A4` | `0x101812C4` | champ A+8, pas une fonction | conserver si header physique inchangé |
| `0x4C254` | `0x1018129C` | VIVAInfo.alice_base | conserver si ALICE ne bouge pas |
| `0x4C22C` | `0x248EBC` | FILE_INFO.file_len | recalculer selon longueur **compressée** effective |

Les quatre occurrences de `0x00157BB4` dans D sont exactement `0xB918,0xEC54,0xECC8,0xFBAC`. Les six occurrences de `0x1024EC00` sont exactement `0xB910,0xC188,0xEC50,0xECC4,0xFBA8,0x110D8`. `0x101812C4` n'apparaît qu'à `0x1812A4`. Recherche de mots little-endian à tous offsets, pas seulement alignés.

La ROM ne contient pas nécessairement toutes les contraintes sous cette représentation : constantes calculées, valeurs arrondies et registres peuvent intervenir. Le scan de U et des `.bin` de `work/extracted/altice_platform/` ne retrouve pas les bases/tailles exactes ci-dessus; il retrouve des séquences `0x2C0000` sans lien ALICE démontré.

### Bornes physiques et faux positifs

`0x0018129C`, `0x002950C8`, `0x102950C8`, `0x00113E2C` : aucune occurrence exacte dans D. Ce sont principalement des positions calculées; seule la base ALICE **mappée** `0x1018129C` apparaît dans VIVAInfo. La longueur VIVA est stockée une fois à `0x4C22C`.

Occurrences exactes de `0x002C0000` dans D :

| Offset | Contexte | Statut |
|---:|---|---|
| `0xA184` | GFH_FLASH_INFO+0x1C | frontière flash significative, STRONGLY SUPPORTED; conserver |
| `0xDEFF` | séquence non alignée dans code Thumb | pas un littéral de frontière démontré; ne pas modifier |
| `0x46D56` | suite de petits entiers | lecture décalée chevauchant un entier `0x2C`; pas une base démontrée |
| `0x480C6` | table IDs/pointeurs F0 | séquence chevauchant ID `0x2C`; pas une limite ALICE |
| `0x4972E`, `0x4973E` | table de petits paramètres | même ambiguïté d'alignement; pas de consommateur ALICE identifié |
| `0x2C5A6C` | région persistante, chaînes `MP25001`/`MP27001` proches | sens précis UNKNOWN; conserver |
| `0x2D344A` | progression `0x26,0x28,0x2A,0x2C,0x2E,0x30` | séquence chevauchante, faux positif pour une adresse |

Autres matchs dans les décompressés : U `0x49A8E,0x4F292,0x8F843,0x106A07`; BOOT_ZIMAGE `0x12122,0x1230E,0x3B13D,0x484FE`; DCM_0102 `0x645`; ZIMAGE `0x104D4A,0x1093CE,0x14221A,0x14AFBB,0x156466,0x161193,0x172A46,0x172E0A,0x178E62,0x17C5FE,0x1859A7`. Aucun n'est établi comme frontière ALICE. Inventoriés pour éviter de les confondre avec des métadonnées à patcher.

### Conséquence exacte de `0x157BB4 -> 0x158BB4`

C'est **+0x1000 = 4096 octets**, pas +64 KiB. Base inchangée; nouvelle fin exacte `0x103A77B4`. Le loader arrondit sa limite à 64 octets via `+0x3F; >>6; <<6` (`D/code 0x1000F55C`), donc limite matérielle attendue `0x103A77C0`; le dernier groupe complet du format couvre jusqu'à `0x103A7800`.

À dictionnaire et grouping conservés, mapping de **11 001 à 11 033 entrées**, soit +128 octets. Les adresses mapping/dictionary et `VIVA.file_len` sont recalculées, pas augmentées aveuglément de 4096. La base stream et VIVAInfo.alice_base restent inchangées. Les quatre tailles explicites et le descripteur de fin doivent être examinés comme ci-dessus. La limite du preset LZMA exige un test séparé; l'agrandir peut changer l'interprétation des flux existants même si le début de U est préservé.

## 7. Integrity/checksum findings

| Mécanisme | Résultat et preuve | Nature |
|---|---|---|
| Signature VIVA GFH | `sig_type=0`, `sig_len=0`; D+`0x4C227`, D+`0x4C238` | FACT : aucune signature déclarée par ce FILE_INFO |
| Signature ROM GFH | également type/longueur zéro dans D+`0xA000` | FACT local au header, pas preuve globale de boot permissif |
| Bootloaders | `sig_type=1`, `sig_len=0x20`; les 20 premiers octets terminaux correspondent **exactement à SHA-1 du fichier entier moins les 32 octets terminaux**, les 12 suivants valent zéro. Vérifié aux GFH `0x800` et `0x2400` | FACT : hash d'intégrité; pas une signature asymétrique démontrée; bootloaders inchangés pour le repack envisagé |
| Hash/CRC ALICE intrinsèque | pas de champ explicite identifié dans le header complet; fin de A occupée exactement par le dictionnaire | Aucun checksum dédié démontré, **ne pas conclure absence de tout contrôle extérieur** |
| Magic ALICE | comparaison `ALICE_1/2` à `0x1000F35C`–`0x1000F3AC` | validation de format |
| Magic décompressé CAKE | U+0 = `43 41 4B 45`; pool D+`0xF650=0x1024EC7F`, D+`0xF654=0x454B4143`; adresse masquée à 128 octets puis comparaison à `0x1000F618`–`0x1000F624` | FACT : marqueur sentinelle, pas CRC; préserver début U |
| Ranges et alignements | contrôle ranges <32; blocksize parmi 32/64/128/256/512; mapping aligné 4; base runtime alignée 128; borne arrondie 64 | FACT dans loader `0x1000F3B2`–`0x1000F4D6`, `0x1000F54E`, `0x1000F586` |
| Dictionnaire en RAM vs image | routine `0x100104F8` compare ranges/registres et portions du dictionnaire; appels à `0x100179D0`, routine de comparaison mémoire inspectée | contrôle de cohérence / comparaison, pas authentification cryptographique |
| file_len | D+`0x4C22C`; extraction arrête à cette borne | longueur structurelle, pas hash |
| max_size | `0xFFFFFFFF`, constante `GFH_FILE_MAX_SIZE_IGNORED` | pas une preuve de capacité physique ou de permissions |
| Debug « integrity check » donor | `SDK/tools/CMMAutoGen.pl:78`, `tools/DebuggingSuite/Misc/Template.cmm:64` | outillage debug; commentaire non suffisant pour conclure à un contrôle boot Altice |
| Secure boot / vérification extérieure / efuses | non établis par cet audit statique | UNKNOWN; aucune opération téléphone pour les déterminer |

La cohérence du dictionnaire matériel compte même si son codebook est changé légalement : les deux wrappers ROM doivent être cohérents avec la même configuration. Garder le codebook réduit ce risque. Les valeurs 0xFFFF de fin de header ne sont pas assimilées à un checksum.

## 8. Existing artifacts

### Références canoniques et duplicatas

| Chemin | Taille | SHA-256 / usage |
|---|---:|---|
| D | `0x400000` | `2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922` |
| U | `0x157BB4` | `7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea` |
| T | `0x157BB4` | `1eec7ce448cb4aefdcc6f3c8d68741a358d09b3f6dbda1ba4487602eabda1495` |
| A | `0x113E2C` | `8a06970667c6af37f7a6b1fb28dde0622e396fccd5c2a0b450bd795a0257988f` |
| `research/f2/work/extracted/altice_alice/altice_VIVA.bin` | `0x248EBC` | manifest `9903e1109a66e3d547f18dfad0d3e2cf0f63563ebd9072a2abbed98e2a945696`; D `[0x4C20C,0x2950C8)` |
| `research/f2/work/repro/dump2_alice_verify/{alice-py.bin,alice-translated-py.bin,altice_ALICE_2.bin}` | mêmes tailles | hashes recalculés identiques à U,T,A |
| `research/f2/work/extracted/qmobile_alice/alice-py.bin` et `alice-translated-py.bin` | `0x2A89E4` chacun | même hash `25b10ac9ab0d5cc7fe4602c20ace6cd8bab2efd9e2ce7ac9aa55404a6fee18dc`; comparaison possible, pas preuve de transformation Altice |

Le mapping et le dictionnaire Altice sont déjà **disponibles dans A**, respectivement `A[0x105AE8:0x1106CC]` et `A[0x1106CC:0x113E2C]`. Aucun besoin de retrouver un dump externe pour la stratégie C. Les tables de l'encodeur `magic` et `before_encode` peuvent être dérivées du dictionnaire/ranges sans histogramme.

**Pas de fichiers autonomes trouvés** nommés `magic.bin`, `magic-py.bin`, `before_encode.bin`, `before_encode-py.bin`, `translated-py.bin`, ni intermédiaires `~C1.tmp`/`~M2.tmp`, dans l'inventaire récursif. Les noms existent dans le prototype, les anciens sources et les chaînes de l'EXE; cette présence textuelle n'est pas un artefact utilisable. Pas de log local démontrant une exécution réussie de `ALICE.exe` sur Altice.

`work/extracted/altice_platform/manifest.json:2`–`:35` conserve les sorties type 3 vérifiées : ZIMAGE `0x185E98`, hash `85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954`; BOOT_ZIMAGE `0x4B06C`, hash `aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e`. Les DCM et leurs `.lzma` sont également présents. `work/extracted/altice_viva/*_alice-py.bin` contient des sorties historiques ZIMAGE/BOOT et les variantes `*_alice-translated-py.bin` sont **vides** : ne pas les prendre pour un codebook ALICE ou une preuve de compression réussie.

Archives inventoriées sans extraction :

- `data/firmware-packages/altice-service/mobiwire altice F2 firmware cm2 MTK.rar` et `data/firmware-packages/unverified/dzgsm_share_kxQEAY4K.rar` : 5 166 058 octets chacun, même SHA-256 `dd09678489d85a006e0e97ccb53abdef64ce6157594d4c22cc5f4ccb4931a08c`; liste RAR = CFG, bootloader, EXT_BOOTLOADER, ROM, VIVA, image complète. Pas de compresseur dans la liste.
- `data/firmware-packages/qmobile/Qmobile_F2_MT6261_V07_10042017_MIRA.zip` : CFG/ROM/VIVA/bootloaders et liens de téléchargement/outillage; pas d'encodeur ALICE embarqué identifié dans la liste.
- `SDK/tools/python25/Python25.zip` : runtime Python; pas un donor firmware supplémentaire.

## 9. Git-history findings

### mtk_fw_tools

**FACT :** origin `https://github.com/donnm/mtk_fw_tools.git`; branche locale `master`, `origin/master`, `origin/HEAD` au même commit `3130a42`; aucun tag. Clone non shallow, **35 commits** accessibles. Reflog : clone au HEAD courant, pas de checkout ultérieur ou ancien HEAD divergent. `git fsck --full --no-reflogs` termine sans objet dangling signalé. Aucun commit accessible après le checkout courant, daté du 2018-01-16. Aucun dump local d'issues identifié; merge PR #3 seulement dans l'historique. Cela ne dit rien d'un éventuel historique distant non présent.

Six révisions du compresseur Python :

| Commit | Date | Taille blob LF | SHA-256 blob | État |
|---|---|---:|---|---|
| `c3347ea` | 2017-12-16 | 5150 | `c3e2cd5a59d93cc57fef02d9fe28ccea106ad449dc306128180bb0f91caa2551` | traduction/histogramme, pas de conteneur |
| `73b16a0` | 2017-12-22 | 7885 | `7de0f659a36b953db3513f8ab3a8c9d2ad5f258c08323ec7eb7e386295987289` | bitpacking expérimental |
| `221ece9` | 2017-12-22 | 6445 | `eeaafe7c7928977c5ae01cdf2254d17b435c394c3a0dee27ad1288b4a008cd0d` | message « working encoder minus end bytes »; stream, pas writer complet |
| `1fab577` | 2017-12-31 | 7861 | `1558aee67d429fce19d2ee23e9cd55c91356d03607ecbe310ce6da2d04a05e7c` | TODO padding; stream |
| `07aef95` | 2018-01-01 | 8978 | `dcf1dca41f14cec057931110785c1c597bb5a32443223aa206099126f0c20b08` | nettoyage, mapping/header seulement décrits |
| `4de87a5` | 2018-01-10 | 9721 | `30d5f018dc7055c6f24d9ba1d492febd2d86e7fc3e79c98362376c8c9aaf848f` | dernière version alice.py, correction BL/BLX |

Les commits ultérieurs modifient principalement unalice/README; `2560736` introduit l'EOF heuristique; `3130a42` corrige une division Python 3. **Aucune version historique inspectée ne contient un writer ALICE_2 complet supérieur au checkout.** Le titre d'un commit n'est pas une preuve de repack complet.

Fichiers supprimés au commit `fd60fc1`, récupérables par `git show fd60fc1^:nom`, sans checkout :

| Chemin historique | Taille / SHA-256 blob | CLI et contenu réel |
|---|---|---|
| `FW@fd60fc1^:alice.c` | 10456 / `912c28a34b4d8b36cf3da0d8bfebe4daf3257c0700cf7eb0c6eaf436549004af` | `alice ALICE.bin magic.bin`; produit translated.bin / translated_encoded.bin; prototype C incomplet, aucun conteneur; boucle de lecture sur taille octets dans buffer u16 dangereuse |
| `FW@fd60fc1^:dicreader.c` | 3560 / `88192c6d558be2b76efb105d1be3bf772658353f61dfd26f95d6708209cc8f42` | `dicreader [-h|-a] dicfile`; lecteur/affichage, `-h` dictionnaire nu, `-a` image ALICE; struct header 40 octets et 8 bornes 32 bits à la ligne 33 |
| `FW@fd60fc1^:unalice.c` | 7090 / `1fe0b77e5e003946f9e719265f0975a6730a59c498d68ebb21a7a8a6bdad2786` | `unalice ALICE`; ancien lecteur C expérimental; header ligne 36, mapping ligne 128; pas encodeur |
| `FW@fd60fc1^:viva-hdr.c` | 2106 / `d517be4856e5532bc0c04ab409561818431da056a609be14091dda0a32b6809b` | `viva-hdr filename`; affiche FILE_INFO; attention struct commence au champ id et ne lit pas explicitement les 8 octets GFH précédents |

La structure historique `dicreader.c:33` suggère le format d'un fichier dictionnaire externe de l'EXE : longueur header, longueur dictionnaire, huit bornes 32 bits, puis données. **HYPOTHESIS de compatibilité avec l'EXE local** : ne pas donner le simple tail de A à `-iDict` sans vérifier son reader ou produire un fichier par `-oDict`.

### Autres historiques locaux

Racine MTKClient : 125 commits accessibles, HEAD `cd25cf9`; recherche historique de chemins `*alice*`, `*ALICE*`, `*repack*` sans candidat. Les mécanismes DA/flash de MTKClient ne constituent pas un repacker ALICE et n'ont pas été lancés.

Donor MT2503-2 : origin `https://github.com/jamesguo/MT2503-2.git`, branche main/origin/main, HEAD `b25f121` (« Initial commit »), shallow, aucun tag observé. L'arbre conserve les candidats non checkout de la section 3, mais les objets absents empêchent l'audit de leur contenu. Aucun changement de branche, fetch ou restauration de fichier effectué.

## 10. Repack options

| Approche | Disponible | Manquant / risques | Test offline décisif |
|---|---|---|---|
| A. ALICE.exe local | EXE MT6261, wrapper build actif, options bases/block/codebook | exécution non testée; possibles temporaires globaux; format `-iDict`; effet précis de `-dBase`; choix de codebook pouvant solliciter les limites dictionnaire RAM | dans un futur dossier isolé : U original -> EXE -> unalice -> comparaison complète; inspecter header, mapping, padding, taille. Pas besoin d'identité compressée pour succès fonctionnel |
| B. Terminer alice.py | traduction validée; logique de codes/bitpacking lisible | manque header/mapping/dictionary/padding, ranges Altice incorrects, validation/CLI; plus de travail qu'un encodeur à codebook fixe | tests de mini-blocs puis même aller-retour original; vérifier avec décodeur indépendant à longueur explicite |
| C. Garder le codebook, réencoder stream + mapping | **déjà prouvé en mémoire avec identité binaire complète** sur original | persistance/CLI et validations à construire ultérieurement; règles hors profil 64; EOF à longueur explicite; extension runtime/LZMA non résolue | section 11 réussie; ensuite extension contrôlée +0x1000, comparaison intégrale et vérification de chaque mapping/hint |
| D. Utiliser raw `111 + u16` | support prouvé par lecteur et original; permet tout nouveau demi-mot absent du dictionnaire | coût 19 bits/16 bits; toujours soumis à traduction, grouping, mapping et longueur; aucun bypass du loader | hybridation C pour les nouveaux symboles. Tout-raw original avec codebook conservé coûterait `0x1A66AC`, dépasse `0x13ED64` |
| E. Conserver les groupes compressés inchangés et ne reconstruire que la fin | mapping et grouping connus; groupes non affectés réutilisables | dernier groupe partiel; reprise de traduction à la jointure; adresses de tables/sentinelle à recalculer; pas testé ici | comparer résultat à C sur l'original puis après append; preuve byte-perfect du décompressé et des groupes préservés |
| E2. Refaire les composants LZMA si preset change | 7lzma et wrapper `etp/dtp`, sources de structures ZIMAGE | peut déplacer BOOT/DCM/ALICE et consommer marge physique; dimensions et pointeurs VIVA à recalculer; non minimal tant que nécessité non prouvée | comparer décompression des ZIMAGE/BOOT existants avec preset original, preset étendu et longueur conservée; ensuite seulement envisager leur recompression |

**Recommandation : C**, puisque son premier contrôle est maintenant positif et conserve tout le codebook et ses besoins RAM. A reste une excellente référence croisée, sans nécessité de réparer tout le prototype ni de reproduire l'histogramme officiel.

Un append de 4096 octets à codebook fixe représente 32 groupes supplémentaires. Dans le pire cas raw, leur coût stream est au plus 32×152 = 4864 octets, plus 128 octets de mapping, avec ajustement possible du dernier groupe original. Cet ordre de grandeur est très inférieur à la marge physique. **STRONGLY SUPPORTED**, pas mesure d'un payload choisi ni validation de son exécution.

## 11. Recommended NEXT OFFLINE EXPERIMENT

### Premier test obligatoire : déjà effectué, en RAM uniquement

Résultat console observé :

```text
MEMORY REENCODE stream 1071808 True map True full True
sha 8a06970667c6af37f7a6b1fb28dde0622e396fccd5c2a0b450bd795a0257988f
first diff None len 0x113e2c
ROUNDTRIP unalice functions True 0x157bb4
7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea
```

Ce test utilise le dictionnaire et les paramètres de l'original, **pas son stream ni ses mots mapping comme sortie**. Il recalcule ces derniers depuis U, puis compare l'intégralité du conteneur. Le header de référence fournit les paramètres fixes; les deux adresses de tables sont recalculées. La reproduction compressée exacte est plus forte que la seule comparaison des décompressés pour ce cas témoin.

Reproducteur de l'expérience, exécutable depuis la racine en Python `-B` via stdin, sans sauvegarder un script. Le code ci-dessous ne fait aucune écriture fichier et ne charge pas le main des outils existants :

```python
from pathlib import Path
import ast, contextlib, hashlib, io, math, struct, sys
from bitstring import BitArray

root = Path('research/f2')
A = (root/'work/extracted/altice_alice/altice_ALICE_2.bin').read_bytes()
U = (root/'work/extracted/altice_alice/alice-py.bin').read_bytes()
B, M, D = struct.unpack_from('<3I', A, 8)
mo, do = M-B+40, D-B+40
regs = list(struct.unpack_from('<7H', A, 20)) + [16]
dictionary = struct.unpack('<%dH' % ((len(A)-do)//2), A[do:])

def functions(path, names=None):
    tree = ast.parse(path.read_text())
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef)
             and (names is None or n.name in names)]
    return compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec')

env = {'buff': bytearray(U)}
with contextlib.redirect_stdout(io.StringIO()):
    exec(functions(root/'tools/unalice/alice.py', {'translate_bl_blx'}), env)
    env['translate_bl_blx']()
translated = bytes(env['buff'])
translated += b'\0' * (-len(translated) % 128)

codes, low = {}, 0
for s, r in enumerate(regs[:7]):
    for j in range(1 << r):
        codes.setdefault(dictionary[low+j], format(s, '03b') + format(j, '0%db' % r))
    low += 1 << r

stream, starts, lengths = bytearray(), [], []
for off in range(0, len(translated), 64):
    words = struct.unpack('<32H', translated[off:off+64])
    bits = ''.join(codes.get(v, '111'+format(v, '016b')) for v in words)
    bits += '0' * (-len(bits) % 8)
    starts.append(len(stream))
    lengths.append(len(bits)//8)
    stream.extend(int(bits[j:j+8], 2) for j in range(0, len(bits), 8))

# Profil exact Altice. Bits 25..24 nuls dans cet original.
mapping = [((B+starts[i]) & 0xFFFFFF) | ((lengths[i]-13) << 26)
           for i in range(0, len(starts), 2)]
mapping.append((B+len(stream)) & 0xFFFFFF)
mapbytes = struct.pack('<%dI' % len(mapping), *mapping)
header = bytearray(A[:40])
struct.pack_into('<II', header, 12, B+len(stream), B+len(stream)+len(mapbytes))
packed = bytes(header) + stream + mapbytes + A[do:]
assert packed == A
print('container', hex(len(packed)), hashlib.sha256(packed).hexdigest())

# Reproduire aussi le lecteur historique, y compris son EOF heuristique.
mapped = [((v-B) & 0xFFFFFF, (v >> 26)+25 if v >> 24 else 0) for v in mapping]
env = dict(math=math, sys=sys, struct=struct, fout=io.BytesIO(),
           instrdict=list(dictionary), range_regs=regs,
           bitbuff=BitArray(bytes(stream)), mappings=mapped,
           alicebin=bytearray(), blocksize=64)
with contextlib.redirect_stdout(io.StringIO()):
    exec(functions(root/'tools/unalice/unalice.py'), env)
    env['bitunpack']()
    env['buff'] = env['alicebin']
    env['untranslate_bl_blx']()
assert bytes(env['buff']) == U
print('decoded', hex(len(env['buff'])), hashlib.sha256(env['buff']).hexdigest())
```

**Limite :** ce reproducteur est un test témoin fixé au profil Altice, pas un repacker général validé. L'EOF heuristique est volontairement utilisé pour reproduire le lecteur demandé. Aucun payload modifié n'a été construit ou injecté pendant cet audit.

### Prochaine expérience après ce témoin

1. Dans un futur travail offline, formaliser le writer C à codebook conservé, avec lecture à longueur explicite et validation individuelle des hints/table/sentinelle.
2. Ajouter **0x1000 octets** de données de test connues à U, sans toucher au préfixe original. Inclure des motifs non présents dans le codebook et des paires BL/BLX près des frontières; ne pas confondre test de données et code exécutable.
3. Vérifier `U_extended -> repack -> unalice à longueur contrôlée -> U_extended` intégralement, taille compressée <= `0x13ED64`, 11 033 entrées mapping et nouvelles adresses de tables cohérentes.
4. **Avant toute réinjection**, prouver offline l'effet du preset agrandi sur les ZIMAGE et BOOT_ZIMAGE existants. Comparer aux hashes canoniques; décider si leur consommateur doit conserver l'ancienne limite ou si les flux doivent être régénérés.
5. Produire ensuite seulement une proposition de modifications ROM/GFH par rôle, incluant les quatre tailles, les descripteurs de fin et la limite matérielle. Pas de remplacement global. Validation du boot matériel reste distincte et non autorisée ici.

## 12. Open questions

- Compatibilité de l'EXE local sur l'Altice original : CLI identifiée, exécution non faite. Format exact de `-iDict` et influence de `-dBase` à documenter si cette voie est choisie.
- Le +0x26 `FFFF` est-il requis, ignoré ou simple résidu du writer ? Sa valeur a été conservée, pas interprétée comme preuve d'intégrité.
- Généralisation du mapping aux autres blocksize/ALICE_1 : test exact limité au profil original.
- EOF des images arbitraires : le header n'indique pas la longueur exacte; les heuristiques de unalice peuvent tronquer un append nul ou trompeur.
- Impact du preset LZMA agrandi : prouver la sémantique de sa longueur et des distances avant de modifier D+0xC18C. Préserver les octets initiaux de U ne suffit pas à prouver cet impact nul.
- Définition exacte GFH_FLASH_INFO+0x1C et premier bloc FDM à 0x2C0000 : identification filesystem solide mais décodage structurel incomplet; header original absent localement.
- Politique de vérification du boot hors des fonctions inspectées : pas de preuve globale d'absence de signature/authentification. Les libs `sys_sec.lib` ne sont pas résidentes.
- Disponibilité exacte de toute la fenêtre runtime étendue et de ses consommateurs : aucun test sur téléphone, aucun relink Altice disponible.
- Des contraintes peuvent être calculées plutôt que stockées comme les mots recherchés; l'inventaire des occurrences n'est pas une liste automatiquement sûre de patches.

### Réponses explicites Q1–Q4

**Q1. Moyen local fonctionnel ou presque fonctionnel de recréer ALICE_2 ?** Oui : **recréation originale byte-perfect prouvée en mémoire**, avec codebook existant et writer minimal de cette section 11. Un ALICE.exe MT6261 est également présent, mais non testé ici. Le `alice.py` standalone actuel reste incomplet.

**Q2. Taille physique maximale avant collision ?** **0x13ED64 = 1 305 956 octets**, header/tables/dictionnaire compris, depuis `0x18129C` jusqu'à `0x2C0000` exclu. Marge actuelle **0x2AF38 = 175 928 octets**. Plafond physique, pas validation runtime.

**Q3. Métadonnées probablement à changer pour 0x158BB4 ?** Les tailles D+`0xB918`, `0xEC54`, `0xECC8`, `0xFBAC`; fin du descripteur D+`0x110DC` vers `0x103A77B4`; traiter **séparément** la fin preset D+`0xC18C`. Recalculer mapping (+32 entrées), adresses A+`0x0C/+0x10`, sentinelle, padding et `VIVA.file_len` D+`0x4C22C`. Conserver bases physique/runtime, magic CAKE, banques et frontière filesystem si append sans déplacement. Ranges/codebook restent identiques avec la stratégie C.

**Q4. Test offline le plus court ?** `U original -> traduction -> stream/mapping avec codebook A -> unalice -> comparaison byte-perfect U`. **Déjà réussi en RAM pendant l'audit, jusqu'à l'identité du conteneur compressé.** Le prochain test utile porte donc sur +0x1000 et la dépendance LZMA, pas sur une nouvelle recherche de code caves.
