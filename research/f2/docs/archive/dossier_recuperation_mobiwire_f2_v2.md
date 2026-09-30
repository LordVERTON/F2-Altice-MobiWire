# Dossier de récupération — MobiWire NIKITI / Altice F2

_Mise à jour : 28 septembre 2026_

## 1. Objectif du projet

L'objectif est d'obtenir sur le MobiWire NIKITI / Altice F2 un **lecteur audio capable de lire des fichiers MP3**, idéalement depuis une carte mémoire.

Ce téléphone n'est pas un smartphone Android : on ne peut donc pas simplement installer une application APK. La solution passe par l'une des voies suivantes :

1. retrouver un firmware officiel F2/NIKITI qui contient déjà le lecteur audio ;
2. vérifier si le lecteur existe déjà dans la ROM actuelle mais est masqué/désactivé ;
3. en dernier recours, adapter une ROM compatible sans toucher aux données uniques du téléphone.

La priorité reste de trouver une **ROM stock compatible**.

---

## 2. Identification matérielle confirmée

Le téléphone a été interrogé directement depuis son **Boot ROM MediaTek (BROM)** via USB.

Résultat lu sur l'appareil :

```text
BB_CPU_ID = 0x6261
BB_CPU_HW = 0xCB01
BB_CPU_SW = 0x0001
BB_CPU_SB = 0x8000
```

**Identification confirmée : MediaTek MT6261.**

Cette lecture directe prime sur les anciennes informations trouvées sur Internet qui associaient parfois certains F2/NIKITI au MT6260.

---

## 3. Outils utilisés

### Windows PowerShell

PowerShell a servi à :

- activer l'environnement Python ;
- lancer les scripts de probe et de dump ;
- calculer les SHA-256 ;
- vérifier la taille des fichiers sauvegardés.

Commandes typiques :

```powershell
cd $env:USERPROFILE\mtkclient
.\.venv\Scripts\Activate.ps1
```

Puis, par exemple :

```powershell
python -u .\probe_mobiwire_flash_size_v2_working.py
python -u .\dump_mobiwire_4mb_v2.py .\mobiwire_dump_2.bin
Get-FileHash .\mobiwire_dump_2.bin -Algorithm SHA256
```

### Python

Python a été utilisé pour communiquer directement avec le téléphone en USB et envoyer les commandes BROM MediaTek.

Bibliothèques utilisées :

```text
pyusb
libusb-package
```

Elles permettent à Python d'utiliser `libusb` sous Windows pour parler au périphérique MediaTek.

### PyUSB / libusb

PyUSB sert d'interface Python vers USB.

Dans notre cas, il a permis de :

- rechercher le périphérique `0E8D:0003` ;
- détecter les interfaces USB ;
- récupérer les endpoints BULK IN et BULK OUT ;
- envoyer le handshake BROM ;
- lire directement la mémoire du MT6261.

### Zadig

**Zadig** a été utilisé pour affecter le pilote **WinUSB** au périphérique MediaTek détecté pendant sa courte apparition en mode Boot ROM.

Le périphérique important est :

```text
VID:PID = 0E8D:0003
```

L'objectif de Zadig était de remplacer/associer le pilote Windows temporaire du périphérique MediaTek par :

```text
WinUSB
```

afin que `libusb` et `PyUSB` puissent l'ouvrir directement.

Cette étape a été déterminante : un pilote COM classique permet de voir un port série, mais ne donne pas nécessairement accès de façon fiable aux endpoints USB nécessaires à notre méthode BROM.

### Gestionnaire de périphériques Windows

Le Gestionnaire de périphériques a été utilisé pour observer l'apparition très brève du téléphone lorsqu'il est branché éteint.

Selon le pilote actif, le téléphone pouvait apparaître comme :

- périphérique MediaTek ;
- port COM temporaire, par exemple `COM3` ;
- périphérique USB utilisant WinUSB après configuration avec Zadig.

Le principal problème était que ce périphérique disparaît rapidement si aucun logiciel ne le capture.

### Scripts de capture USB / COM

Des scripts ont été utilisés pour surveiller rapidement l'apparition du téléphone afin de ne pas rater la courte fenêtre BROM.

La logique était :

```text
téléphone éteint
↓
batterie retirée quelques secondes
↓
batterie remise
↓
script déjà en attente
↓
connexion USB
↓
détection 0E8D:0003 / COM temporaire
↓
capture immédiate
```

Les essais autour du port `COM3` ont surtout servi à comprendre que Windows exposait parfois brièvement le téléphone comme port série, mais la solution stable retenue a finalement été **WinUSB + accès USB BULK direct**.

### mtkclient

Le dossier de travail a été conservé dans :

```text
C:\Users\verto\mtkclient
```

`mtkclient` a servi de base d'environnement Python et de référence pour le travail MediaTek.

Cependant, l'accès final utilisé pour ce MT6261 a reposé sur des scripts spécifiques adaptés au protocole BROM de cette famille de feature phones.

### mediatek_flash

Le projet open source `mediatek_flash` de ilyakurdyukov a servi de référence technique importante pour comprendre :

- les commandes BROM MT6260/MT6261 ;
- la désactivation temporaire du watchdog ;
- le registre de mapping de la NOR ;
- la lecture mémoire 32 bits ;
- le comportement attendu d'une flash de quelques MiB.

Référence :

```text
https://github.com/ilyakurdyukov/mediatek_flash
```

### Outils de hachage SHA-256

PowerShell a été utilisé pour calculer les empreintes SHA-256 :

```powershell
Get-FileHash .\mobiwire_dump_1.bin -Algorithm SHA256
Get-FileHash .\mobiwire_dump_2.bin -Algorithm SHA256
Get-FileHash .\mobiwire_dump_3.bin -Algorithm SHA256
```

Le SHA-256 permet de savoir si deux dumps sont **strictement identiques octet par octet**.

---

## 4. Problèmes rencontrés avec les pilotes et l'USB

### Problème 1 — périphérique visible seulement quelques secondes

Lorsque le téléphone est branché éteint, la BROM MediaTek apparaît brièvement.

Si aucun programme ne l'ouvre immédiatement, le périphérique peut :

- disparaître ;
- changer de pilote ;
- passer par un port COM temporaire ;
- laisser Windows tenter un autre mode de démarrage.

### Solution

Les scripts ont été conçus pour afficher :

```text
>>> BRANCHEZ LE CABLE USB MAINTENANT <<<
```

et scruter très rapidement `0E8D:0003` afin de capturer la BROM dès son apparition.

---

### Problème 2 — confusion entre port COM et interface USB réelle

Au début, l'apparition d'un port tel que `COM3` pouvait laisser penser qu'il fallait travailler uniquement en série.

En réalité, la solution retenue utilise directement l'interface USB BULK du périphérique BROM.

Configuration confirmée :

```text
USB VID:PID   : 0E8D:0003
Classe USB    : 0x02
Configuration : 1
Interface     : 0
Bulk OUT      : 0x01
Bulk IN       : 0x81
Pilote Windows: WinUSB
```

---

### Problème 3 — mauvais pilote Windows

Avec un pilote non compatible `libusb`, PyUSB ne pouvait pas ouvrir correctement le périphérique.

### Solution : Zadig

Zadig a été utilisé pour affecter **WinUSB** au périphérique `0E8D:0003`.

Après cela, le script a pu réclamer l'interface :

```text
Interface WinUSB reclamee.
```

---

### Problème 4 — `NotImplementedError` lors d'une seconde connexion

Pendant le deuxième dump, Windows/libusb a parfois retourné :

```text
NotImplementedError('Operation not supported or unimplemented on this platform')
```

L'erreur se produisait avant le handshake, au moment de :

```text
usb.util.claim_interface(...)
```

Donc ce n'était pas une erreur de lecture de la flash.

### Solution

Une version plus robuste du script a été créée :

```text
dump_mobiwire_4mb_v2.py
```

Elle :

- libère les ressources USB ;
- redétecte le périphérique ;
- réessaie jusqu'à 10 fois ;
- continue dès que WinUSB accepte de nouveau l'ouverture.

Lors du troisième dump, on a effectivement vu :

```text
Tentative WinUSB 1/10 echouee : NotImplementedError(...)
Interface WinUSB reclamee.
```

puis le dump s'est déroulé normalement.

---

## 5. Handshake Boot ROM confirmé

Le handshake obtenu est :

```text
A0 -> 5F
0A -> F5
50 -> AF
05 -> FA
```

Ce handshake prouve que le script parle bien directement avec la BROM MediaTek.

Aucune zone de flash n'est écrite pendant cette phase.

---

## 6. Registres volatils utilisés

Deux écritures matérielles temporaires ont été nécessaires.

### Watchdog

```text
Adresse : 0xA0030000
Valeur  : 0x2200
```

Cela empêche le téléphone de redémarrer pendant une longue lecture.

### Mapping de la NOR

```text
Registre : 0xA0510000
Bit      : 0x00000002
```

Ce bit permet de rendre la flash NOR visible dans l'espace mémoire à partir de l'adresse `0x00000000`.

Ces modifications sont **volatiles** : elles disparaissent au redémarrage et ne modifient pas le firmware stocké dans la NOR.

---

## 7. Détermination de la taille de la flash

Le premier probe comparait :

```text
0 MiB
4 MiB
8 MiB
```

Les trois blocs étaient identiques.

Cela indiquait un mirroring, mais ne suffisait pas à prouver 4 MiB : une flash plus petite pouvait également se répéter à ces offsets.

Un deuxième probe a donc comparé :

```text
0 MiB
1 MiB
2 MiB
3 MiB
4 MiB
8 MiB
```

Résultat :

```text
0 MiB != 1 MiB
0 MiB != 2 MiB
0 MiB != 3 MiB
0 MiB == 4 MiB
0 MiB == 8 MiB
```

Conclusion : **période de mirroring observée = 4 MiB**.

Taille probable de la NOR :

```text
0x00400000 octets
4 194 304 octets
4 MiB
```

Plage sauvegardée :

```text
0x00000000 -> 0x003FFFFF
```

---

## 8. Sauvegardes complètes réalisées

Trois dumps complets ont été réalisés.

### Dump 1

```text
SHA256 = 5b25c7efd86f22794f745a089f58610cfe57773a4c53aaf475bd124864bd9036
```

### Dump 2

```text
SHA256 = 2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922
```

### Dump 3

```text
SHA256 = 2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922
```

Les dumps 2 et 3 sont **strictement identiques**.

Ils constituent donc la sauvegarde reproductible de référence.

À conserver :

```text
mobiwire_dump_2.bin
mobiwire_dump_3.bin
```

---

## 9. Pourquoi le dump 1 était différent

Une comparaison octet par octet entre les dumps 1 et 2 a montré :

```text
882 octets différents
sur 4 194 304 octets
soit 0,021029 %
```

Toutes les différences étaient concentrées dans un seul bloc de 4 KiB :

```text
0x002C6000 -> 0x002C6FFF
```

Les 1023 autres blocs de 4 KiB étaient identiques.

Cela ressemble à une petite zone de données variables, de compteur, d'état ou de NVRAM, plutôt qu'à un problème général de lecture.

Le fait que les dumps 2 et 3 soient ensuite identiques valide fortement la méthode de lecture.

---

## 10. Firmware actuellement installé

L'analyse du dump a permis d'identifier la ROM actuelle :

```text
ALTICE_F2_DS_V02.1_181023_MP
```

Nom interne observé :

```text
DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00.ALTICE_F2_DS_V02_1_181023_MP.bin
```

Autres chaînes utiles :

```text
SAGETEL61M_11C_HW
DL188_GX1882_NIKITI
2018/10/23 09:22
```

Cela confirme que la ROM actuelle est bien une ROM spécifique NIKITI / Altice F2 / MT6261.

---

## 11. Analyse du lecteur audio dans la ROM actuelle

Des chaînes telles que :

```text
Music
Playlists
Photo
```

ont été trouvées dans le dump.

Cependant, leur analyse montre qu'elles appartiennent à des entrées FAT marquées avec `0xE5`, c'est-à-dire des entrées supprimées.

Donc elles ne prouvent pas qu'un lecteur audio actif est présent dans le menu actuel.

Des occurrences de `MP3` existent également, mais elles ressemblent davantage à des identifiants internes qu'à une interface utilisateur complète.

La ROM contient aussi au moins une structure audio WAV de type :

```text
RIFF
WAVEfmt
```

Cela prouve une gestion de sons, mais pas nécessairement un lecteur MP3 utilisateur.

---

## 12. Firmware recherché

Les documents réglementaires du NIKITI / Altice F2 indiquent :

```text
Hardware Version : V01
Software Version : ELKI_DS_L_V01.2_181106_MP
FCC ID           : QPN-NIKITI
```

Le manuel de cette famille documente un **lecteur audio**.

La cible prioritaire est donc :

```text
ELKI_DS_L_V01.2_181106_MP
```

et non une ROM MT6261 générique.

---

## 13. Recherches de firmware effectuées

Requêtes principales utilisées :

```text
ELKI_DS_L_V01.2_181106_MP
ELKI_DS_L_V01.2_181106_MP.bin
NIKITI ELKI firmware
MobiWire NIKITI MT6261 firmware
Altice F2 ELKI firmware
QPN-NIKITI firmware
ALTICE_F2_DS_V02.1_181023_MP
DL188_GX1882_NIKITI
SAGETEL61M_11C_HW
```

Pistes explorées :

- documents FCC / certification ;
- manuels officiels ;
- GitHub ;
- GSMHosting ;
- Infinity / CM2 ;
- FuriousGold / OTZ Flasher ;
- DZGSM ;
- anciens sites et forums de firmware.

Aucun fichier public vérifié correspondant exactement à `ELKI_DS_L_V01.2_181106_MP` n'a encore été trouvé.

---

## 14. Pistes importantes restantes

### FuriousGold / OTZ Flasher

Le MobiWire F2 est explicitement listé avec prise en charge :

```text
USB
FLASH_READ
FLASH_WRITE
FORMAT
```

Cela indique que le modèle était présent dans les bases de maintenance professionnelles.

La zone de support FuriousGold reste donc une piste importante pour retrouver une ROM ancienne.

### Infinity / CM2 / GSMHosting

Des discussions historiques sur le MobiWire F2 existent dans l'écosystème Infinity/CM2.

L'objectif est de retrouver :

- une ROM complète ;
- un dump utilisateur ;
- un package de support ;
- ou au minimum un nom de firmware précis.

### DZGSM

Un sujet récent concerne exactement le firmware du **Mobiwire Altice F2**.

Cette piste doit être suivie car elle peut conduire à un dump ou à un fichier non indexé publiquement.

---

## 15. Pourquoi ne pas flasher une ROM MT6261 quelconque

Deux téléphones équipés du même MT6261 peuvent utiliser :

- des écrans différents ;
- des contrôleurs LCD différents ;
- un clavier câblé différemment ;
- des GPIO différents ;
- une configuration RF différente ;
- des périphériques audio différents ;
- une NVRAM spécifique.

Une ROM non adaptée peut donc provoquer :

```text
écran blanc
pas de clavier
pas de réseau
pas de son
boot bloqué
```

C'est pourquoi les ROM Ayasha, Nakai, F1 ou autres MT6261 ne doivent pas être flashées sans comparaison préalable.

---

## 16. Ce qui a été accompli

```text
[OK] Identifier le téléphone
[OK] Identifier le CPU : MT6261
[OK] Comprendre la fenêtre BROM USB
[OK] Capturer le périphérique 0E8D:0003
[OK] Résoudre le problème de pilote avec Zadig / WinUSB
[OK] Identifier les endpoints USB BULK
[OK] Obtenir le handshake BROM
[OK] Désactiver temporairement le watchdog
[OK] Mapper la NOR en mémoire
[OK] Déterminer une période de flash de 4 MiB
[OK] Lire la NOR complète
[OK] Réaliser plusieurs dumps
[OK] Obtenir deux dumps strictement identiques
[OK] Identifier le firmware actuel
[OK] Examiner les chaînes Music / MP3 / Playlists
[OK] Identifier la ROM ELKI comme cible prioritaire
[EN COURS] Trouver le fichier firmware ELKI/NIKITI
```

---

## 17. Ce qu'il reste à faire

Lorsqu'une ROM candidate sera trouvée :

1. vérifier sa taille ;
2. identifier son CPU et sa plateforme ;
3. chercher `NIKITI`, `DL188`, `GX1882`, `SAGETEL61M_11C_HW` ;
4. confirmer la présence du lecteur audio/MP3 ;
5. comparer son organisation avec le dump actuel ;
6. identifier les zones NVRAM/IMEI/calibration ;
7. préserver les données uniques du téléphone ;
8. vérifier la compatibilité LCD ;
9. seulement ensuite préparer une écriture contrôlée ;
10. tester le démarrage, le réseau, le clavier, le son et finalement les fichiers MP3.

---

## 18. Scripts produits pendant le projet

Principaux scripts utilisés ou créés :

```text
probe_mobiwire_flash.py
probe_mobiwire_flash_size_v2_working.py
dump_mobiwire_4mb.py
dump_mobiwire_4mb_v2.py
compare_mobiwire_dumps.py
```

Fonction de chacun :

### `probe_mobiwire_flash.py`

Premier probe de la mémoire flash et validation du MT6261.

### `probe_mobiwire_flash_size_v2_working.py`

Compare plusieurs offsets pour déterminer la période réelle du mirroring de la NOR.

### `dump_mobiwire_4mb.py`

Premier script de sauvegarde complète des 4 MiB.

### `dump_mobiwire_4mb_v2.py`

Version renforcée pour contourner les problèmes intermittents d'ouverture WinUSB sous Windows.

### `compare_mobiwire_dumps.py`

Compare deux dumps octet par octet, identifie les blocs différents et permet de distinguer une petite zone variable d'une lecture instable.

---

## 19. Règle de sécurité du projet

Tant qu'une ROM candidate n'a pas été :

- identifiée ;
- comparée ;
- vérifiée ;
- et que les zones NVRAM / IMEI / calibration ne sont pas comprises ;

**aucune écriture de firmware ne doit être effectuée.**

Les dumps 2 et 3 doivent être conservés intacts comme sauvegarde de référence.

---

## 20. Sources principales

- FCC NIKITI / Altice F2 : https://fccid.io/QPN-NIKITI
- Rapport logiciel/hardware V01 : https://fccid.io/QPN-NIKITI/RF-Exposure-Info/I20D00015-SAR01-4666225.pdf
- Manuel NIKITI / Altice F2 : https://manuals.plus/m/6b8d291ae649edbbb4e2955ed2784ec8b7a3300e1cbd33d392f2f5ac4aa20c9a
- mtkclient : https://github.com/bkerler/mtkclient
- mediatek_flash MT6260/MT6261 : https://github.com/ilyakurdyukov/mediatek_flash
- FuriousGold / OTZ Flasher : https://www.furiousgold.com/en/modules/otz-flasher
- GSMHosting / Infinity : https://forum.gsmhosting.com/
- DZGSM : https://dzgsm.com/

