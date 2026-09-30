# Dossier de récupération — MobiWire NIKITI / Altice F2

_Date de l’état des lieux : 28 septembre 2026_

## 1. Objectif

L’objectif est de remettre le téléphone dans un état fiable avec un firmware compatible qui fournisse un **lecteur audio**.

Point important : la documentation du **MobiWire NIKITI / Altice F2** décrit déjà un **Audio player** capable de lire des fichiers stockés dans le téléphone ou sur carte mémoire. La voie la plus logique n’est donc pas, en premier lieu, de fabriquer un firmware modifié : il faut d’abord **identifier exactement le matériel, sauvegarder le firmware actuel, puis retrouver/restaurer une ROM stock compatible** qui possède ce menu multimédia.

Sur un feature phone MediaTek, on ne peut pas ajouter un lecteur audio comme une application Android APK. Le lecteur est normalement intégré au firmware/RTOS. Une modification personnalisée ne sera envisagée que si aucune ROM stock compatible avec lecteur audio ne peut être obtenue.

## 2. Identification actuelle du téléphone

### Identification du modèle

| Élément | État actuel |
|---|---|
| Famille commerciale | **MobiWire NIKITI / Altice F2** |
| Type | Téléphone 2G / feature phone |
| P/N relevé sur l’appareil | **286547133** |
| FCC ID de la famille | **QPN-NIKITI** |
| Référence matérielle documentée | **V01** |
| Référence logicielle documentée | **ELKI_DS_L_V01.2_181106_MP** |
| Plateforme USB observée | **MediaTek** |
| CPU probable | **MT6260** |
| CPU de cet exemplaire | **à confirmer par lecture BROM** |

La certification FCC associe explicitement **MobiWire NIKITI** et **Altice F2**, et un rapport de certification donne `Hardware Version: V01` et `Software Version: ELKI_DS_L_V01.2_181106_MP`.

Un ancien journal d’outil de maintenance pour **F2 NIKITI / Altice** identifie le CPU comme **MT6260** et montre le même identifiant USB de boot `VID_0E8D&PID_0003`. C’est une forte indication, mais le CPU de **cet exemplaire précis** doit encore être confirmé par lecture.

## 3. Point très important sur le lecteur audio

Le manuel du NIKITI / Altice F2 documente un **Lecteur audio / Audio player** dans le menu multimédia. Il indique notamment :

- lecture des fichiers audio depuis le téléphone ou la carte mémoire ;
- lecture/pause avec la touche OK ;
- morceau précédent/suivant avec gauche/droite ;
- volume avec `*` et `#` ;
- liste de lecture ;
- répétition, aléatoire et lecture en arrière-plan.

Conséquence : si le téléphone actuel n’affiche pas ce lecteur, il est possible que le firmware installé soit une variante opérateur différente, que des ressources soient absentes/corrompues, ou que la version actuellement présente ne soit pas celle documentée pour le NIKITI/Altice F2.

La cible prioritaire sera donc une **ROM stock exacte et vérifiée**, pas une ROM générique « MobiWire F2 ».

## 4. Ce qui a déjà été fait

### Pilote et identification USB

Windows a d’abord présenté le téléphone comme périphérique inconnu avec :

```text
USB\VID_0E8D&PID_0003
```

Le pilote MediaTek proposé par Windows Update a ensuite été installé. Le téléphone a été vu comme :

```text
MediaTek USB Port (COM3)
```

Le port COM est toutefois très bref : après quelques secondes, le téléphone bascule vers une autre personnalité USB.

### Changement de personnalité USB observé

UsbDk a permis de voir la séquence suivante :

```text
0E8D:0003
```

puis :

```text
0E8D:0002
```

Le premier état correspond au mode de boot MediaTek recherché. Le second correspond à l’état vers lequel le téléphone bascule ensuite.

### UsbDk

**UsbDk x64** a été installé et fonctionne. `UsbDkController.exe -n` a vu `0e8d:0003`, puis `0e8d:0002`.

### mtkclient

Un environnement Python virtuel a été créé et `mtkclient` fonctionne.

La commande `python .\mtk.py devices` affiche la base d’appareils interne de mtkclient ; le `Wiko Lenny 4` affiché n’est **pas** l’identification du téléphone.

La tentative avec `--vid/--pid` a déclenché une erreur interne :

```text
TypeError: 'int' object is not subscriptable
```

La détection standard de `mtkclient` n’a pas accroché le téléphone assez vite avant le basculement USB.

### Backend libusb de mtkclient

Un test direct du backend a confirmé :

```text
DETECTE: 0E8D:0003  class=0x02
Peripherique MediaTek disparu.
DETECTE: 0E8D:0002  class=0x00
```

C’est un résultat important : **Python + libusb + UsbDk voient bien le mode MediaTek 0E8D:0003**. Le problème n’est donc plus l’installation du pilote mais la capture et la communication pendant cette courte fenêtre.

## 5. Pourquoi l’ancien script n’affichait pas clairement « branchez maintenant »

L’ancien script était injecté dans Python au moyen d’un here-string PowerShell :

```powershell
@'
...
'@ | python -
```

Dans cette forme, l’affichage Python peut rester tamponné alors que le programme attend déjà le périphérique.

La version corrigée est fournie séparément sous le nom `identify_mobiwire.py`. Elle doit être lancée avec Python en mode non tamponné :

```powershell
python -u .\identify_mobiwire.py
```

Elle s’arrête volontairement avant la détection et demande d’appuyer sur **Entrée**. Ensuite seulement elle affiche :

```text
>>> BRANCHEZ LE CABLE USB MAINTENANT <<<
```

On ne branche le téléphone qu’à ce moment-là.

## 6. Prochaine étape immédiate : confirmer le CPU

Placer `identify_mobiwire.py` dans :

```text
C:\Users\verto\mtkclient
```

Puis :

```powershell
cd $env:USERPROFILE\mtkclient
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -u .\identify_mobiwire.py
```

Le téléphone doit rester **débranché** jusqu’à l’instruction affichée par le script.

Le script attend `0E8D:0003`, récupère l’interface USB bulk, effectue uniquement le handshake BROM MediaTek, puis lit en priorité `0x80000008`, utilisé pour l’identifiant CPU sur la famille visée. Il écrit aussi un journal :

```text
mobiwire_identification.txt
```

Résultat recherché :

```text
BB_CPU_ID = 0x6260
CPU IDENTIFIE : MediaTek MT6260
```

ou éventuellement :

```text
BB_CPU_ID = 0x6261
CPU IDENTIFIE : MediaTek MT6261
```

Le script ne contient aucune commande d’effacement ou d’écriture de flash.

## 7. Ce qu’il reste à faire avant tout flash

### Étape A — confirmer le SoC

Obtenir le `BB_CPU_ID` du téléphone réel.

### Étape B — sauvegarder avant de modifier

Avant toute écriture, effectuer un **dump complet** de la flash et conserver plusieurs copies. Il faudra préserver les zones qui peuvent contenir IMEI, calibration radio, paramètres NVRAM et données de production.

Aucune option de type `Format All`, `Erase NVRAM` ou équivalent ne doit être utilisée.

### Étape C — identifier la flash et la disposition mémoire

Après confirmation du CPU, déterminer le fabricant et la taille de la mémoire flash, les adresses de début/fin, le format du firmware et l’éventuelle nécessité d’un Download Agent spécifique.

### Étape D — analyser le firmware actuellement installé

Sur le dump sauvegardé, rechercher notamment :

```text
ELKI
NIKITI
ALTICE
F2
AUDIO
MP3
MULTIMEDIA
```

L’objectif est de déterminer la version réellement installée et de savoir si le lecteur audio existe déjà dans l’image mais est masqué/désactivé.

### Étape E — trouver une ROM compatible

Une ROM candidate ne sera retenue que si elle correspond au maximum à :

```text
MobiWire NIKITI / Altice F2
P/N 286547133
hardware V01
CPU confirmé
révision LCD/carte
dual SIM
```

La référence documentée à rechercher en priorité est :

```text
ELKI_DS_L_V01.2_181106_MP
```

À ce stade, aucune image de firmware publique exacte n’a encore été validée.

### Étape F — vérifier le lecteur audio avant flash

La documentation du téléphone indique que le firmware de cette famille doit proposer un lecteur audio. Une ROM stock NIKITI/F2 vérifiée sera donc préférée à une modification binaire artisanale.

### Étape G — flasher seulement après sauvegarde et vérification

Une fois la ROM correcte trouvée : comparer la taille et l’organisation avec le dump original, conserver calibration/IMEI, utiliser l’outil correspondant exactement au MT6260/MT6261 confirmé, et tester après restauration l’écran, le clavier, SIM1/SIM2, réseau, audio, Bluetooth, FM, microSD et lecteur audio.

## 8. Ce qu’il ne faut pas faire

Ne pas flasher une ROM Android ; ne pas utiliser une ROM seulement nommée « MobiWire F2 » ; ne pas utiliser SP Flash Tool au hasard avec un scatter d’un autre appareil ; ne pas formater la mémoire avant sauvegarde ; ne pas effacer NVRAM/IMEI/calibration ; ne pas écrire une image MT6260 tant que le CPU du téléphone réel n’est pas confirmé.

## 9. État du projet

**Déjà acquis :** famille NIKITI/Altice F2 identifiée, pilote MediaTek installé, `0E8D:0003` observé, COM3 observé, UsbDk fonctionnel, backend libusb de mtkclient fonctionnel, basculement `0003 -> 0002` caractérisé, et documentation confirmant l’existence d’un lecteur audio sur cette famille.

**Bloquants restants :** confirmer `BB_CPU_ID`, réaliser un dump complet et sûr, identifier la ROM actuellement installée, obtenir une ROM NIKITI/F2 exacte et vérifiée, puis seulement décider s’il faut restaurer une ROM stock ou modifier le firmware.

## 10. Sources techniques utiles

- FCC — NIKITI / Altice F2 : https://fccid.io/QPN-NIKITI
- Manuel NIKITI / Altice F2, incluant le lecteur audio : https://manuals.plus/m/6b8d291ae649edbbb4e2955ed2784ec8b7a3300e1cbd33d392f2f5ac4aa20c9a
- Rapport de certification `V01` / `ELKI_DS_L_V01.2_181106_MP` : https://fccid.io/QPN-NIKITI/RF-Exposure-Info/I20D00015-SAR01-4666225.pdf
- mtkclient — table USB : https://github.com/bkerler/mtkclient/blob/main/mtkclient/config/usb_ids.py
- mtkclient — backend USB : https://github.com/bkerler/mtkclient/blob/main/mtkclient/Library/Connection/usblib.py
- mediatek_flash — MT6260/MT6261 : https://github.com/ilyakurdyukov/mediatek_flash
- Exemple de journal de maintenance F2 NIKITI / Altice identifié MT6260 : https://www.nicagsm.com/unlock-f2-nikiti-altice-mt6260-nck-box/

---

### Conclusion

Le téléphone est très vraisemblablement un **MobiWire NIKITI / Altice F2 sur plateforme MediaTek MT6260**, mais l’identification CPU de l’exemplaire doit encore être confirmée. La documentation de cette famille inclut déjà un **lecteur audio**, donc le scénario recherché est probablement une **restauration vers le firmware stock correct** plutôt qu’un développement de lecteur audio personnalisé.

La prochaine action unique est : **exécuter `identify_mobiwire.py` avec `python -u`, obtenir `BB_CPU_ID`, puis ne rien flasher avant d’avoir réalisé une sauvegarde complète.**
