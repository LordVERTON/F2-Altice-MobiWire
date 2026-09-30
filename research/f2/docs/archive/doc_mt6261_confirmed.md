# Dossier de récupération — MobiWire NIKITI / Altice F2

_Mise à jour : 28 septembre 2026_

## Résultat décisif

Le téléphone a maintenant été interrogé directement depuis son Boot ROM MediaTek via WinUSB.

Résultat lu sur l'appareil :

```text
BB_CPU_ID = 0x6261
BB_CPU_HW = 0xCB01
BB_CPU_SW = 0x0001
BB_CPU_SB = 0x8000
```

**Identification confirmée : MediaTek MT6261.**

Cette lecture directe de la BROM de l'appareil prime sur les anciens journaux trouvés sur Internet qui associaient certains F2/NIKITI au MT6260.

## Chaîne USB confirmée

```text
USB VID:PID   : 0E8D:0003
Classe USB    : 0x02
Configuration : 1
Interfaces    : 2
Interface     : 0
Bulk OUT      : 0x01
Bulk IN       : 0x81
Pilote Windows: WinUSB
```

Handshake BROM obtenu :

```text
A0 -> 5F
0A -> F5
50 -> AF
05 -> FA
```

Aucune zone de flash n'a été écrite ou effacée pendant cette identification.

## Modèle / famille

Les documents réglementaires associent le produit à :

```text
MobiWire NIKITI / Altice F2
Hardware Version : V01
Software Version : ELKI_DS_L_V01.2_181106_MP
FCC ID           : QPN-NIKITI
```

Le manuel de cette famille documente déjà un **lecteur audio**.

Conséquence : l'objectif prioritaire est de retrouver/restaurer une ROM stock NIKITI/F2 compatible, plutôt que d'essayer d'ajouter un APK ou une application Android.

## Correction importante

Une ancienne piste Internet indiquait MT6260 pour un F2 NIKITI.

Pour cet exemplaire précis, cette piste est maintenant écartée : le téléphone lui-même renvoie `BB_CPU_ID = 0x6261`.

Toute future ROM devra donc être compatible **MT6261**, ainsi qu'avec la carte, l'écran et les périphériques de cette variante.

## Étape suivante : sauvegarde avant tout flash

Avant toute écriture, il faut :

1. déterminer la taille réelle de la NOR/SPI flash ;
2. effectuer un dump complet ;
3. calculer SHA-256 du dump ;
4. conserver au moins deux copies ;
5. rechercher dans le dump les chaînes de version/plateforme ;
6. préserver IMEI, calibration, NVRAM et données de production.

Le script `probe_mobiwire_flash.py` est destiné à l'étape 1.

Il ne contient aucune commande d'effacement ou d'écriture de flash. Il utilise seulement :
- le handshake BROM ;
- des lectures mémoire ;
- la désactivation volatile du watchdog ;
- le mapping volatile de la NOR en mémoire.

## Après le probe

Une fois la taille de flash déterminée, produire **deux dumps indépendants** de la totalité de la NOR et vérifier que leurs SHA-256 sont identiques.

Aucune ROM candidate ne devra être écrite avant cette double sauvegarde.

## Recherche firmware

Référence logicielle documentée à rechercher en priorité :

```text
ELKI_DS_L_V01.2_181106_MP
```

La recherche publique effectuée jusqu'ici confirme cette référence dans les documents de certification mais n'a pas encore fourni une image de firmware publique et vérifiée.

## Sources

- FCC NIKITI / Altice F2 : https://fccid.io/QPN-NIKITI
- Rapport logiciel/hardware V01 : https://fccid.io/QPN-NIKITI/RF-Exposure-Info/I20D00015-SAR01-4666225.pdf
- Manuel NIKITI / Altice F2 : https://manuals.plus/m/6b8d291ae649edbbb4e2955ed2784ec8b7a3300e1cbd33d392f2f5ac4aa20c9a
- mtkclient : https://github.com/bkerler/mtkclient
- mediatek_flash MT6260/MT6261 : https://github.com/ilyakurdyukov/mediatek_flash
