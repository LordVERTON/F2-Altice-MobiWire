# Feuille de route

Le point de reprise unique est [REPRISE.md](../REPRISE.md).

## Acquis

- [x] dumps physiques 4 MiB
- [x] dump2 == dump3
- [x] deux readbacks live A/B byte-identical
- [x] extraction/repack ALICE
- [x] backend MP3 / DAF
- [x] aud_player_media ABI
- [x] File Manager / Audios path
- [x] frontend Audio Player natif
- [x] registration `0x8928 → 0x1033D841`
- [x] Image Viewer comme contrôle positif
- [x] candidat S12.8E live-preserving
- [x] D6 READ hardware
- [x] D5 WRITE hardware
- [x] erase path hardware
- [x] recovery hardware
- [x] restore hardware
- [x] S12.10B7 sacrificial gate PASS

## Étape active — S13

Objectif :

exposer / lancer l'Audio Player natif déjà compilé.

Chaîne :

`0x8928`
→ `0x1033D841`
→ `0x1033D840`
→ `0x1033E815`
→ `0x1033F83C`

Contrôle positif :

`0x8313 / 0x8321 → F02F3F85`

### S13.1

Identifier le plus petit point de raccordement permettant d'exposer ou lancer
le player natif.

### S13.2

Construire le candidat offline reproductible.

Exiger :

- ALICE/VIVA valide
- diff exact
- aucune modification `>= 0x2C0000`
- manifest exact des secteurs 4 KiB

### S13.3 — preflight

Pour chaque secteur cible :

- D6 frais
- comparaison avec l'original attendu
- sauvegarde rollback 4096 octets
- SHA original
- SHA candidat
- abort sur toute différence

### S13.4 — écriture

Uniquement :

D3
→ D5
→ recovery
→ ProcessInfo

Interdit :

- generic `writeflash()` / `0x62`
- flash 4 MiB complet
- SAV complet
- cible `>= 0x2C0000`

### S13.5 — validation

- power-cycle
- D6 readback des secteurs modifiés
- comparaison au candidat
- boot
- lancement Audio Player
- test MP3 SD
- Play/Pause/Resume/Stop
- conserver rollback jusqu'à validation

## Fallback

Une UI custom ne sera envisagée que si le frontend natif confirmé est
inutilisable sur hardware.
