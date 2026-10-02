# Continuité de la recherche F2

Pour toute recherche ou modification dans ce sous-projet, lire d'abord
`REPRISE.md`. C'est l'unique état courant; les autres dossiers servent de
preuves techniques ou d'archives.

Mettre à jour REPRISE avant une commande longue, après un résultat significatif
et avant de terminer. Indiquer la dernière action validée, l'action/commande
en cours, les artefacts attendus et la prochaine action exacte. Consigner les
résultats au fil de l'eau dans `docs/JOURNAL.md`, avec liens vers les notes
techniques séparées. Suivre `docs/ORGANISATION.md`.

Ne pas traiter une ancienne conclusion comme actuelle si REPRISE la remplace.
La phase actuelle est hors ligne : aucun flash, écriture appareil ou changement
de pilote n'est nécessaire pour l'analyse statique.

## Current hardware safety checkpoint — S12.10B7

S12.10B7 has validated on the real owned phone:

- D6 READ
- D5 WRITE
- NOR erase path
- recovery
- restore

Sacrificial target:

`0x2A0000..0x2A0FFF`

This does NOT authorize generic or whole-image flashing.

Future firmware mutation rules:

- exact 4 KiB sector manifest
- fresh D6 read before every target-sector mutation
- exact rollback bytes
- D3+D5 only
- D6 verification after mutation
- no target `>= 0x2C0000`
- never use generic mtkclient `writeflash()` / `0x62`

Active phase:

S13 — expose / launch the already-confirmed native Audio Player:

`0x8928 → 0x1033D841`
