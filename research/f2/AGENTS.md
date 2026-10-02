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
<!-- CURRENT-S13.3A-2026-10-02 -->
## Current S13.3A checkpoint

S13.1 is closed. S13.2A/B/C and S13.3A are PASS.

Current target:

- sector `0x249000..0x249FFF`
- BEFORE SHA `dc8cc6b5be54d1554d71d60539f10a8077a375a3d7ddf92efe6149610ecffb1b`
- AFTER SHA `29a21401b84442554dc051edd16ec561bbd842e01e048344e30ca547f78bb7f9`
- actual changed range `0x249AEF..0x249B13`
- 37 physical changed bytes
- erase required

Proven writer reference:

`research/f2/scripts/hardware/reference/s12_10b7_sacrificial_gate_v4_reference.py`

SHA256:

`255a00f49b99c72871cd3a9ca9e66f4d5284590d9844ff58c3c7c5796e9616eb`

Do not rebuild the D3/D5 protocol. Derive S13.3 from this exact reference.

Next action is S13.3B local/dry-run writer construction and static safety audit.
Do not write firmware until S13.3B/C are PASS.
