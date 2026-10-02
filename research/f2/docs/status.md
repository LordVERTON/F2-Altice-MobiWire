# État courant

Le point de reprise unique est [REPRISE.md](../REPRISE.md).

## Checkpoint actuel — 2026-10-02

S12.10B7 est terminé sur le téléphone réel.

- D6 READ : HARDWARE PASS
- D5 WRITE : HARDWARE PASS
- erase path : HARDWARE PASS
- recovery : HARDWARE PASS
- restore : HARDWARE PASS
- sacrificial gate : PASS

Détail :

[S12.10B7 hardware write gate](reverse-engineering/s12-10b7-hardware-write-gate-2026-10-02.md)

Le secteur `0x2A0000..0x2A0FFF` a été restauré exactement à son état FF initial.

Un nouveau dump complet 4 MiB n'est pas requis avant S13 :

- dump2/dump3 sont déjà bit-identiques ;
- deux readbacks live A/B complets et indépendants sont également identiques.

## Étape active

S13 : exposition / lancement du frontend Audio Player natif déjà confirmé.

Registration :

`0x8928 → 0x1033D841`

Il ne faut pas refaire la recherche « frontend présent ou absent ».

Avant toute écriture firmware :

- calculer les secteurs 4 KiB modifiés ;
- refuser toute cible `>= 0x2C0000` ;
- faire un D6 frais de chaque secteur cible ;
- sauvegarder ses octets originaux ;
- écrire uniquement par D3+D5 ;
- vérifier par D6 après écriture.

Pas de generic `writeflash()` / `0x62`.
Pas de flash complet.
