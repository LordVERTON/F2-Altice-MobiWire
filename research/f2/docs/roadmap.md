# Feuille de route

État courant : [REPRISE.md](../REPRISE.md).
Preuves : [S13.4H–J](reverse-engineering/s13-4h-j-dual-row-registration-repack-2026-10-05.md).
Ancienne roadmap conservée dans archive/roadmap-before-s13-4h-2026-10-05.md.

## Acquis

- [x] Dumps canoniques et repack ALICE byte-perfect.
- [x] Frontend Audio natif, callback 0x8928 -> 1033D841.
- [x] Primitives matérielles sacrificielles S12.10B7 et harness S13.3 historique.
- [x] S13.4D–G : vrai stub Image, veneers ARM et ambiguïté 0x8313 / 0x8321.
- [x] S13.4H : candidat D double-row, huit octets logiques.
- [x] S13.4I : registration idempotente, 1728 cas d'émulation bornée PASS.
- [x] S13.4J : recompression originale exacte et repack expérimental D validé.

## Gate actuel — empreinte physique

D change 384255 octets sur 96 secteurs (0x04C000 et 0x0DF000..0x13DFFF).
Il n'est pas compatible avec le harness one-sector. Aucun write autorisé.

- [ ] S13.4K : audit offline d'une route ALICE équivalente à plus faible empreinte,
  à partir du fallback resolver 1034C806..1034C80E ; comparer au D exact.
- [ ] Préserver le resolver dynamique et tous les IDs hors Image.
- [ ] Prouver le rôle et les effets du nouveau chemin avant sélection.
- [ ] Si D reste choisi : plan explicite de reprise multi-secteur, aucun script
  de flash générique ni extension automatique du writer S13.3.
- [ ] Avant toute nouvelle phase matérielle : clarifier puis vérifier l'état
  restauré actuel par un gate D6 séparé, préparer des rollbacks frais exacts.
- [ ] Après autorisation matérielle séparée seulement : mutation bornée,
  vérification dans une nouvelle session, puis test fonctionnel.

## Fonctionnel encore à démontrer

- [ ] Activation Audio depuis l'action Image Viewer réelle.
- [ ] Effets des appels répétés, retours UI et interactions avec les deux alias.
- [ ] Sélection et lecture MP3 ; Play / Pause / Resume / Stop.

## Invariants

Aucun whole-image flash, aucun generic writeflash()/0x62, aucune écriture
>=0x2C0000. Fresh read avant mutation et vérification séparée après ; rollback
exact. Une image construite depuis le dump canonique n'est pas une baseline live.
L'ancien hook S13.2A n'a pas produit l'activation Audio attendue.
