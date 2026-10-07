# Reprise — Altice F2 / MobiWire

## 2026-10-07 — Orchestrateur de revue offline installé

Construction de l'infrastructure uniquement, sans reprise des audits historiques.
Notion vérifié : A.56 PROCESSED ; A.57 existe, QUEUED/PENDING. Worker inchangé.
Implémenté : orchestrateur déterministe, sortie Codex structurée, journal de reprise,
claim local exclusif, publication idempotente, arrêt hardware persistant.
Validation : 29 tests orchestrateur et 11 tests runner PASS, strictement offline.
Artefacts et commandes : [bridge/README.md](automation/bridge/README.md).
Infrastructure publiée dans c23f12f ; tâche F2 Research Orchestrator installée,
première passe exit 0, aucune revue en attente, aucun appel Codex.
Preflight Notion/Codex et preuves smoke/rejet/GitHub du worker : PASS.
Prochaine action automatique : le worker exécute le job QUEUED courant, puis
l'orchestrateur traite le plus ancien COMPLETED/PENDING. Notion reste l'autorité.
Aucun accès matériel autorisé ; arrêt obligatoire au premier hardware gate.

## 2026-10-07 — Installation de l'automatisation locale

Branche `automate-research` créée depuis `6bec2ed4f42887d1ae2f7eec63790a66ab2ad7a9`,
après synchronisation de `s12-alice-extension`, puis poussée sur `github`.
Runner v4 corrigé pour Windows PowerShell, installé et validé : smoke PASS,
exit 0, quatre artefacts suivis et poussés automatiquement dans `5247018`.
Mode continu sans job validé, puis arrêté par Ctrl+C. Nettoyage d'installation
terminé ; aucune recherche supprimée. Détails, erreurs initiales, corrections,
hashes et commande canonique : [automation/README.md](automation/README.md).
Installation et tests terminés ; documentation et runner corrigé archivés avec
ce checkpoint. Aucun runner actif. Prochaine action après livraison :
attendre un nouveau job offline explicitement demandé et relu.
La recherche F2 et les anciennes demandes matérielles ci-dessous sont suspendues
pour cette tâche. Aucun audit A.51, téléphone, USB, COM, flash, erase ou repack.

## 2026-10-05 — S13.4H/I/J terminés, candidat D offline uniquement

Objectif : exposer le lecteur Audio natif depuis Image Viewer.
Source détaillée : [audit H–J](docs/reverse-engineering/s13-4h-j-dual-row-registration-repack-2026-10-05.md).

- Notion technique / last update relus : S13.4G confirmé ; l'ancien état local
  S13.3A est archivé et remplacé par ce checkpoint.
- H fourni : PASS structurel, alias 0x8313 + 0x8321 -> 1033D841 ; exactement
  huit octets ZIMAGE modifiés. Trigger unique toujours non identifié.
- I ajouté ici : 1728 cas d'émulation des instructions natives PASS ; état
  global de registration idempotent. Ne prouve pas le double lancement UI.
- J ajouté ici : canonique recompressé byte-perfect ; D exact roundtrip et
  BOOT exact decode ; géométrie VIVA et ALICE canonique inchangées.
- Résultat physique : 384255 octets modifiés, 96 secteurs : 0x04C000 et
  0x0DF000..0x13DFFF. Le harness S13.3 one-sector est INAPPLICABLE.

Hashes :
- D logique : 778b89f149e0600dcdca38b8f878fa046fdbffa1ddbaec645af70f6b56324078
- image expérimentale : a2bc044a36db4210877d57a5dc3341be8c76d2a49c3c435371ce4f5de0af1cc6

Artefacts : work/reports/s13_4h_dual_row_alias_idempotence_audit.txt,
work/reports/s13_4i_registration_state_audit.{txt,json},
work/reports/s13_4j_zimage_dual_row_repack.txt et work/candidates/s13_4j/manifest.json.
Scripts reproductibles dans scripts/analysis/ et scripts/patching/.

État appareil INCONNU ici : Notion dit ancien AFTER après boot stable, mais
un log local et restore_protocol_complete.json indiquent ensuite restore
jusqu'à ProcessInfo, avec verify_restored_required=true. Aucune vérification
D6 séparée de restauration trouvée. Aucun accès téléphone dans cette session.
L'image J est basée sur dump2 canonique, pas sur une baseline live actuelle.

Prochaine action : S13.4K OFFLINE, réduire/comparer l'empreinte physique en
étudiant une route ALICE au niveau du fallback resolver 1034C806..1034C80E
vers le callback Audio complet ; préserver lookup dynamique et IDs non ciblés.
Ne pas reprendre le hook inefficace S13.2A. Si D reste choisi, préparer un
plan de reprise multi-secteur distinct avant toute étape matérielle.

Aucune commande longue active. Lecture MP3 / activation UI non démontrées.
HARDWARE WRITE AUTHORIZED: NO. Aucun flash, aucun accès matériel autorisé ici.

Documentation Notion H–J synchronisée sur les trois pages de suivi.
Vérifications locales : H et I exécutés avec succès, J exact roundtrip,
py_compile et git diff --check PASS. Modifications locales non commitées.

## Nouvelle demande utilisateur — installation du lecteur (2026-10-05)

L'utilisateur demande explicitement de préparer la modification et l'injection
sur son téléphone. Cette demande remplace l'absence générale d'autorisation
précédente ; aucun candidat précis n'est encore validé pour écriture.
EN COURS : choix du parcours UI (Photos remplacé ou nouvelle entrée), audit
S13.4K pour réduire l'empreinte ; matériel Windows non détecté au premier inventaire.
Aucune écriture ni connexion DA lancée. Préconditions techniques et rollback
restent obligatoires. Prochaine action : valider la route et les dépendances
LZMA avant construire un manifeste matériel concret.

Clarification utilisateur : CONSERVER PHOTOS et AJOUTER une entrée Audio.
D et la redirection de K sont abandonnés pour installation (preuves historiques
conservées). EN COURS : S14.1 audit du registre de menus, enfants Multimedia,
ressources et handler natif 0x8928. Aucun payload conforme encore construit.
Sorties attendues : audit read-only, note et prochaine étape basée sur preuves.
