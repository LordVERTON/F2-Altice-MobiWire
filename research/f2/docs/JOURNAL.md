# Journal de recherche

L'état à reprendre est [REPRISE.md](../REPRISE.md). Les entrées ci-dessous
conservent les résultats et changements de direction.

## 2026-09-29 — S01 terminé : identité du codec et mapping

34 fonctions MP3 correspondent à la bibliothèque SDK; appels Init/Decode
depuis ALICE et callbacks DAF vérifiés. Correction de la base ALICE à
`0x1024EC00`. Nouvelle analyse `Altice_MP3_Runtime_20260929`.
Scripts `match_mp3_library.py` et `audit_mp3_bridge.py` exécutés avec succès.
Hash du dump original inchangé. Lecture SD et UI inconnues.
[Preuves](reverse-engineering/mp3-decoder-verdict-2026-09-29.md).

## 2026-09-29 — S02 commencé : documentation et ouverture DAF

À la demande de l'utilisateur, création d'un point unique de reprise et de
checkpoints réguliers; anciens états préservés dans les snapshots.
Hypothèse à examiner : un consommateur de la table parser/décodeur révèle
`DAF_Open` et la gestion du module DCM. Aucun accès téléphone prévu.

Checkpoint : DAF_Open `0x10358254` retrouvé par adressage `base+0x44/+0x54`,
et Open média `0x1028D230` reliée au constructeur `0x10303BE0`. Mapping DPMGR
`3 → 0x010C` identifié. Exports `daf_open_runtime.txt` et
`daf_dispatch_runtime.txt` terminés. Limite : helper switch ROM non mappé,
décompilation partielle de Open média; poursuivre avec octets et source témoin.

## 2026-09-29 — S02 consignée et vérifiée, prochain checkpoint S03

Reconnaissance `.MP3 → 5` retrouvée à `0xF02ADD64`. Open média est reliée au
constructeur; DAF_Open construit les tables retrouvées en S01. Mapping région
3 vers module `0x010C`, wrappers DCM et callback de décompression LZMA identifiés.
La sélection format 5 dans le switch reste une inférence étayée : helper ROM
`0x70008C68` absent des images. Pas de lecture sur téléphone démontrée.

`audit_daf_open.py` exécuté : PASS, 25 instructions, hashes, veneers, chaînes
et tables. Trois exports Ghidra terminés, aucune commande longue laissée active.
Ghidra a nécessité l'accès autorisé à ses préférences Java hors workspace;
les programmes existants ont été ouverts en lecture seule.

[Note technique S02](reverse-engineering/daf-open-dispatch-2026-09-29.md).
Suite S03 : callback Play `0x1028D394` et pointeur `MHdl.Play` au littéral
`0x10358334`, puis rechargement DCM et sortie audio. REPRISE actualisé.

Contrôle de fin : audits S01 et S02 relancés avec succès; 23 liens des
documents courants vérifiés; UTF-8 contrôlé; SHA-256 du dump 2 inchangé.
Consignes de continuité ajoutées aux AGENTS.md racine et F2 pour les reprises.

## 2026-09-29 — Synchronisation Notion demandée (« update ntn »)

Ajout d'une synthèse du checkpoint en tête des pages
[projet](https://www.notion.so/3e9173c57e048076b559c63e7a2bd708),
[documentation technique](https://www.notion.so/3ea173c57e0481e383b1eadbe67ad997)
et [last update](https://www.notion.so/3e9173c57e048093a8e3ce8c03b398ac).
S01/S02, limites du dispatch et prochaine action S03 explicités.

Écart constaté : Notion annonçait déjà MHdl.Play à 0x1035FB00, rechargement
DAF et trajet AudioDrain/PcmSink, ainsi qu'une stratégie de frontend injecté.
Ces notes sont conservées intégralement sous un avertissement historique;
elles restent à confronter aux preuves locales. REPRISE reste l'état courant.
Les trois pages ont été relues après écriture et leur historique vérifié.
Aucun audit binaire relancé, aucune analyse ou commande longue lancée.
Suite inchangée : S03, Play 0x1028D394 et littéral MHdl.Play 0x10358334.

## 2026-09-29 — S09.7 en cours : construction des chemins

La consigne utilisateur complète remplace la priorité de reprise S03 par S09.7.
Inspection préalable des changements Git : research/ est non suivi; changements
préexistants conservés. Commande : `.venv/Scripts/python.exe
research/f2/scripts/analysis/analyze_audio_paths.py`.

Audit PASS : dump2/dump3 identiques, hashes VIVA/ALICE/ZIMAGE/BOOT conformes,
VIVA du package égal à la tranche physique du dump. 19 ancrages d'octets,
31 chaînes et 159 références candidates. Rapport audio_path_audit.json,
audio_path_evidence.txt et audio_drive_contexts.txt sous alice_reports/.

Correction : les chaînes annoncées sont deux objets adjacents, `%c:\` ASCII
et `Audios\` UTF-16. Flux réel ADR→formatter 0xF022DC34→concat 0xF02E2A08.
Drive courant à 0xF00AD8A3; getter 0xF02B8FE8 vérifie la préférence à
0xF00AD89D et utilise le service drive 0xF0229230 en repli. Table native
0xF00EF090, init 0x10300DA4, index→lettre 0x102F1084 retrouvés dans Altice.
Les noms SDK et Phone/Memory card restent distincts des preuves numériques.
Suite : audits ABI/formats et rapport détaillé, POC_SPEC sans injection.

## 2026-09-29 — S09.7 consignée, spécification POC créée

Commandes : analyze_audio_paths.py, audit_minimal_player_abi.py,
audit_daf_open.py, audit_mp3_bridge.py avec .venv/Scripts/python.exe.
Résultats : PASS chemins (19 ancrages), PASS ABI (31 ancrages, 9 callbacks,
12 suffixes, 7 cas de dispatch inférés), PASS S02 (25 instructions), PASS S01.
Deux contrôles négatifs en mémoire rejettent respectivement un ZIMAGE altéré
par son hash et une instruction modifiée à 0xF02B3C56. Aucun octet de fichier
firmware modifié. Les limitations anciennes du JSON S01 décrivent son périmètre;
S02/S09 constituent les preuves complémentaires plus récentes.

Artefacts durables :
[rapport S09](reverse-engineering/s09-file-path-and-minimal-player-2026-09-29.md)
et [POC_SPEC](reverse-engineering/POC_SPEC.md). Nouveaux scripts sous analysis/;
sorties ABI minimal_player_abi.json et minimal_player_abi_disasm.txt.
REPRISE, roadmap, status et index EVIDENCE actualisés; index antérieurs et
checkpoint intermédiaire conservés dans archive/pre-s09-final-2026-09-29/.
Le rapport brut filetype_mp3_dispatch.txt est conservé, indexé comme historique.

Conclusion : racine UTF-16 produite par formatter natif puis suffixe concaténé;
drive courant issu d'une préférence montée ou d'un repli FS_GetDrive-like.
Table native initialisée avec (8,1,1), (8,2,1), (0x10,1,1); index→lettre
retrouvé. Association des labels Phone/Memory Card encore inférée SDK;
lettres montées non observées, aucun hardcoding.

Limite POC découverte : callback NULL sélectionne une autre construction DAF.
Stop nécessite MHdl; Destroy ne ferme pas automatiquement le média.
Le POC reste une spécification non exécutable, sans cave/hook choisis.
Prochaine action unique : 0xF02E1B00 → 0xF0297DC4, objets créés pour Play
0x1035FB00 puis fermeture. Aucun Ghidra, processus long ou accès appareil lancé.

Git contrôlé : git diff --stat, git diff --check, git diff, git status --short.
Stat suivie : 2 fichiers, 8 insertions (.gitignore/README préexistants).
research/ est non suivi : les nouvelles preuves ne figurent donc pas dans
git diff --stat. Aucun stage, commit ni suppression de changement utilisateur.

Contrôle final documentaire : UTF-8 valide, 30 liens locaux valides; SHA-256
du dump2 relu en fin de travail et inchangé. La première commande de contrôle
des liens a échoué sur le quoting PowerShell; relance par entrée standard Python
réussie, sans impact sur les fichiers firmware.

## 2026-10-01 - Synchronisation S12.3-S12.6

S12.3 valide le repack ALICE_2 byte-perfect et une extension controlee
`+0x1000`.

S12.4/S12.4b demontrent offline que le preset LZMA historique doit conserver
la fenetre `0x1024EC00..0x103A67B4`.

S12.5 valide la matrice runtime et la nouvelle geometrie physique :
ALICE runtime `0x158BB4`, VIVA `file_len=0x24A23C`, fin `0x296448`,
headroom `0x29BB8`.

S12.6 construit le premier candidat offline avec allow-list exhaustive.
Premier run : reconstruction ALICE correcte mais assertion trop stricte sur le
stream compresse. U finit a `0x157BB4`, dans le dernier groupe commencant a
`0x157B80`, avec `0x34` octets reels et `0x4C` octets de padding.

Invariant corrige : 10999 mappings stables; dernier mapping original et
sentinelle autorises a changer.

Aucun candidat final n'a ete produit par ce premier run.

Notion synchronise le 1 octobre 2026.

Prochaine action : relancer S12.6 corrige et exiger zero difference hors
allow-list.

Aucun flash.

