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

## 2026-10-01 - S12.6 valide

Relance du builder avec invariant corrige : PASS complet.

ALICE :
- stable stream `0x105A6E`
- 10999 mappings stables
- dernier groupe original `0x157B80`
- `0x34` octets reels + `0x4C` ancien padding
- dictionnaire conserve

Audit du candidat :
- changed bytes `62429`
- diff ranges `792`
- unauthorized changed bytes `0`
- VIVA file_len PASS
- ALICE extract PASS
- ALICE self-decode PASS
- exhaustive diff allow-list PASS

Hashes :
- candidate dump
  `15299fe668390f5d14dc110b5c1f9444fad2c9be09c2ee86a245ad3c853c5298`
- candidate VIVA
  `f2f7edad0f2e20160df81d3b4bec37d8f308f0d78aada6ba1480deac98dd4a2a`

Statut :
OFFLINE CANDIDATE - NOT FLASH APPROVED.

Prochain gate :
audit independant, recovery, read-back et restauration avant toute ecriture
telephone.

<!-- JOURNAL-S12.10B7-2026-10-02 -->

## 2026-10-02 — S12.10B7 hardware write / erase / restore : PASS

Gate physique terminé sur l'Altice F2 réel.

Cible :

`0x2A0000..0x2A0FFF`

Chemin testé :

D3 SetMemBlock
→ D5 Sequential Erase / WRITE
→ recovery
→ ProcessInfo
→ power-cycle
→ D6 verification

Le generic `writeflash()` / `0x62` n'a jamais été utilisé.

Séquence validée :

1. FF → AA
2. D6 : AA exact
3. AA → 55
4. D6 : 55 exact
5. restore → FF
6. D6 : FF initial exact
7. guard `0x280000..0x2BFFFF` inchangé hors cible

Hashes :

- FF `f47a8ec3e9aff2318d896942282ad4fe37d6391c82914f54a5da8a37de1300c6`
- AA `c622005493c4cb75f3e08eda4cc0bfe172e2c5eeca661ec4908c5490fc3d6994`
- 55 `0561079e4fe3390bc1d8bb706edb7d80243eeca7ddf876cefbaa8c1684db80c3`
- guard `caac124c9e376fdf13f854555937eff52ae28f4872f71d3216c6b773693de3e4`

Une tentative de restore a subi une déconnexion USB pendant la prélecture D6,
avant D3/D5 ; aucune mutation n'a eu lieu pendant cette tentative.

Le retry après cycle batterie a réussi.

Baselines déjà disponibles :

- dump2/dump3 :
  `2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922`
- live A/B :
  `c571f3852f4a70d1845cc79abaa95007f8826ec858a1db1ad501c4a2a7b35ce6`

Un nouveau dump 4 MiB n'est donc pas requis pour démarrer S13.

Suite :

S13 = exposition / lancement du frontend Audio Player natif déjà confirmé :

`0x8928 → 0x1033D841`
<!-- JOURNAL-S13.3A-2026-10-02 -->

## 2026-10-02 â€” S13.3A : import/audit du harness hardware Ã©prouvÃ©

Le harness S12.10B7 v4 ayant passÃ© le gate sacrificiel rÃ©el a Ã©tÃ© copiÃ© dans le
repo comme rÃ©fÃ©rence :

`research/f2/scripts/hardware/reference/s12_10b7_sacrificial_gate_v4_reference.py`

Source :

`C:\Users\verto\mtkclient\research\f2\scripts\hardware\s12_10b7_sacrificial_gate.py`

SHA256 source/copie :

`255a00f49b99c72871cd3a9ca9e66f4d5284590d9844ff58c3c7c5796e9616eb`

La copie a Ã©tÃ© commitÃ©e/pushÃ©e dans le commit :

`5c7f83bbf01fa425a1a768dd5c49dbdc14577414`

Audit statique :

- `d6_read_4k_native()` confirmÃ©
- `d6_read_sector_range()` confirmÃ©
- `d3_set_memblock()` confirmÃ©
- `d5_write_until_processinfo()` confirmÃ©
- GFH VIVA `0x0108`
- D5 Sequential Erase
- exactement une frame 4 KiB
- checksum additif 16 bits
- recovery ACK
- ProcessInfo ACK
- arrÃªt volontaire avant le final image checksum verifier
- mutation verrouillÃ©e par `--execute` + token exact
- generic `writeflash()/0x62` absent

La fonction `mutate()` de cette rÃ©fÃ©rence rÃ©alise dÃ©jÃ  le pattern de sÃ©curitÃ©
requis : fresh D6 dans la mÃªme session, validation exacte de l'Ã©tat attendu,
puis D3 et D5.

S13.3A est restÃ© local/read-only : harness non exÃ©cutÃ©, tÃ©lÃ©phone non accÃ©dÃ©,
aucun D3/D5, erase ou write.

Prochaine Ã©tape : S13.3B, dÃ©river un writer strictement limitÃ© au seul secteur
firmware `0x249000..0x249FFF`, avec BEFORE/AFTER hardcodÃ©s et dry-run/local audit
avant toute exÃ©cution matÃ©rielle.

## 2026-10-05 — S13.4H/I/J : alias double-row, idempotence et empreinte physique

Notion technique/last update confirment S13.4G ; REPRISE et roadmap locaux
étaient restés à S13.3A. Anciennes versions archivées, état courant remplacé.

S13.4H fourni exécuté sans modification : PASS structurel, candidat D logique
huit octets. S13.4I ajouté : émulation des instructions natives, sans mocks,
1728 cas PASS sur l'idempotence de l'état global de registration. Correction :
le core H débordait sur des fonctions adjacentes et le dispatcher contient deux
appels distincts (registration, puis init conditionnel).

S13.4J ajouté : recompression canonique byte-perfect, D roundtrip exact, BOOT
canonique exact. Stream réduit de 76 octets ; VIVA/ALICE et adresses conservés.
Résultat : 384255 octets changés, 96 secteurs. L'ancien writer one-sector ne
s'applique pas. Image expérimentale canonique NON FLASHABLE, aucun accès appareil.

Écart documentaire matériel : log local restore jusqu'à ProcessInfo, mais
verify_restored_required=true et aucune vérification séparée trouvée, alors
que Notion dit encore AFTER. Ne pas présumer l'état live.

Détails, hashes, limites et commandes :
[Audit S13.4H–J](reverse-engineering/s13-4h-j-dual-row-registration-repack-2026-10-05.md).
Prochain gate : S13.4K offline, réduction/comparaison de l'empreinte physique.
HARDWARE WRITE AUTHORIZED: NO.

Synchronisation Notion : nouveau checkpoint H–J inséré dans last update,
documentation technique et page projet ; historique conservé. Scripts compilés
avec py_compile ; diff Git vérifié sans erreur. Aucun commit/push effectué.
