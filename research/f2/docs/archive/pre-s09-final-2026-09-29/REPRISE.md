# Reprise de la recherche — MobiWire NIKITI / Altice F2

**Document à lire en premier à chaque reprise.** Mis à jour le 29 septembre 2026.
Ce fichier décrit uniquement l'état courant. Les preuves et détails sont dans
les dossiers techniques liés ci-dessous; l'historique ne remplace pas cet état.

## Objectif et périmètre

Lire un fichier MP3 de la carte SD sur le firmware installé
`ALTICE_F2_DS_V02.1_181023_MP` (MT6261), puis exposer une interface utilisable.
Recherche actuelle hors ligne sur sauvegardes. Aucun flash, écriture NVRAM ou
changement de pilote à effectuer dans cette phase.

## État validé

| Élément | Conclusion |
|---|---|
| Code MP3 | Présent : 34 fonctions identifiées par comparaison binaire |
| Composant DAF | Init/décodage, buffers et callbacks Start/Stop/Process retrouvés |
| Ouverture média | Callback Open relié au constructeur; ouverture fichier et reconnaissance `.MP3 → 5` vérifiées |
| DAF_Open / DCM | Fonction identifiée, tables parser/décodeur et mapping région 3 → module 0x010C retrouvés |
| Dispatch format 5 → DAF | Table et bloc d'appel cohérents; helper switch ROM non mappé, interprétation à confirmer |
| Lecture SD jusqu'à la sortie audio | Non démontrée |
| Interface Audio Player / lancement File Manager | Non démontrés |
| Menu observé | Image Viewer et FM Radio seulement |
| Patch / recovery d'écriture | Non prêts; aucun firmware modifié |

ALICE doit être analysée à **`0x1024EC00`**, base confirmée par la ROM et les
callbacks. Les anciennes adresses ALICE basées sur `0x101812C4` nécessitent une
translation `+0xCD93C`. Ne pas appliquer cette translation à ROM/ZIMAGE/DCM.

## Étape active — S09.7 : drive dynamique (EN COURS)

La consigne utilisateur complète du 29 septembre remplace la priorité S03
ci-dessous : suivre les XREF Altice de `%c:\Audios\` et de la playlist,
identifier la provenance du caractère de drive, puis préparer POC_SPEC.md.
Les acquis S08/S09 fournis sont à recouper avec les octets; le donor ne fait
pas preuve. Aucun patch ni accès téléphone. Analyse Capstone reproductible
prévue : `scripts/analysis/analyze_audio_paths.py`, sorties
`work/ghidra/alice_reports/audio_path_audit.json` et désassemblage associé.
Dernière action : audit chemins PASS (hashes, 19 ancrages d'octets, 31 chaînes,
159 XREF candidates). `%c:\` ASCII et suffixe `Audios\` UTF-16 sont séparés.
Formatter 0xF022DC34; concaténation 0xF02E2A08; drive courant RAM 0xF00AD8A3;
préférence 0xF00AD89D; sélection 0xF02B8FE8; service drive 0xF0229230.
Table drive 0xF00EF090 initialisée à 0x10300DA4; index→lettre 0x102F1084.
Les libellés Phone/Memory card restent une inférence SDK, pas une lettre fixe.
Prochaine action : figer audits ABI/formats, rapport S09 et spécification POC.

## Checkpoint antérieur — S03 : Play, rechargement DAF et sortie audio

**État : À DÉMARRER. S02 consignée et vérifiée dans les limites statiques.**
Lire le [dossier S02](docs/reverse-engineering/daf-open-dispatch-2026-09-29.md).
L'ouverture décharge la région DAF après construction : il faut établir son
rechargement avant décodage et le trajet des buffers jusqu'à la sortie.

Prochaine action concrète : décompiler le callback Play `0x1028D394`, lire le
pointeur `MHdl.Play` au littéral `0x10358334` de DAF_Open, puis suivre ses appels
DPMGR et sa construction des composants audio. Utiliser le projet runtime
ci-dessous, conserver l'export sous `alice_reports/daf_play_runtime.txt`.

Critère de fin : un chemin statique documenté relie Play au chargement DAF,
au traitement MP3 et au composant de sortie; toute partie non résolue reste
explicitement inconnue. Après cela, remonter vers le frontend utilisateur.

Question technique conservée : confirmer le helper switch ROM `0x70008C68`
ou ses conventions sans inventer son comportement. Le fichier MP3 est reconnu,
mais l'exécution du dispatch et la lecture sur appareil n'ont pas été testées.

## Reprendre après interruption

1. Lire ce fichier et la dernière entrée du [journal](docs/JOURNAL.md).
2. Lire uniquement le dossier technique de l'étape active et ses preuves.
3. Vérifier l'existence des artefacts indiqués et les processus encore actifs;
   ne pas supposer qu'une commande interrompue a terminé ou échoué.
4. Reprendre à « prochaine action concrète ». Mettre à jour ce fichier avant
   tout traitement long, après une preuve nouvelle et avant de terminer.
5. Ajouter au journal le résultat, les commandes/rapports et la suite exacte.

Dernière validation terminée : S02, audit de 25 instructions, hashes, veneers,
chaînes et tables réussi. Les trois exports `daf_open_runtime.txt`,
`daf_dispatch_runtime.txt` et `daf_file_dcm_runtime.txt` sont terminés.
**Aucune commande longue ni session Ghidra lancée par cette étape ne reste active.**
Les projets antérieurs et le dump original sont conservés.
Contrôle de fin : audits S01/S02 réussis, 23 liens des documents de reprise
vérifiés, encodage UTF-8 vérifié et SHA-256 du dump 2 inchangé.

## Artefacts utiles

Synchronisation documentaire du 29 septembre 2026 : les trois pages Notion
(projet, documentation technique et « last update ») reflètent ce checkpoint
en tête de page. Leurs anciennes conclusions S03 sont conservées comme pistes
à réconcilier, sans changer l'état S03 « à démarrer ». Voir le journal.
Aucune analyse ni commande longue lancée lors de cette synchronisation.

- Dossier de travail : `C:\Users\verto\mtkclient`.
- Python d'analyse : `.venv\Scripts\python.exe` (Capstone installé).
- Ghidra : `C:\Tools\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat`.
- Projet courant : `research/f2/work/ghidra/Altice_MP3_Runtime_20260929`.
- Entrées extraites : `research/f2/work/extracted/altice_platform/` et
  `research/f2/work/extracted/altice_alice/alice-py.bin`.
- Rapports bruts : `research/f2/work/ghidra/alice_reports/` (locaux, ignorés Git).
- Source témoin : `research/f2/work/donor_repos/MT2503-2/`; ne prouve jamais à
  elle seule la présence d'une fonctionnalité dans Altice.

## Dossiers techniques et ordre de recherche

1. **S01 terminé** — [preuve du décodeur et mapping ALICE](docs/reverse-engineering/mp3-decoder-verdict-2026-09-29.md).
2. **S02 consignée** — [ouverture DAF, DCM et dispatch](docs/reverse-engineering/daf-open-dispatch-2026-09-29.md), avec limite switch explicite.
3. **S03 à démarrer** — Play, rechargement DAF et sortie audio.
4. À venir — handler `.mp3`, frontend, puis entrée Multimedia.
5. À venir — patch reproductible hors ligne, recovery, puis décision de test.

Règles de maintenance : [organisation documentaire](docs/ORGANISATION.md).
Les fichiers STATUS/ROADMAP et l'ancienne mise à jour à la racine orientent vers
ce point unique. Les anciennes conclusions sont conservées en archives.
