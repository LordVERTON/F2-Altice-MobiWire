# Roadmap — écouter un MP3 sur le MobiWire NIKITI / Altice F2

> **Avancement du 29 septembre :** code MP3 et intégration au composant DAF
> démontrés. Base ALICE corrigée à `0x1024EC00`. La prochaine étape est
> `DAF_Open` / chargement DCM / dispatch fichier, puis le frontend; la lecture
> complète reste à prouver. Voir le [verdict](docs/reverse-engineering/mp3-decoder-verdict-2026-09-29.md).

Objectif court : copier un MP3 sur la carte SD, le sélectionner sur le téléphone et l'écouter. La priorité est de vérifier si le firmware Altice sait décoder le MP3 avant de chercher à reconstruire parfaitement PlutoMMI ou à modifier le menu.

États : `[ ] TODO` · `[>] IN PROGRESS` · `[x] DONE` · `[!] BLOCKED`.

## Point de départ

Prochaine expérience préparée le 29 septembre : lecture BROM ciblée de deux
échantillons des APIs plateforme manquantes, après reconnexion téléphone éteint.
Outil : `../../f2_runtime/probe_platform_rom.py`; protocole et limites :
[PLATFORM_ROM_PROBE.md](../../f2_runtime/PLATFORM_ROM_PROBE.md).
11 tests simulés passent; test matériel en attente. L'expérience vérifie
l'accessibilité des adresses, pas encore la présence d'un lecteur/décodeur.

- Téléphone : MobiWire NIKITI / Altice F2, MT6261, NOR 4 MiB, PCB `DL188_GX1882_NIKITI_PCB01`.
- Build : `ALTICE_F2_DS_V02.1_181023_MP`.
- Trois dumps NOR sont disponibles sous `research/f2/data/dumps/`; les dumps 2 et 3 ont déjà été documentés comme identiques.
- Package de service Altice ROM/VIVA et ALICE Altice extraits; projet Ghidra et rapports existants.
- L'écran Multimedia observé contient Image Viewer et FM Radio.
- `aud_player_media` et son interface callbacks sont présents; ceci ne prouve pas un décodeur MP3, un frontend AudioPlayer ou son inscription au menu.
- COM3 répond aux commandes d'information AT et confirme le build, mais aucune primitive de lecture RAM/debug n'est connue. COM sort du chemin critique.

## Phase 0 — figer l'état et tenir les preuves

- [x] Créer les fichiers de suivi `ROADMAP_MP3.md`, `STATUS.md` et `EVIDENCE.md`.
- [x] Consigner séparément faits, hypothèses et expériences proposées.
- [ ] Toute nouvelle conclusion met à jour `STATUS.md` et ajoute une preuve datée à `EVIDENCE.md`.

## Phase 1 — décider si Altice décode le MP3

- [x] Scanner l'image service Altice, ROM, VIVA, ALICE compressée/décompressée et un dump, en ASCII/UTF-16LE, pour les signatures MP3/MPEG/DAF/codec ciblées.
- [>] Suivre une chaîne fonctionnelle : reconnaissance/dispatch du format → sélection du codec → init du décodeur → ouverture/lecture MP3. Les scans et la décompilation ciblée des voisinages WAV/AMR n'en montrent pas une complète; voir `work/ghidra/alice_reports/audio_decode_path_fast.txt`.
- [x] Traiter les marqueurs `MP33`/`MP36` de la ROM comme tags non identifiés (pas comme preuve d'un décodeur); `MP33` est partagé avec le QMobile témoin.
- [x] Requalifier le callback déjà suivi : les helpers sont des opérations génériques d'objet/configuration/ressource; aucun open/read ou init de décodeur MP3 n'est établi.
- [x] Décompiler les fonctions proches des marqueurs `WavDecoder.c`/`AmrParser.c` en lecture seule : aucune cible voisine ne prouve à elle seule un décodeur audio; aucune piste MP3 reliée au playback. Verdict inchangé `UNKNOWN`, pas `ABSENT`.
- [x] Test réversible File Manager sans patch : le petit MP3 essayé ne propose pas Lire/Ouvrir, seulement des actions Bluetooth (envoyer/déplacer). Cela élimine le parcours direct observé, pas le décodeur ni les autres launch paths.
- [ ] Publier `f2_ghidra/alice_reports/mp3_decoder_verdict.txt` avec verdict `PRESENT`, `ABSENT` ou `UNCERTAIN`, adresses et preuves convergentes.
- **Gate 1 :** si `ABSENT`, arrêter le patch Altice et chercher le firmware ELKI/donneur. Si `PRESENT`, passer directement à la phase 2. Si `UNCERTAIN`, ne pas le transformer en `ABSENT`; identifier la table de composants/les cibles MP33/MP36 ou faire un test d'ouverture MP3 au File Manager avant toute UI.

## Phase 2 — trouver l'association `.mp3` du File Manager

- [x] Scanner les composants ALICE/ROM/VIVA pour les tables extension/type/icône/handler. Indice Altice : ressource `Playlist\\audio_play_list\\...` et liste `.3gp/.MP4/.AVI`; aucun dispatch `.mp3` relié à une cible trouvé.
- [x] Chercher les XREF Ghidra de `Playlist\\audio_play_list`: aucune XREF reconnue ni pointeur absolu; l'indice ne prouve pas un frontend.
- [x] Suivre le contrôle positif `.3GP/.MP4/.AVI`: `FUN_10287048` classe ces suffixes et est appelée par `FUN_10281D68` dans un chemin de préparation média. Pas de branche `.mp3` établie dans ce chemin.
- [ ] Utiliser l'ouverture `.jpg` → Image Viewer comme contrôle positif, puis suivre `.mp3` → callback éventuel.
- [ ] Chercher si un handler MP3 est déjà enregistré même si aucun Audio Player n'est visible dans Multimedia.
- [x] Produire `f2_ghidra/alice_reports/filetype_mp3_dispatch.txt` et le scanner reproductible `scripts/analysis/scan_filetype_mp3_dispatch.py`.
- [ ] Si un handler plausible existe, faire un test physique réversible avec un MP3 court/simple depuis File Manager, sans patch préalable.

## Phase 3 — classer le frontend AudioPlayer

À engager après preuve d'un décodeur MP3 utilisable, ou en parallèle d'une vérification donneur si nécessaire.

- [ ] Chercher un cluster relié au backend média, au filesystem/File Manager, aux ressources UI et aux handlers de touches.
- [ ] Rechercher les fonctions d'ouverture, play/pause/resume/stop, EOF/seek/durée, fichier courant, next/previous et volume.
- [ ] Produire `f2_ghidra/alice_reports/audioplayer_frontend_verdict.txt` et classer : frontend complet, frontend partiel, ou aucun frontend démontré.
- [x] Examiner le candidat playlist du firmware témoin QMobile : `FUN_103213dc` ouvre `@Playlists/audio_play_list.sal` et ses appelants parcourent/préparent les entrées. Aucun appel identifié au décodeur, au playback ou aux touches dans la trace; cela ne prouve pas un frontend complet. Rapport `work/ghidra/alice_reports/qmobile_playlist_audio_candidate.txt`.
- [x] Examiner l'unique site d'appel connu de l'initialisation playlist (`0x103bd438`) : branche conditionnelle vers `FUN_102f6620`, contenant de fonction inconnue. Cela ne révèle pas un launch handler. Contexte `work/ghidra/alice_reports/qmobile_playlist_callsite.txt`.
- [x] Comparer les quatre fonctions playlist QMobile à toutes les fonctions ALICE Altice exportées : meilleur score de séquence mnémotechnique de 0,519; aucun homologue net. Mesure exploratoire uniquement, ne prouve pas une absence. Rapport `work/ghidra/alice_reports/qmobile_playlist_altice_similarity.txt`.
- [x] Vérifier les 33 adresses `F0xxxxxx` externes touchées par les traces `aud_player_media` contre les fichiers ROM/VIVA du package : 0 référence littérale exacte en ROM, 0 en VIVA, 34 en ALICE (contrôle positif). Cela ne remplace pas une analyse de tables indirectes, mais confirme que les implémentations visées ne sont pas dans les modules locaux. Pas d'API decoder/PCM nommée établie. Rapport `work/ghidra/alice_reports/audio_platform_api_gate.txt`, script `scripts/analysis/scan_audio_external_api_literals.py`.
- [x] Valider les témoins positifs proposés : les marqueurs WavDecoder/AmrParser n'ont pas de XREF, FM Radio n'a pas encore de cluster launch/backend attribué. Ils ne peuvent donc pas servir de contrôles audio prouvés. Voir `audio_decode_path_fast.txt` et `fm_positive_control.txt`.
- [x] Trouver une référence source publique MT6261/MT2503 : frontend PlutoMMI complet (`AudioPlayer.res` → `mmi_audply_entry_main`), appel MDI `mdi_audio_play_file_with_vol_path`, dispatch `MED_TYPE_DAF` → `DAF_Open`, parseur DAF et bibliothèque `mp3_dec.a`. Dans cette référence, l'association `.mp3` et le dispatch DAF sont conditionnés par `DAF_DECODE`; un exemple client a `DAF_DECODE = FALSE`. Ce n'est pas le build Altice. Rapport `work/ghidra/alice_reports/mt6261_public_audio_reference_2026-09-28.txt`.
- [x] Rejeter Logicrom `audio.h` comme voie audio MT6261 prouvée : sa documentation actuelle dit explicitement que l'interface audio n'est prise en charge que par RDA8910. Référence dans le rapport ci-dessus.

## Phase 4 — choisir le chemin minimal

- [ ] Frontend complet : retrouver son launch/registration et l'enregistrer sans reconstruire le lecteur.
- [ ] Backend MP3 prouvé, frontend absent : envisager une UI minimale qui réutilise File Manager, liste UI, ressources et `aud_player_media`.
- [ ] Codec ou app absents : comparer d'abord le donneur exact `ELKI_DS_L_V01.2_181106_MP`; ne pas conclure sur la seule absence d'une chaîne.
- [x] Nouvelle piste publique DZGSM/MEGA vérifiée : l'archive RAR de 4,93 MB contient six éléments identiques octet pour octet au package Altice V02 déjà local; ce n'est pas le firmware ELKI. Rapport `work/ghidra/alice_reports/firmware_candidate_search_2026-09-28.txt`, vérification reproductible par `scripts/analysis/compare_shared_archive.py`.
- [x] Recherche Web répétée du firmware donneur exact : rapport réglementaire et portail MobiWire retrouvés, mais toujours aucun binaire ELKI/NIKITI 2018 public vérifiable. Le firmware distinct `Mobiwire_Elki_MT6261_V03_20150729_MIRA.zip` reste une archive 2015 annoncée par des tiers, non retenue comme donneur compatible; voir `EVIDENCE.md`.
- [ ] L'ID numérique de Multimedia et sa relation enfants deviennent prioritaires seulement après identification d'une cible launch fonctionnelle.

MVP visé : Audio Player → choisir un `.mp3` sur SD → Play/Pause → Stop. Previous/Next si simple. Playlists, skins, égaliseur, lecture arrière-plan et Video Player sont hors chemin critique.

## Phase 5 — préparer une preuve de concept hors ligne

- [ ] Copier le dump original vers un artefact distinct `patched_altice_audio_test.bin` uniquement après identification d'un launch valide et de ses dépendances.
- [ ] Fournir un script de patch reproductible, offsets, bytes originaux/nouveaux et justification de chaque modification.
- [ ] Vérifier taille NOR 4 MiB, zones boot, NVRAM et filesystem personnel, checksums, adresses Thumb, branches et absence de chevauchement.
- [ ] Produire une liste exhaustive des différences; arrêter si une zone inattendue change.
- **Aucune écriture téléphone pendant ces phases.**

## Phase 6 — recovery et validation matérielle

- [ ] Avant tout flash, démontrer un chemin de récupération, protéger NVRAM/IMEI/calibration/données et vérifier une sauvegarde exacte.
- [ ] Tester hors téléphone erase/program/verify et définir les secteurs autorisés.
- [ ] Un premier essai éventuel doit être minimal, avec read-back obligatoire et comparaison au patch.
- [ ] Tester boot, SIM/réseau, écran, clavier, Image Viewer, FM Radio, SD, puis un MP3 CBR 44,1 kHz simple.
- [ ] Ne pas lancer de flash sans autorisation explicite distincte et recovery prêt.

## Ordre de travail maintenant

- [x] Décompiler un second consommateur de `F02D8870`/`F032ACDC` (`FUN_102d43dc`): lookup d'un ID égal à `parent+7` et indexation d'une table de chaînes; aucun registre d'applications ni launch handler révélé. Voir `work/ghidra/alice_reports/menu_registry_api_users.txt` et `work/ghidra/alice_reports/multimedia_registration_launch_trace.txt`.
- [x] Vérifier le manifeste du package de service : la configuration livre ROM/VIVA et les bootloaders, sans image applicative système séparée; les APIs de registre externes ne sont pas dans un composant supplémentaire de ce package.

1. `[>]` Comparer le code Altice décompilé au témoin source PlutoMMI MT6261 : rechercher si `DAF_DECODE`/le chemin `MED_TYPE_DAF → DAF_Open` est compilé, puis identifier le frontend/launch. La source de référence est publiquement disponible mais différente du client Altice; voir `mt6261_public_audio_reference_2026-09-28.txt`.
2. `[!]` Résoudre les services audio `F0xxxxxx` : les cibles des callbacks média ne sont pas implémentées dans ROM/VIVA; les valeurs F0 brutes ne sont pas des ordinals classifiés. Il manque exports/symboles ou un donneur exact pour lever ce verrou.
3. `[>]` Identifier le registre dynamique des enfants Multimedia et les launch handlers Image Viewer/FM Radio comme contrôles positifs. La seconde fonction consommatrice décompilée reste un simple lookup via le registre externe; les APIs/implémentations d'enregistrement et le dispatcher feuille restent hors des binaires disponibles.
4. `[ ]` Rechercher la voie Video Player/décodeur vidéo indépendamment de la présence de `.3GP/.MP4/.AVI` dans un dispatcher.
5. `[ ]` N'envisager le patch hors ligne qu'après preuve des modules/handlers; recovery puis décision séparée sur toute écriture.

Hypothèse de travail et alternatives : voir `work/ghidra/alice_reports/multimedia_app_presence_analysis.txt`. L'ID du parent/registre est externe au code ALICE identifié, donc ne pas injecter un enfant supposé.

Dernière vérification des launch handlers : `work/ghidra/alice_reports/multimedia_registration_launch_trace.txt`. ALICE prouve l'énumération dynamique, mais le callback de navigation étudié ne lance pas les éléments feuille. Ne pas faire un patch menu avant d'avoir une target valide et son codec.

### Test « from scratch »

- [x] Réunir le gate audio natif : callbacks `aud_player_media`, File Manager, ressource playlist et dispatcher vidéo. Aucun maillon fichier MP3 → decoder → sortie PCM/DAC n'est établi; UI minimale non prête. Rapport : `work/ghidra/alice_reports/audio_native_path_gate.txt`.

- [x] Confirmer la limite de la piste actuelle : ni chaîne de build/link reproductible pour ajouter du code ALICE, ni voie de sortie PCM/lecture audio par API, ni RAM libre mesurée ne sont démontrées. Les 4 MiB désignent la NOR, pas l'espace libre.
- [x] Inventorier les artefacts du workspace : aucun SDK MAUI/MRE, header/lib d'application ou API de sortie audio documentée trouvée. Scan textuel ROM/VIVA négatif, mais les exports par ordinal/pointeur restent possibles.
- [x] Vérifier le marqueur `[MRE VERSION] %d` en Ghidra : XREF reconnu absent; aucun `.vxp`, `VXP`, `MRE API`, `J2ME`, `appdb` ou `@mre` trouvé dans ALICE. Cela ne suffit pas à prouver l'absence de runtime applicatif.
- [>] Constater la limite du package : les veneers ALICE visant des APIs système `0xF0xxxxxx` pointent hors des plages ROM/VIVA fournies; les implémentations système manquent du package de service. Obtenir leurs exports/symboles ou une documentation de plateforme avant d'attribuer une API audio. Rapport : `work/ghidra/alice_reports/audio_runtime_api_inventory.txt`.
- [x] Vérifier le chemin utilisateur MRE : l'utilisateur confirme qu'il n'y a ni menu Applications, ni Java, ni installateur. Cela écarte l'installation/lancement ordinaire d'une app tierce; le runtime caché reste techniquement UNKNOWN.
- [!] Ne pas retenir l'application externe comme voie MVP tant qu'un launch path caché et un SDK compatible ne sont pas prouvés. Priorité au lecteur natif et à l'identification du sink audio.
- [ ] Avant d'envisager un décodeur logiciel embarqué, vérifier l'API audio et obtenir une chaîne de build ou un SDK externe compatible. Sans l'une de ces voies, le port du décodeur seul ne suffit pas.

Statut du donneur : exact ELKI/NIKITI 2018 non trouvé publiquement à ce jour; voir la section dédiée dans `EVIDENCE.md`.

Rapports de départ : `work/ghidra/alice_reports/media_callback_structure.txt`, `work/ghidra/alice_reports/altice_menu_reconstruction.txt`, `work/ghidra/alice_reports/mp3_decoder_verdict.txt`, `scripts/analysis/scan_mp3_codec_evidence.py`, `../../f2_runtime/reports/fast_runtime_protocol_test.txt` et `../../f2_runtime/reports/firmware_at_command_strings.txt`.


## Verification comparative des tables DAF (2026-09-28)

- [x] Extraire les tables bitrate DAF V1/V2 et sample-rate de la reference source MT6261 et chercher les encodages 16/32 bits little-/big-endian dans ROM, VIVA, ALICE traduit et dump 2. Zero correspondance exacte.
- [>] Interpreation limitee : resultat negatif faible, il n etablit pas l absence du decoder car le compilateur peut retirer ou transformer les constantes; garder MP3=UNKNOWN.
- [ ] Prochaine action utile : identifier Image Viewer et FM Radio dans le registre externe comme controles positifs et tester si AudioPlayer est un slot applicatif desactive. Le menu ne doit pas etre patche sans launch handler et decoder/playback etablis.
- Reproducteur : scripts/analysis/scan_daf_table_signatures.py; analyse : work/ghidra/alice_reports/mt6261_public_audio_reference_2026-09-28.txt.
- [!] Les rapports Image Viewer/FM montrent que leurs IDs et launch targets vivent dans le registre plateforme absent de ROM/VIVA/ALICE fournis; contrôle positif statique non résolu avec les artefacts présents. La source PlutoMMI publique montre deux gates distincts : __MMI_AUDIO_PLAYER__ + __MMI_APP_MANAGER_SUPPORT__ pour l enregistrement, DAF_DECODE pour MP3. La config Altice correspondante manque, donc impossible d attribuer lequel est désactivé. Détails dans work/ghidra/alice_reports/mt6261_public_audio_reference_2026-09-28.txt.

## Controles positifs Multimedia (2026-09-28)

- [x] Inventorier et scanner le dump, image service, ROM, VIVA, ALICE compressee/decompressee/traduite pour les noms Image Viewer, FM Radio, AudioPlayer et les marqueurs connus. Reproducteur : `scripts/analysis/scan_multimedia_resource_markers.py`.
- [x] Separer les hits QMobile des preuves Altice : `FMradio` et les MIME `audio/mp3` de `qmobile_audio_superregion.bin` sont exclus comme preuves pour ce telephone.
- [x] Relier le resultat aux rapports Ghidra : les IDs enfants sont demandes aux APIs systeme `0xF032ACDC` / `0xF02D8870`; handlers feuille et registre non resolus, cibles F0 unmapped dans les composants fournis.
- [x] Conclure sans surinterpreter les chaines : noms Image Viewer/FM et AudioPlayer non trouves dans les images Altice scannees; `aud_player_media` et la ressource Playlist existent mais aucun XREF/launch MP3 n'est etabli.
- [!] Le controle positif statique est bloque par le registre/ROM systeme externe absent. IDs, ressources d'app et launch restent UNKNOWN; ne pas patcher le menu. Rapport `work/ghidra/alice_reports/multimedia_positive_controls.txt`.
- [ ] Reprendre cette branche seulement si une ROM systeme/export de plateforme ou un build donneur vraiment compatible est acquis; conserver MP3 decoder = UNKNOWN.

