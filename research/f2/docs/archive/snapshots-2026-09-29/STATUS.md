# État courant — lecteur MP3 Altice F2

Dernière mise à jour : 2026-09-29.

## Reprise après extraction VIVA — état faisant autorité

**Décodeur MP3 : PRESENT, démontré par comparaison binaire.** 34 fonctions
identifiées dans le module DAF, dont `MP3Dec_Init` et `MP3Dec_Decode`.
Le composant audio ALICE les appelle via des veneers vérifiés; callbacks
Start/Stop/Process et table parser/décodeur retrouvés.

**Correction majeure : ALICE s'exécute à `0x1024EC00`**, selon la table ROM et
les pointeurs de callbacks. L'ancienne base `0x101812C4` est une base d'analyse
incorrecte pour l'exécution. Translation des positions ALICE : `+0xCD93C`.

| Question | Verdict courant |
|---|---|
| Code MP3 | **PRESENT** — identité binaire et appels init/decode |
| Composant DAF et buffers PCM | **PRESENT** — callbacks et traitement de trames |
| Fichier SD → DAF → sortie matérielle | **UNKNOWN** — chaîne complète non établie |
| Lien depuis aud_player_media | **UNKNOWN** — reprendre à l'adresse réelle `0x10303BE0` |
| Frontend AudioPlayer / handler .mp3 | **UNKNOWN** |
| Entrée Multimedia | **UNKNOWN** — aucun patch préparé |
| Écriture / recovery | **NOT READY** — aucune écriture appareil effectuée |

Prochaine action : résoudre le consommateur de la table parser/décodeur
ZIMAGE à l'offset `0x175154`, retrouver `DAF_Open` et le chargement DCM `0x010C`,
puis remonter vers le dispatch fichier. Le test BROM des APIs F0 n'est plus
prioritaire : ces blocs sont disponibles localement.

Preuves, adresses, limites et reproduction :
[verdict MP3](docs/reverse-engineering/mp3-decoder-verdict-2026-09-29.md).
Projet : `Altice_MP3_Runtime_20260929`.

---

## Historique antérieur à cette reprise (verdicts remplacés ci-dessus)

Les lignes suivantes conservent la chronologie. Les mentions MP3 UNKNOWN,
plateforme absente et prochaine action BROM ne sont plus l'état courant.

Reprise USB du 29 septembre : après cycle batterie et sélection « COM port »,
l'utilisateur confirme l'écran principal. RUN 7 observe COM3 sous `wdm_usb`
(`oem68.inf`), puis les requêtes bornées `AT`, `AT+GMR`, `AT+CGMM` répondent
`OK` et confirment `ALTICE_F2_DS_V02.1_181023_MP` / `MTK2`.
Rapport : `../../f2_runtime/reports/runtime_identity_2026-09-29.json`.
Identification reconfirmée uniquement : aucune lecture RAM, installation ou
écriture firmware effectuée; les verdicts audio ci-dessous restent inchangés.

**Prochaine étape opérationnelle (29 septembre) :** test BROM borné des deux
cibles plateforme `F02D8870` / `F032ACDC`, implémenté et validé par 11 tests
simulés, résultat matériel encore en attente. Procédure :
[PLATFORM_ROM_PROBE.md](../../f2_runtime/PLATFORM_ROM_PROBE.md).
Le mapping F0 en BROM est inconnu; ce test ne lit pas la RAM live et ne modifie
aucun registre. Il remplace la répétition des tests AT comme prochaine action.

| Question | Verdict actuel | Portée |
|---|---|---|
| Décodeur MP3 | **UNKNOWN** | Aucun chemin format → codec → init → lecture MP3 établi. Les cibles externes des traces média sont hors ROM/VIVA; le scan des 33 adresses `F0xxxxxx` trouve 0 littéral en ROM, 0 en VIVA et les veneers attendus en ALICE. Marqueurs WAV/AMR sans XREF; `MP33`/`MP36` non résolus. Voir `work/ghidra/alice_reports/audio_platform_api_gate.txt` et `audio_decode_path_fast.txt`. |
| Backend audio | **PRESENT, rôle playback fichier non démontré** | `aud_player_media` et son interface callbacks existent; le chemin direct connu est orienté Bluetooth/A2DP et callbacks de configuration/notification. Aucun chemin fichier → décodeur → sortie audio/PCM n'est établi. Voir `work/ghidra/alice_reports/audio_native_path_gate.txt`. |
| Extension native MRE/VXP | **NON EXPOSÉE À L'UTILISATEUR / runtime UNKNOWN** | L'utilisateur confirme qu'il n'y a aucun menu Applications, Java ou installateur. Aucun SDK local, `.vxp`, API MRE, J2ME ou `appdb` trouvé dans ALICE; `[MRE VERSION] %d` est sans XREF. Une application tierce n'est pas un chemin MVP crédible actuellement, sans conclure formellement que le runtime interne est absent. |
| Firmware donneur ELKI exact | **NOT FOUND PUBLICLY** | La piste DZGSM/MEGA de 4,93 MB a été vérifiée : six fichiers identiques au package Altice V02 local, aucun ELKI. L'archive Elki 2015 tierce reste un firmware différent. Rapport `work/ghidra/alice_reports/firmware_candidate_search_2026-09-28.txt`. |
| Frontend AudioPlayer Altice | **UNKNOWN** | Aucun frontend Altice attribué. Référence source MT6261 publique : app PlutoMMI complète enregistrée par `AudioPlayer.res` et lancée par `mmi_audply_entry_main`; son association `.mp3` dépend de `DAF_DECODE`. Cela prouve un frontend dans le témoin uniquement. Voir `work/ghidra/alice_reports/mt6261_public_audio_reference_2026-09-28.txt`. |
| Référence AudioPlayer MT6261 | **PRESENT, non équivalente au build Altice** | Le dépôt MT2503/MT6261 contient frontend PlutoMMI, MDI file playback, dispatch DAF/MP3 et `mp3_dec.a`; l'exemple client généré désactive toutefois `DAF_DECODE`. C'est une référence d'architecture, pas un firmware donneur Altice. |
| Association de fichier `.mp3` | **UNKNOWN** | File Manager ne propose que Bluetooth envoyer/déplacer pour le MP3 essayé. Le chemin média analysé classe `.3GP/.MP4/.AVI`; aucun `.mp3` → handler relié. |
| Enregistrement Multimedia | **UNKNOWN** | L'écran observé montre Image Viewer et FM Radio seulement; IDs/tables/launch sont non résolus. Deux consommateurs ALICE décompilés appellent les APIs externes d'énumération; le second fait un lookup `parent+7` et range un pointeur vers une chaîne par index, sans révéler table d'applications ni lancement feuille. Voir `work/ghidra/alice_reports/multimedia_registration_launch_trace.txt` et `menu_registry_api_users.txt`. |
| Cause probable des lecteurs manquants | **VARIANTE/REGISTRE DE BUILD (hypothèse la mieux étayée)** | Le manuel NIKITI/Altice décrit Audio/Video; les documents FCC associent le même nom commercial au build ELKI `V01.2_181106`, tandis que le dump installé est `ALTICE_F2_DS_V02.1_181023`. Le menu tire ses enfants d'APIs dynamiques externes. La comparaison binaire ELKI manque pour confirmer. |
| IDs/launch Multimedia | **NON RÉSOLUS** | ALICE peuple la liste via APIs plateforme. `1021F904 → 102BA458` ne fait que la navigation si l'enfant a lui-même des enfants; le launch des éléments feuille n'est pas dans ce chemin analysé. IDs Image Viewer/FM et handlers restent à retrouver dans le registre externe ou un firmware témoin. |
| COM runtime / RAM live | **AT_MODEM; RAM primitive UNKNOWN/LOW** | `AT` répond, AT+CLAC renvoie ERROR, commandes d'identification répondent. Aucun accès mémoire/debug démontré; hors chemin critique. |
| Writer / recovery | **NOT READY** | Aucun patch reproductible validé ni recovery d'écriture démontré. Aucune écriture autorisée ou faite. |

Prochaine action unique : comparer les fonctions Altice décompilées à la source témoin MT6261 autour de `aud_player_media`/MDI et chercher si le dispatch `MED_TYPE_DAF → DAF_Open` est réellement présent dans Altice. Le témoin montre un lecteur complet et MP3 conditionnel; il ne prouve pas que l'Altice l'a conservé. Garder MP3=UNKNOWN et ne pas patcher avant cette preuve. Voir `work/ghidra/alice_reports/mt6261_public_audio_reference_2026-09-28.txt`.

Ne jamais convertir `UNKNOWN` en `ABSENT` uniquement parce qu'une chaîne, un symbole ou un frontend n'a pas été trouvé.


Mise a jour 2026-09-28 : le scan exact des tables de bitrate DAF V1/V2 et des frequences du SDK MT6261 dans ROM, VIVA, ALICE traduit et dump 2 retourne zero correspondance. Ce resultat negatif faible ne prouve pas l absence du decodeur (tables susceptibles d etre transformees ou retirees). Verdict MP3 reste UNKNOWN. Prochaine action statique : retrouver Image Viewer et FM Radio dans le registre externe comme controles positifs, puis verifier si AudioPlayer a un slot desactive. Rapport et script : work/ghidra/alice_reports/mt6261_public_audio_reference_2026-09-28.txt, scripts/analysis/scan_daf_table_signatures.py.

MISE A JOUR 2026-09-28 — CONTROLES MULTIMEDIA
Image Viewer et FM Radio sont confirmes presents par observation utilisateur, mais leur ID, ressource et launch binaire restent UNKNOWN. Le scan des composants Altice n'a trouve aucun de leurs noms; les hits FMradio/MIME audio/mp3 du rapport audio_refs sont QMobile et exclus. Les marqueurs `aud_player_media` et `Playlist\audio_play_list.sal` dans ALICE ne prouvent pas un launch/player. Le registre est fourni par APIs plateforme F0 non mappees dans les composants locaux. AudioPlayer et decoder restent UNKNOWN; aucun patch menu. Rapport `work/ghidra/alice_reports/multimedia_positive_controls.txt`. Prochaine action statique : obtenir ROM systeme ou temoin compatible; la comparaison locale est a sa limite.

