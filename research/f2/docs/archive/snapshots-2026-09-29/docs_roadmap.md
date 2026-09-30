# Roadmap — lecteurs audio et vidéo sur le MobiWire NIKITI / Altice F2

> **Priorité actuelle — lecture MP3 :** suivre [ROADMAP_MP3.md](../ROADMAP_MP3.md). Elle remplace l'ordre de travail de ce document pour l'objectif immédiat : vérifier le décodeur MP3, puis l'association `.mp3` et le frontend, avant toute recherche du parent Multimedia. Cette roadmap historique couvre aussi Video Player et le comparatif firmware donneur; la garder pour les phases ultérieures.

## Objectif

Obtenir un firmware compatible avec cet exemplaire du MobiWire NIKITI / Altice F2 qui expose les lecteurs Audio et Video dans le téléphone et permet de lire des fichiers réels. Le résultat visé est un téléphone fonctionnel, pas seulement la présence d’un codec ou d’une entrée de menu.

Le téléphone est un feature phone MediaTek/MAUI : les lecteurs sont des applications intégrées au firmware, pas des APK. La voie prioritaire est d’identifier et de comparer un firmware stock exact pour la même famille matérielle. Une modification personnalisée ne sera envisagée qu’après avoir établi que le code existe, compris ses dépendances et déterminé qu’une restauration stock adéquate est impossible.

## Référence factuelle à utiliser

- Appareil : MobiWire NIKITI / Altice F2, MT6261 confirmé par lecture BROM (`BB_CPU_ID=0x6261`, `BB_CPU_HW=0xCB01`), plateforme `SAGETEL61M_11C_HW`.
- Firmware installé : `ALTICE_F2_DS_V02.1_181023_MP`, carte/PCB `DL188_GX1882_NIKITI_PCB01`.
- Le téléphone affiche actuellement **Multimedia → Image Viewer, FM Radio**. Les captures sont décrites dans [les notes des captures](assets/screenshots/README.md).
- Le manuel de la famille F2 documente aussi Audio Player et Video Player. Cette documentation établit le comportement attendu d’une variante F2 ; elle ne prouve pas que les applications soient incluses dans le build Altice installé.
- Le meilleur firmware témoin identifié est `ELKI_DS_L_V01.2_181106_MP`, associé dans les documents réglementaires au NIKITI/F2 et au matériel V01. Il n’a pas été trouvé dans les fichiers locaux inventoriés. Ne pas le remplacer silencieusement par un autre firmware.
- Le témoin secondaire MobiWire Nakai (`MOBIWIRE_NAKAI_SS_L_V01.2_181214_MP`) peut aider à reconnaître le lecteur audio sur MT6261/`SAGETEL61M_11C_HW`, mais il ne représente pas le même téléphone et n’est pas un bon témoin pour le lecteur vidéo. Le QMobile F2 déjà étudié est plus éloigné encore.

## État par thème

| Thème | Fait établi / travail fait | À faire |
|---|---|---|
| Identification matérielle | Le BROM confirme MT6261 et l’accès USB `0E8D:0003`. Le build Altice et la famille matérielle sont identifiés. | Garder l’identification du firmware témoin distincte de celle du téléphone ; confirmer ses marqueurs, CPU, base ALICE et variantes d’écran/carte avant toute comparaison utile. |
| Sauvegarde | Trois dumps NOR de 4 MiB existent localement. Les dumps 2 et 3 ont le même SHA-256 (`2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922`). Le dump 1 diffère dans une petite zone documentée. | Conserver deux copies indépendantes et intactes des dumps 2/3, avec leurs empreintes. Toute nouvelle lecture doit être comparée avant d’être considérée comme sauvegarde de référence. |
| Firmware stock témoin | Les documents associent `ELKI_DS_L_V01.2_181106_MP` au NIKITI/F2, HW V01 ; le manuel de la famille décrit Audio et Video Player. | Obtenir le package/dump exact, puis prouver qu’il s’agit bien de cette build et de cette plateforme. Chercher d’abord chez les sources de maintenance documentées dans les notes historiques ; ne pas flasher une ROM MT6261 générique. |
| Extraction et désassemblage | L’ALICE Altice a été extraite/décompressée et désassemblée en ARM Thumb à `0x101812C4`. Les binaires et projets sont conservés sous `work/`. | Répéter exactement la chaîne d’extraction sur le témoin ELKI et conserver hashes, en-têtes, base runtime, composants et rapports. Comparer les builds seulement après validation des images. |
| Menu et framework | Le descripteur de menu est caractérisé : parent U16 `+0x14`, ID sélectionné `+0x18`, tableau U16 d’enfants `+0x40`, nombre d’enfants `+0x48`. `0x102BA458` promeut l’enfant sélectionné au parent ; le chemin de rendu appelle des APIs externes de comptage/énumération. | Résoudre l’origine du descripteur et les APIs externes dans les composants réellement mappés, ou obtenir leurs valeurs à runtime par une méthode démontrée comme non destructive. Trouver l’ID du parent Multimedia et ses deux IDs enfants, puis mapper chaque enfant à son texte, highlight et launch handler. |
| Image Viewer / FM Radio | Ce sont les deux ancres utilisateur certaines dans le menu Multimedia. Une table factory-test contenant « FMradio » a été identifiée séparément et ne prouve pas le handler FM utilisateur. | Identifier leurs launch/init/UI handlers par leurs comportements (navigation fichiers/décodeur/écran pour Image Viewer ; tuner/fréquence/audio/touches pour FM). Trouver leur parent commun et s’en servir comme contrôle positif pour interpréter les tables de menu. |
| Audio | Le build Altice contient un backend `aud_player_media`, un constructeur d’interface à `0x102362A4` et une chaîne de callbacks qui rejoint des services génériques de texte/UI. | Déterminer si un moteur de lecture applicatif existe au-delà du backend : écran, touches play/pause/next/previous, playlist, navigateur de fichiers, timers, callbacks d’état et chemin d’initialisation. Relier ces fonctions aux IDs/dispatchers du menu. Une primitive UI isolée ou le backend seul ne suffit pas. |
| Vidéo | La présence d’une application Video Player ou d’un backend vidéo utilisable dans le build actuel n’est pas démontrée. | Sur le témoin F2 exact, identifier init, launch, UI, navigation de fichiers et décodage/affichage. Dans Altice, distinguer application complète, backend/codec seul et absence de code applicatif. Vérifier formats et dépendances audio/vidéo sans inférer l’application à partir d’un codec. |
| USB et accès runtime | Les scripts de surveillance/capture non interactifs sont prêts. La trace récente RUN 5 a vu `0E8D:0003` pendant environ 2,634 s puis `0E8D:0002`, mais aucun événement COM. `0002` reste inconnu. | Refaire des cycles séparés watch-only puis écoute série passive. Capturer identité PnP/driver et toute seconde énumération. Ne tenter AT, handshake BROM ou lecture RAM qu’après classification du protocole et preuve qu’elle ne nécessite pas d’arrêter le firmware principal. |
| Sécurité et compatibilité | Les dumps, archives, ALICE extraites, projets Ghidra et captures sont séparés et ignorés par Git. Aucun firmware n’a été modifié dans cette analyse. | Avant toute restauration ou expérimentation future, établir un plan de récupération et la compatibilité exacte CPU, carte, LCD, clavier, RF, mémoire et configuration dual-SIM. Préserver NVRAM, IMEI, calibration et données de production. Toute écriture nécessitera une décision explicite distincte. |

## Phases et critères de sortie

### 1. Obtenir et valider le témoin NIKITI/F2

**Action :** trouver le package ou dump de `ELKI_DS_L_V01.2_181106_MP`.

**Sortie attendue :** provenance documentée, version/build confirmés dans les données, SoC/base ALICE connus et empreintes calculées. Si la build exacte reste introuvable, garder ce blocage visible et utiliser Nakai uniquement comme témoin secondaire audio.

### 2. Comparer les couches de menu entre les deux builds F2

**Action :** comparer ROM/VIVA/ressources/ALICE, pas seulement le code décompressé. Repérer les fonctions ou tables reliées aux ancres communes Image Viewer et FM Radio, puis remonter au parent Multimedia.

**Sortie attendue :** parent ID, IDs enfants, nombre d’entrées actives, resource IDs, handlers highlight/launch/init et preuves d’alignement entre builds. Déterminer si Audio/Video sont des entrées compilées mais masquées, absentes de la table, ou entièrement absentes.

### 3. Établir l’état réel des applications Audio et Video

**Action :** suivre les handlers depuis le dispatcher du menu. Classer séparément UI/application, moteur de lecture, décodeurs/codecs et services audio/vidéo. Chercher les appels filesystem, browser, playlist, touches, écrans, timers, callbacks et ressources.

**Sortie attendue :** pour chaque lecteur, verdict `application complète`, `code présent mais détaché/masqué`, `moteur seulement`, `absent` ou `incertain`, chacun accompagné d’indices convergents. Un codec, une chaîne `MP3`, un backend commun ou un appel supplémentaire ne constitue pas une preuve suffisante.

### 4. Choisir la voie la moins risquée

Décider à partir des résultats :

1. **Le témoin stock exact possède les lecteurs et est compatible :** préférer comprendre puis restaurer cette variante, sous réserve d’un plan de sauvegarde/récupération complet.
2. **Les applications existent déjà dans Altice mais les entrées sont omises/filtrées :** d’abord déterminer le mécanisme exact et ses dépendances ; une simple entrée de menu n’est envisageable que si ses handlers, ressources, init et paramètres existent tous.
3. **Altice ne contient que des moteurs/codecs :** ajouter un ID de menu seul ne créera pas l’application. Il faudra trouver un firmware compatible qui inclut l’application ou démontrer qu’un port complet est réaliste.
4. **Le témoin ou l’architecture reste indéterminé :** ne rien modifier ; poursuivre acquisition et analyse statique.

**Sortie attendue :** note de décision documentant le scénario, les preuves, les risques de compatibilité et les moyens de restauration. Aucun scénario ne justifie un flash « pour essayer ».

### 5. Vérifier hors téléphone puis valider le fonctionnement

Avant toute opération sur l’appareil, analyser hors ligne les images, adresses, structures, checksums et zones uniques. Toute validation sur matériel devra être réversible et autorisée séparément.

**Définition de réussite fonctionnelle :** Audio Player et Video Player apparaissent dans le menu du téléphone ; ils ouvrent leurs interfaces, parcourent un stockage, lisent des formats compatibles et répondent aux commandes de base. Vérifier également que démarrage, écran, clavier, SIM/réseau, FM Radio, Image Viewer, haut-parleur/casque et carte mémoire restent fonctionnels.

## Prochaine action recommandée

Chercher/obtenir le fichier ou dump exact `ELKI_DS_L_V01.2_181106_MP`, puis le valider sans le flasher. En parallèle, le chemin de menu Altice reste à compléter par la résolution du parent/enfants dynamiques à partir du framework et des deux applications visibles. Ne pas reprendre l’exploration AudioPlayer à partir du backend seul avant d’avoir ces ancres.

## Références internes

- [État et résultats courants](status.md)
- [Identification matérielle et USB](hardware-usb.md)
- [Configuration locale et chemins](local-setup.md)
- [Framework de menus](reverse-engineering/menu-framework.md)
- [État des lecteurs audio/vidéo](reverse-engineering/audio-status.md)
- [Workflow Ghidra](reverse-engineering/ghidra-workflow.md)
- [Notes historiques et limites](archive/README.md)
