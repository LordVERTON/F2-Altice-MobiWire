# État Audio Player / Video Player

## Audio

- Le firmware Altice contient un backend nommé `aud_player_media` et une interface de callbacks reconstruite autour de `0x102362A4`.
- Une chaîne de callbacks atteint des fonctions génériques de ressources/UI.
- Cela prouve une infrastructure média, pas une application Audio Player complète avec écran, gestion des touches, navigateur de fichiers, playlist et entrée de menu.
- Aucune entrée Audio Player n’a été identifiée dans le menu utilisateur. La présence d’une application MMI orpheline ou détachée du menu reste incertaine.

## Vidéo

La présence d’un moteur vidéo ou d’une application Video Player dans cette build n’est pas démontrée.

## Conclusion prudente

Ne pas déduire « lecteur audio présent mais caché » de la seule présence du backend. Il faut d’abord résoudre le parent/enfants du menu ou obtenir un firmware témoin réellement comparable.

## Priorité mise à jour — 2026-09-28

Le chemin immédiat est désormais de prouver si la build Altice décode vraiment le MP3, puis de chercher l'association `.mp3` du File Manager et seulement ensuite le frontend/menu. Le décodeur, l'association et le frontend restent **UNKNOWN**; les signatures absentes ne suffisent pas à déclarer le décodeur absent. Voir [ROADMAP_MP3.md](../../ROADMAP_MP3.md), [STATUS.md](../../STATUS.md), [EVIDENCE.md](../../EVIDENCE.md) et le [verdict audio rapide existant](../../work/ghidra/alice_reports/audio_player_fast_path.txt).

## Vérification ciblée suivante — voisinage des parseurs

La décompilation read-only des fonctions autour des chaînes source `WavDecoder.c` (0x101F6274) et `AmrParser.c` (0x102A0708) n'a pas relié ces marqueurs à une chaîne de décodage MP3. Les marqueurs n'ont pas de XREF Ghidra reconnu; certaines fonctions voisines du marqueur AMR sont du rendu UI. `FUN_101F6474` traite des données 16-bit et remplit un buffer, sans identification sûre du format. Voir [rapport court](../../work/ghidra/alice_reports/audio_decode_path_fast.txt) et [décompilations](../../work/ghidra/alice_reports/audio_codec_neighborhood.txt). Le verdict MP3 reste **UNKNOWN**, non ABSENT.

Créer un décodeur logiciel MP3 est possible en théorie, mais la route n'est pas encore praticable à partir des éléments actuels : il faut d'abord une API de sortie audio utilisable (PCM ou équivalent), une chaîne de build/link compatible avec la firmware, et des preuves de RAM/performance/place disponible. La capacité NOR de 4 MiB ne renseigne pas sur la place libre. La prochaine vérification est l'inventaire des APIs audio natives/ROM et d'un éventuel SDK d'applications externe.

L'inventaire du workspace n'a trouvé aucun SDK MAUI/MRE, header/lib d'application ou API audio documentée. Les noms ROM/VIVA testés sont absents ou donnent des faux positifs; cela ne ferme pas la possibilité d'exports sans noms (ordinals/pointeurs). Prochaine vérification : résoudre ces exports dans Ghidra et suivre les appels de lecture FM/voix jusqu'à la sortie matérielle. Voir [rapport d'inventaire](../../work/ghidra/alice_reports/audio_runtime_api_inventory.txt).

Un second scan read-only trouve `[MRE VERSION] %d` dans ALICE, sans XREF, mais aucun marqueur applicatif `.vxp`, `VXP`, `MRE API`, `J2ME` ou `appdb`. Une note communautaire indique que beaucoup de builds MAUI récents MT6261 n'ont pas MRE/J2ME; ce constat général ne permet pas de classer ce build précis. Les veneers vers certaines APIs plateforme aboutissent à `0xF0xxxxxx`, hors ROM/VIVA livré, donc leurs implémentations ne peuvent pas être lues dans le package de service. Le support d'app externe reste **UNKNOWN**, avec une probabilité pratique basse.

L'utilisateur confirme qu'il n'existe aucun menu Applications, Java ou installateur. Cela retire le parcours ordinaire d'application externe des options MVP. Le runtime caché n'est pas déclaré absent sur cette seule base; priorité aux fonctions audio natives déjà intégrées et à leur sortie.

Le tracé du menu montre une population d'IDs via des APIs externes et un handler ALICE d'activation qui ne traite que la navigation vers les parents ayant des enfants. Le launch des items feuille (Image Viewer/FM Radio) reste externe/non identifié. Un patch de ligne seul n'est donc pas une prochaine étape fonctionnelle. Voir [trace registre/launch](../../work/ghidra/alice_reports/multimedia_registration_launch_trace.txt).
