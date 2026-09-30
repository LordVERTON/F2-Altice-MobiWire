# État du reverse engineering — 28 septembre 2026

> **Correction du 29 septembre :** le décodeur MP3 est maintenant identifié
> par comparaison binaire et ses appels depuis le composant DAF sont vérifiés.
> La base d'exécution ALICE est `0x1024EC00`, et non `0x101812C4` utilisée dans
> l'historique ci-dessous. Voir le [verdict détaillé](reverse-engineering/mp3-decoder-verdict-2026-09-29.md)
> et [l'état courant](../STATUS.md). Lecture SD et frontend restent inconnus.

> Statut opérationnel du chemin MP3 : voir le tableau actualisé dans [../STATUS.md](../STATUS.md) et les preuves datées dans [../EVIDENCE.md](../EVIDENCE.md). La priorité est maintenant le verdict décodeur MP3, pas la résolution des IDs Multimedia.

## Appareil et firmware

- Téléphone : MobiWire NIKITI / Altice F2.
- CPU : MT6261, confirmé par lecture BROM (`BB_CPU_ID=0x6261`, `BB_CPU_HW=0xCB01`).
- Famille matérielle : `SAGETEL61M_11C_HW`.
- Build : `ALTICE_F2_DS_V02.1_181023_MP`.
- Trois dumps complets de 4 MiB sont conservés localement dans `research/f2/data/dumps/` ; ce dossier est ignoré par Git. Les dumps 2 et 3 ont le même SHA-256 : `2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922`.

## Conclusions établies

1. Le menu Multimedia observé sur le téléphone affiche Image Viewer et FM Radio.
2. ALICE a été désassemblée comme ARM Thumb à la base `0x101812C4`; l’image décompressée fait 1 407 924 octets.
3. Le chemin du framework utilise un descripteur de menu avec parent courant `+0x14`, enfant sélectionné `+0x18`, buffer d’enfants `+0x40` et nombre d’enfants `+0x48`.
4. Les IDs enfants sont récupérés par des appels externes et le buffer est traité comme un tableau d’IDs U16. Les valeurs numériques Multimedia/enfants ne sont pas encore démontrées.
5. L’analyse statique n’a pas encore identifié l’écriture runtime de `+0x18` ni la table parent-enfants concrète.
6. Le backend `aud_player_media` et une interface de callbacks existent. Cela ne démontre ni une application Audio Player MMI complète ni une entrée de menu.
7. Les notes d’acquisition détaillent trois lectures NOR ; les dumps 2 et 3 sont identiques. Le dump 1 présente une petite différence localisée décrite dans le dossier historique de récupération.

## Firmware témoin

Les documents réglementaires associent `ELKI_DS_L_V01.2_181106_MP` au NIKITI/F2 et au matériel V01 ; le manuel NIKITI/Altice F2 décrit Audio Player et Video Player dans Multimedia. Le fichier exact n’est pas présent dans l’inventaire local courant. Le téléphone analysé contient plutôt `ALTICE_F2_DS_V02.1_181023_MP` et n’affiche que Image Viewer/FM Radio. Le menu utilise des APIs externes dynamiques d’énumération, ce qui rend plausible une différence de build/registre, sans la prouver. Voir `work/ghidra/alice_reports/multimedia_app_presence_analysis.txt`. Le QMobile et le Nakai restent des témoins secondaires, avec des limites de comparabilité différentes.

## Observation USB passive

La trace RUN 5 du 28 septembre 2026 a enregistré l’ajout puis le retrait de `0E8D:0003` en environ 2,634 s, puis l’ajout de `0E8D:0002`. Aucun `PORT_ADDED` n’a été observé. Le premier PID est cohérent avec le BROM déjà identifié ; le second reste non classé. Aucun protocole n’a été envoyé. Des watchers antérieurs ont pu produire des événements dupliqués.

## Suite recommandée

**Résultat ultérieur, RUN 3 :** l'utilisateur a validé **COM port** et confirme l'écran principal affiché ; `0E8D:0003` persiste depuis 17:48:07 avec WinUSB. Aucun COM Windows ni alias COM3. L'INF actif associe cette identité à WinUSB. Le PID ne distingue donc pas à lui seul le BROM connu d'une interface sélectionnée depuis le firmware. La classification protocolaire est désormais **UNKNOWN** pour cet essai ; piste runtime intéressante, lecture RAM non démontrée. Test proposé : navigation dans Multimedia en conservant la connexion et l'observation USB.

**Navigation validée :** l'utilisateur confirme Multimedia et la sélection fonctionnels. Contrôle de 17:52:36 : `0003` toujours présent, au moins 4 min 29 s de présence sans ouverture. Le fonctionnement du menu pendant la présence USB est confirmé par l'utilisateur ; lecture RAM toujours inconnue. Prochaine étape proposée : inspection des descripteurs et points d'entrée WinUSB, sans handshake ni changement de pilote.

**COM3 restauré :** PnPUtil a installé le pilote série MediaTek signé depuis un terminal administrateur. COM3 est actif (`Ports`, `wdm_usb`, `oem68.inf`); ouverture passive 8 s sans erreur, 0 octet reçu/envoyé. WinUSB a été exporté pour retour. La commande et les résultats figurent dans [DRIVER_COM_STATUS.md](../../../f2_runtime/DRIVER_COM_STATUS.md).

Mise à jour après capture à 17:33 : le nouveau RUN 2 a identifié `0003` comme USBDevice/WinUSB pendant environ 2,59 s, puis `0002` comme stockage USB (`USBSTOR`). Aucun COM actif énuméré. `COM3` n'est qu'une valeur de registre résiduelle sur le devnode WinUSB dans cette observation. L'utilisateur confirme l'écran de charge uniquement. Le firmware principal/menu en cours d'exécution et la lecture RAM live restent non démontrés. Le maintien en vie par ouverture COM n'a donc pas encore été testé. Détails dans [hardware-usb.md](hardware-usb.md) et [la procédure d'essai](../../../f2_runtime/README.md).

Relancer le watcher non interactif avant la connexion, puis effectuer une capture série passive distincte. Il faut établir l’identité PnP complète et confirmer si un COM existe. Ne pas envoyer de handshake BROM ni de commande AT à une interface non classifiée.

## Mise à jour COM et priorité MP3 — 2026-09-28

Les paragraphes USB ci-dessus relatent les observations initiales sous WinUSB. Ils sont historiques et ne décrivent pas le binding actuel après essai série : le pilote MediaTek `wdm_usb` a exposé **COM3**, ouvert pendant le firmware principal. L'écoute passive corrigée a duré 225,223 s sans octet RX/TX. Le test AT actif a reçu `OK` à `AT`, les commandes d'identification ont renvoyé le build attendu, et `AT+CLAC` a renvoyé `ERROR`. Aucun primitive RAM/debug n'est identifiée; le COM sort du chemin critique MP3. Les rapports complets sont sous `f2_runtime/reports/` à la racine du dépôt.

La prochaine analyse est le décodeur MP3, puis l'association de fichier `.mp3` et le frontend éventuel. L'état canonique est [STATUS.md](../STATUS.md), la feuille de route [ROADMAP_MP3.md](../ROADMAP_MP3.md), les sources [EVIDENCE.md](../EVIDENCE.md).

## Rapports

Les exports et projets Ghidra sont sous `research/f2/work/ghidra/`. Les rapports de synthèse sont sous `research/f2/work/reports/`. Les données d’acquisition locales et les captures restent hors Git.

## Hiérarchie des notes

Les fichiers dans `docs/archive/` sont historiques. En particulier, `doc.md` conserve l’ancienne hypothèse MT6260 et des instructions USB dépassées ; la lecture directe BROM (`0x6261`) et les documents courants de ce dossier la remplacent.
