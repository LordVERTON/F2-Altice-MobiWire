# Identification matérielle et observation USB

## Identification confirmée

Le téléphone a répondu au handshake BROM MediaTek :

```text
BB_CPU_ID = 0x6261
BB_CPU_HW = 0xCB01
BB_CPU_SW = 0x0001
BB_CPU_SB = 0x8000
```

Le BROM précédemment identifié utilisait `VID:PID 0E8D:0003`. La table locale `mtkclient/config/usb_ids.py` associe ce PID au BROM et plusieurs autres PID (`6000`, `2000`, `2001`, `20FF`, `3000`) au Preloader ; elle ne classe pas `0002`.

## Trace PnP passive — 28 septembre 2026

RUN 5 a enregistré les interfaces USB suivantes :

| Heure locale | Événement | VID:PID | Durée/état |
|---|---|---|---|
| 16:27:16.119 | ajout | `0E8D:0003` | présent environ 2,634 s |
| 16:27:18.753 | retrait | `0E8D:0003` | — |
| 16:27:22.947 | ajout | `0E8D:0002` | retrait non enregistré |

La trace concerne des interfaces USB PnP, pas un port COM. RUN 5 n’a enregistré aucun `PORT_ADDED`, donc elle ne confirme ni port série ni service de pilote. Des watchers plus anciens ont tourné en parallèle et peuvent avoir dupliqué certains événements.

## Nouvelle capture avec identité PnP — 17:33, 28 septembre 2026

Le nouvel outil `f2_runtime/` a capturé RUN 2 (numérotation distincte des anciennes traces) :

- Vers 17:33:05, `0E8D:0003`, `MediaTek USB Port`, classe `USBDevice`, service `WinUSB`, fournisseur `libwdi`, INF `oem86.inf`. Présence environ **2,59 secondes** sur l'interface USB générique ; deux autres notifications d'interface du même devnode donnent environ 2,57 secondes.
- Vers 17:33:12, `0E8D:0002`, `USB Mass Storage Device`, service `USBSTOR`, pilote Microsoft `usbstor.inf`, IDs compatibles `Class_08/SubClass_06/Prot_50`. Le rôle stockage est donc identifié dans cette configuration.
- Même emplacement USB physique dans les deux snapshots. Aucun COM énuméré via pyserial/SetupAPI pendant cette séquence.
- `PortName=COM3` subsiste dans le registre de `0003`, mais sa classe active et son service sont USBDevice/WinUSB. Cette valeur seule ne démontre pas une interface série active.
- L'utilisateur indique rétrospectivement **écran de charge uniquement**. Aucun timestamp de logo/menu ne peut être déduit de cette réponse.

Preuves locales : `f2_runtime/transient_com_events.jsonl` (RUN 2, `PNP_SNAPSHOT`), `f2_runtime/transient_device_identity.txt`. L'observateur n'a ouvert aucun périphérique et n'a envoyé aucun protocole. Le test de prolongation par ouverture COM n'a pas pu être effectué faute de COM observé.

Une autre présence de `0003` entre 17:40:27 et 17:42:32 a duré environ 125 s. L'utilisateur confirme que la batterie était retirée pendant cet essai. Cela ne démontre pas un maintien par ouverture COM : aucun handle n'a été ouvert. Le scénario suivant (RUN 3) utilise le sélecteur USB du téléphone : batterie remise, branchement, touche rouge, choix **COM port**, avec capture passive armée avant la connexion.

## Interprétation et suite

### Sélecteur COM confirmé — RUN 3

Capture passive armée à 17:46:54. Après des passages brefs en `0003`, un passage `0002` de 2,784 s et un autre `0003` de 2,668 s, `0E8D:0003` apparaît à 17:48:07 et reste présent. L'utilisateur confirme avoir choisi **COM port** et voir **l'écran principal**. Le contrôle à 17:49:40 trouve WinUSB, aucun COM énuméré et aucun alias système COM3 (`QueryDosDeviceW`, erreur 2). Le fichier actif `oem86.inf` associe `USB\VID_0E8D&PID_0003` à WinUSB sans distinction de contexte boot/runtime.

Ce résultat impose de distinguer **identité USB** et **protocole** : `0003` n'est plus une preuve suffisante de BROM dans les essais F2. L'interface runtime choisie sur le téléphone semble partager cette identité ; le protocole et une éventuelle primitive RAM restent inconnus. Aucun handle ni octet de protocole n'a été envoyé faute de COM actif. Le prochain test proposé est la navigation Multimedia, câble branché, avec observation de la persistance USB.

**Test Multimedia effectué :** l'utilisateur confirme que le menu s'ouvre et que la sélection fonctionne. À 17:52:36, la même interface USB est toujours présente, soit au moins 4 min 29 s depuis sa dernière apparition, sans ouverture de handle par l'observateur. La coexistence d'une interface USB et du menu fonctionnel est donc établie par corrélation entre le journal et l'observation utilisateur. Aucune primitive de lecture RAM n'est encore démontrée. Suite proposée : inspection des descripteurs/points d'entrée USB sous WinUSB, téléphone laissé dans Multimedia, avant d'envisager un protocole.

### Pilote série MediaTek installé en CLI — 18:11

PnPUtil a associé le `cdc-acm.inf` MediaTek sauvegardé. Windows rapporte désormais COM3, classe `Ports`, service `wdm_usb`, INF `oem68.inf`; `QueryDosDeviceW` confirme `\\Device\\cdcacm1`. COM3 a été ouvert en lecture passive pendant huit secondes : ouverture/fermeture sans erreur, zéro octet reçu et zéro transmis. Détails et commande reproductible dans [DRIVER_COM_STATUS.md](../../../f2_runtime/DRIVER_COM_STATUS.md).

- `0E8D:0003` correspond au BROM connu lors des identifications antérieures, mais apparaît également dans le contexte COM choisi avec écran principal visible ; classification protocolaire **UNKNOWN** sans preuve supplémentaire.
- `0E8D:0002` expose du stockage USB dans la nouvelle capture ; aucun protocole AT, META ou RAM live n'est établi.
- Aucun octet de protocole n’a été envoyé pendant cette observation.
- Le watcher actuel est non interactif : depuis la racine, le démarrer avant de connecter le téléphone avec `./f2_runtime_test.ps1 -Mode watch -PollMs 20 -DurationSec 180`.
- Une capture série passive se fait dans un cycle distinct avec `-Mode passive`. Elle ouvre le COM s’il existe et ne transmet rien.

Les anciennes traces sont sous `research/f2/runtime/`; les nouvelles sont sous `f2_runtime/`, ignorées par Git. Voir la [procédure actuelle](../../../f2_runtime/README.md). Répéter les cycles indépendants pour établir la reproductibilité ; un essai passive n'aura d'ouverture à mesurer que si un véritable COM apparaît.
