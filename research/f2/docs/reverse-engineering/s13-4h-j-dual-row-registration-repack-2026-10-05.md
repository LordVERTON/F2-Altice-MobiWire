# S13.4H–J — alias Image, registration Audio et repack ZIMAGE

## Résultat et périmètre

Travail du 5 octobre 2026, exclusivement hors ligne. Aucun accès téléphone,
aucun D6/D3/D5, aucune écriture flash. D est retenu pour caractérisation
physique, pas pour installation. **HARDWARE WRITE AUTHORIZED: NO**.

| Étape | Résultat |
|---|---|
| S13.4H fourni | Contrôles PASS ; candidat D logique, 8 octets |
| S13.4I ajouté ici | Idempotence de l'état global de registration : 1728 cas PASS |
| S13.4J ajouté ici | Recompression/repack expérimental exact ; 96 secteurs modifiés |
| Activation UI / lecture MP3 | Non démontrée |
| Déploiement matériel de D | Non autorisé, non préparé |

Les désignations I/J correspondent aux étapes ajoutées dans ce dépôt lors
de cette session ; elles ne sont pas des scripts fournis par ChatGPT.

## Sources et réconciliation

Les pages [last update](https://www.notion.so/3e9173c57e048093a8e3ce8c03b398ac)
et [documentation technique](https://www.notion.so/3ea173c57e0481e383b1eadbe67ad997)
confirmaient S13.4G. La page projet était encore à S13.3D, REPRISE à S13.3A.
L'ancien REPRISE et l'ancienne roadmap sont archivés dans `docs/archive/`.

Le script Downloads S13.4H a été inspecté, copié sans changement, puis exécuté.
SHA256 du script :
`7836dbadaa819c2fcb52bbc3f5c5cd083515c6f50927459ccb9291f9a60f2783`.
Ses imports et sorties sont locaux : aucun module device ni commande hardware.

L'état matériel ne doit pas être déduit de ces images canoniques. Notion
rapporte un boot finalement stable avec S13.2A AFTER toujours présent. Toutefois,
`work/reports/s13_4b_restore_before.txt` indique un restore D3+D5 terminé jusqu'à
ProcessInfo et `work/repro/s13_3_one_sector_firmware/restore_protocol_complete.json`
contient `verify_restored_required: true`. Aucun `verify_restored` séparé n'a été
trouvé dans les artefacts examinés. Cela ne prouve ni une restauration vérifiée
ni l'état actuel du téléphone. Aucune de ces opérations historiques n'a été
réexécutée ici.

## Entrées exactes

| Entrée | SHA256 |
|---|---|
| ALICE U, taille `0x157BB4` | `7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea` |
| ZIMAGE U, taille `0x185E98` | `85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954` |
| Dump2 canonique, taille `0x400000` | `2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922` |
| `7lzma.exe` donor | `092190b3504bd433019a8c211f16b4f8c01817c0464c9d178075470f228aabd8` |

Adresses ALICE runtime : base `0x1024EC00`. ZIMAGE runtime : base `0xF023CA50`.
Les offsets flash ci-dessous sont des offsets physiques dans le dump, pas des
adresses runtime.

## S13.4H — sortie du script fourni

Table `F0345E68` : 58 lignes, 53 callbacks distincts, cinq groupes d'alias.
Le groupe Image contient exactement `0x8313` et `0x8321`, tous deux vers
`F02F3F85`. Audio `0x8928 -> 1033D841` est inchangé.

| ID | Champ callback runtime | Offset ZIMAGE | Avant | Après |
|---|---|---|---|---|
| `0x8313` | `F0345EBC` | `0x10946C` | `F02F3F85` | `1033D841` |
| `0x8321` | `F0345EC4` | `0x109474` | `F02F3F85` | `1033D841` |

Diff exactement huit octets en deux plages de quatre octets ; taille inchangée.
SHA256 logique D :
`778b89f149e0600dcdca38b8f878fa046fdbffa1ddbaec645af70f6b56324078`.
H ne prouve pas l'idempotence : son propre verdict la laisse ouverte.

Sortie complète originale :
`work/reports/s13_4h_dual_row_alias_idempotence_audit.txt`.
Manifeste et binaire : `work/candidates/s13_4h/`.

## S13.4I — correction des bornes et audit de registration

Le vrai core couvre `10301910..10301953`, avant le literal `10301954`.
La fenêtre `0x120` de H incluait plusieurs fonctions suivantes : ses dix appels
comptés ne sont pas dix appels du core. Le core réel contient cinq callsites.

Les registrars A/B/C utilisent les canaux 0/2/1. Le core consulte
`F00BAAB9[channel]`, copie éventuellement des pointeurs de contexte puis appelle
le setter `1031145C`. Celui-ci écrit un emplacement fixe, et ne crée aucune liste.
Pour les trois registrations natives, les slots sont :

- A : `F00BAD70 = 1033E815` lorsque le canal est autorisé ;
- B : `F00BAD90 = 1033E815` lorsque le canal est autorisé ;
- C : `F00BAD80 = F02E18BD` lorsque le canal est autorisé.

Les veneers ARM sont validés par leurs huit octets exacts :

| Veneer | Cible Thumb | Effet |
|---|---|---|
| `102FB97C` | `F02B9EF1` | store à `F00B1568` |
| `102FBCE4` | `F02D1EC9` | store à `F00B1578` |
| `102FB984` | `F02F5FC9` | store à `F00B156C` |

Le wrapper B réécrit aussi son miroir après le retour du core, même si le core
est verrouillé. Cette écriture supplémentaire est un store fixe identique.
`10316898` et `10314468` copient des pointeurs via `1031E680 -> 10318D80` dans
la table `F00B661C`; ils n'appellent pas ces pointeurs.

### Émulation des octets natifs

Unicorn 2.1.4 exécute le callback `1033D841` et ses helpers, sans mocks.
Tout passage hors des intervalles de code audités ou toute écriture globale
hors de l'allow-list échoue. Une limite de 10000 instructions impose le retour.

- 27 combinaisons de locks (0 / 1 / autre représenté par 2), trois canaux ;
- 64 combinaisons des quatre classes de branches contexte, trois canaux ;
- 1728 cas, chacun avec deux appels successifs ;
- RAM environnante pseudo-aléatoire reproductible, sans changement externe
  entre les appels ;
- comparaison de l'intégralité du MiB de RAM globale après un puis deux appels ;
- 155 instructions distinctes exécutées ; stores globaux sur 15 adresses fixes ;
- tous les cas PASS. Scratch de pile et registres CPU exclus de l'équivalence.

Conclusion bornée : état global de registration idempotent dans ce domaine,
sans accumulation de callbacks. Ce n'est pas une preuve du lancement Audio,
des effets d'une réentrance, d'accès concurrents ou d'une action UI réelle.

### Deux appels indirects dans le dispatcher

`1033679E` appelle le callback de registration résolu. Le dispatcher lit ensuite
le slot `(channel=0,index=1)`, restaure sa valeur initiale via `1031145C`, puis
`103367E6` appelle l'init capturé si non nul et différent de la valeur initiale.
Ainsi, « une résolution -> un callback de registration » ne veut pas dire
« un seul appel indirect au total ». Deux événements peuvent conduire à deux
lancements ; l'idempotence des stores de registration ne les rend pas équivalents.
Le resolver dynamique peut aussi prendre priorité sur la table statique.

Rapports : `work/reports/s13_4i_registration_state_audit.{txt,json}`.

## S13.4J — résultat physique, changement de portée

Le compresseur `7lzma etp input output ALICE` reproduit le stream canonique
**byte-perfect**, SHA256
`f7152fde422628928e47e1a5cf6f60e538999367f56fba4f6a5bab07e778ae6a`.
Le décodage `dtp` du canonique puis de D redonne exactement leurs entrées.

Le stream D passe de 987903 à 987827 octets (76 de moins), SHA256
`87b2fe99e3262f9b91e0c661dac006843dc5b17bba04c888e67ed04cdd93bd6e`.
La taille décompressée, les propriétés LZMA et le preset ALICE restent identiques.

Repack expérimental, sans relocation :

- stream situé à l'offset flash `0x04C270` ;
- longueur compressée au champ `0x04C264`, actualisée ;
- 76 octets libérés remplis de FF à l'intérieur de l'ancien slot ;
- adresses VIVA/ZIMAGE/BOOT/DCM/ALICE et longueur VIVA conservées ;
- tout `0x13D570..EOF` byte-identical au dump canonique ;
- BOOT décompressé avec le preset ALICE inchangé : SHA canonique exact ;
- aucune inclusion de l'ancien hook ALICE S13.2A.

**384255 octets physiques modifiés, 96 secteurs de 4 KiB** :

- `0x04C000` : un octet du champ de longueur, uniquement des bits 1 -> 0 ;
- 95 secteurs contigus `0x0DF000..0x13DFFF`, tous avec transitions 0 -> 1 ;
- plage globale des différences : `0x04C264..0x13D56E` (non contiguë).

SHA256 image expérimentale 4 MiB :
`a2bc044a36db4210877d57a5dc3341be8c76d2a49c3c435371ce4f5de0af1cc6`.
Elle repose sur le dump canonique, **pas sur l'état matériel actuel** et ne doit
pas être flashée entière. Le manifeste détaille tous les secteurs, hashes,
différences et transitions NOR ; les paires avant/après sont des comparaisons
canoniques, pas des rollbacks frais du téléphone.

Artefacts : `work/candidates/s13_4j/manifest.json`,
`canonical_sector_comparison_NOT_FOR_WRITE/`,
`candidate_D_CANONICAL_BASELINE_NOT_FOR_FLASH.bin`.
Rapport : `work/reports/s13_4j_zimage_dual_row_repack.txt`.

## Prochain gate : S13.4K, décision sur l'empreinte physique

Le harness one-sector S13.3 ne convient pas : ne pas remplacer ses constantes
par celles de D. La validation logique n'autorise pas une séquence de 96 writes.

Prochaine investigation hors ligne : étudier une route ALICE vers le callback
Audio complet qui réduise le nombre de secteurs, puis comparer sa sémantique au
candidat D. Point de départ : fallback du resolver `1034C806..1034C80E`, en
préservant le lookup dynamique et les IDs non ciblés. Ne pas réutiliser le hook
inefficace S13.2A ni supposer qu'un emplacement libre est une code cave valide.
Si D reste choisi, il faudra un protocole de reprise multi-secteur explicite et
un plan matériel séparé, avec validation fraîche de l'état restauré et rollback.

## Reproduction

Depuis la racine du dépôt, Python installé dans le venv mtkclient :

```powershell
$F2Python = 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe'
& $F2Python research/f2/scripts/analysis/s13_4h_dual_row_alias_idempotence_audit.py
& $F2Python research/f2/scripts/analysis/s13_4i_registration_state_audit.py
& $F2Python research/f2/scripts/patching/s13_4j_zimage_dual_row_repack.py
```

H utilise le cwd. I/J calculent la racine depuis leur emplacement. Dépendances
locales : Capstone, Unicorn et le `7lzma.exe` de hash verrouillé. Toutes les
sorties binaires et les rapports volumineux restent sous `work/`, hors Git.
