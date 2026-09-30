# Décodeur MP3 Altice — preuve binaire du 29 septembre 2026

> Dossier S01 conservé comme preuve. L'état courant est dans
> [REPRISE.md](../../REPRISE.md). La recherche ultérieure a relié aud_player_media
> à l'ouverture DAF et identifié le chemin DCM : [S02](daf-open-dispatch-2026-09-29.md).
> Les « prochaines actions » ci-dessous décrivent la sortie de S01.

**MP3 decoder: PRESENT (code et intégration statique au composant DAF).**
**Lecture d'un fichier SD sur le téléphone: INCERTAINE, non testée.**

## Preuve d'identité du codec

Le module `dcm_010c.bin` contient 34 fonctions correspondant à la bibliothèque
SDK `hal/audio/lib/MTKRVCT31/SLIM/mp3_dec.a`, dont les trois entrées publiques.
16 250 octets sont comparés dans ces fonctions (16 934 octets au total) : tous
les octets hors emplacements de relocation correspondent. Certaines fonctions
correspondent aussi à la variante non-SLIM. Ce n'est donc plus une conclusion
tirée uniquement d'une chaîne de caractères ou d'un identifiant de module.

| Fonction identifiée | Adresse d'exécution | Taille | Octets comparés |
|---|---|---:|---:|
| MP3Dec_GetMemSize | `0xF03D850C` | 24 | 24 |
| MP3Dec_Init | `0xF03D8784` | 46 | 46 |
| MP3Dec_Decode | `0xF03D852C` | 572 | 488 |
| MP3_DecodeLayer3 | `0xF03D8990` | 928 | 844 |
| MP3_Dequantize | `0xF03D8D30` | 2764 | 2600 |
| MP3_SubbandSynthesis | `0xF03DB710` | 1392 | 1388 |

Plage DAF : `[0xF03D84E0, 0xF03DF808)`, 29 480 octets, en-tête de 44 octets
inclus. SHA-256 :
`04cbf133ef50408dbb2203cd6306890c0aa2bc804bcc39d2fb890d1bc19717c7`.
L'en-tête interne confirme module `0x010C`, pool 5, groupe 11 et base
`0xF03D84E0`. L'overlay wavetable partage cette base : il ne faut pas le charger
simultanément dans le même espace Ghidra.

Le manifeste d'extraction rattache VIVA octet pour octet au dump 2 du téléphone
(SHA-256 `2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922`).
Les signatures de bibliothèques servent à identifier du code déjà présent dans
ce dump, pas à importer un décodeur étranger dans le firmware.

## Correction du mapping ALICE

La table de la ROM aux offsets fichier `0x5BA8/0x5BAC` contient
`0x1024EC00 / 0x00157BB4` : base d'exécution et taille d'ALICE.
La taille correspond exactement aux 1 407 924 octets décompressés.

L'ancienne base d'analyse `0x101812C4` correspondait à la position dans le
conteneur et ne doit plus servir comme adresse d'exécution. Pour les positions
dans cette même image ALICE, ajouter `0x000CD93C` aux anciennes adresses.
Ne pas appliquer cette translation aux adresses F0, ROM ou à d'autres builds.
Les anciens graphes et conclusions d'absence de pointeurs doivent être réévalués.

Validation indépendante : les quatre pointeurs absolus enregistrés par
`0x10368B44` retombent à cette base sur des callbacks cohérents Start, Stop,
Process et SetParameter. Les appels vers la ROM redeviennent également cohérents.
Le constructeur `aud_player_media` anciennement nommé `0x102362A4` se situe ainsi
à `0x10303BE0`; son chemin fichier reste à reconstruire.

## Appels et interface retrouvés

Les noms DAF ci-dessous sont des identifications structurelles par comparaison
avec `hal/audio/src/common/src/DafDecoder.c`, et non des symboles conservés dans
le binaire. Les cibles MP3 publiques sont, elles, identifiées par leurs octets.

| Rôle | Adresse ALICE réelle | Preuve |
|---|---|---|
| DafDec_GetMemSize | `0x10368B0C` | Appel `0x10368B16 → 0x102FAF64 → MP3Dec_GetMemSize`, alignement des tailles et ajout de `0x1BC` |
| DafDec_Init | `0x10368B44` | Appel `0x10368B62 → 0x102FAF64 → MP3Dec_GetMemSize`, répartition buffers et enregistrement callbacks |
| dafDec_ResetMem | `0x10372008` | Appel `0x1037203C → 0x102FAB84 → MP3Dec_Init`, sauvegarde du handle |
| Traitement d'une trame | `0x10370AE4` | Appel `0x10370BF2 → 0x102FAB2C → MP3Dec_Decode`, buffers entrée/sortie et consommation des octets |
| Start | `0x1036C4E0` | Appelle ResetMem puis prépare le traitement |
| Process | `0x1036C410` | Appelle ResetMem au besoin puis la routine de trame |
| Stop | `0x1036C526` | Callback enregistré, met à jour l'état |
| SetParameter | `0x1036C4C0` | Callback enregistré |

Les trois veneers sont des instructions ARM `LDR PC,[PC,#-4]` suivies du
pointeur Thumb vers le codec. Le script d'audit vérifie chaque instruction
d'appel et chaque pointeur sur les fichiers locaux.

La routine de trame réclame au moins `0x1200` octets de sortie, appelle le codec,
lit fréquence/canaux/échantillons du handle puis notifie le nombre d'octets
produits. Cela établit un composant de décodage avec buffers PCM; le chemin
jusqu'au matériel de sortie n'est pas encore démontré.

Une table parser/décodeur est retrouvée dans ZIMAGE, offset `0x175154`
(adresse du mapping courant `0xF03B1BA4`) :

```text
10368BF5 10368BFD 00002000 00000002  # parser, noms à confirmer
10368B0D 10368B45 00001200 00000001  # GetMemSize / Init décodeur
```

Elle correspond à la structure `DafDecFuncArray` du SDK. Son consommateur
`DAF_Open` n'est pas encore identifié. Aucun pointeur absolu exact vers son
début n'a été trouvé dans le scan ALICE/ZIMAGE effectué; un adressage relatif
ou via une table englobante reste possible.

## Limites et prochaine action

La chaîne démontrée est : composant DAF → callbacks → init/décodage MP3.
Elle ne démontre pas encore fichier SD → sélection DAF → chargement overlay →
`aud_player_media` → sortie audio, ni un lancement UI.

La signature `Fraunhofer IIS MP3` reste localisée à `0xF034AC94` dans ZIMAGE;
sa référence d'utilisation n'est pas établie. L'identité du codec est prouvée
indépendamment par les fonctions de la bibliothèque.

**Prochaine action : retrouver le consommateur de la table parser/décodeur,
identifier `DAF_Open` et le chargement DCM `0x010C`, puis remonter le dispatch
de format vers `aud_player_media` à la bonne base ALICE.** Ensuite seulement,
chercher le handler File Manager et le frontend. Ne pas reprendre une recherche
de ROM manquante ou un test BROM pour des fonctions déjà extraites.

## Reproduction et artefacts

Depuis la racine du dépôt :

```powershell
.venv\Scripts\python.exe research/f2/scripts/analysis/match_mp3_library.py
.venv\Scripts\python.exe research/f2/scripts/analysis/audit_mp3_bridge.py
```

Le premier script compare les symboles ELF32 des archives, masque les octets
de relocation et contrôle les SHA-256 des composants contre le manifeste.
Le second vérifie le mapping, quatre appels, les veneers, quatre callbacks et
la table parser/décodeur. Ils ont tous deux été exécutés avec succès.

Rapports détaillés locaux sous `work/ghidra/alice_reports/` :
`mp3_library_matches.json`, `mp3_library_provenance.json`,
`mp3_bridge_audit.json`, `mp3_runtime_functions.txt`, `mp3_decoder_verdict.txt`.
Les rapports `mp3_bridge*.txt` antérieurs à l'import runtime emploient encore
la base historique : préférer `mp3_runtime_functions.txt`.

Projet distinct : `Altice_MP3_Runtime_20260929`, ALICE brute importée en
`ARM:LE:32:v5t` à `0x1024EC00`, ROM, BOOT_ZIMAGE, ZIMAGE et overlay DAF ajoutés
par `PrepareMp3Image.java`; décompilation ciblée par `InspectMp3Bridge.java`.
Les anciens projets sont conservés. Aucun accès au téléphone, aucune écriture
firmware, NVRAM ou calibration n'a été effectué.
