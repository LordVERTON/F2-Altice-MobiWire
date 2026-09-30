# S02 — Ouverture fichier, dispatch DAF et chargement DCM

Date : 29 septembre 2026. Analyse statique uniquement.
Pour reprendre la recherche, lire [REPRISE.md](../../REPRISE.md).

## Résultat

Le lien auparavant inconnu depuis `aud_player_media` est retrouvé : son
constructeur enregistre une fonction Open qui ouvre un fichier, détermine
son format, contient un bloc de sélection `DAF_Open`, puis appelle le handler.
`DAF_Open` construit le parser/décodeur identifié en S01 et encadre cette
construction par le chargement/déchargement DPMGR de la région MP3.

La reconnaissance `.MP3 → format 5` est vérifiée dans le binaire. Le bloc de
dispatch DAF et son appel sont vérifiés. L'association du cas 5 de la table
compacte à ce bloc est une **inférence étayée par la table et le SDK** : le
helper switch ROM `0x70008C68` n'est pas présent dans les images mappées.
Ne pas présenter ce dernier détail comme une exécution observée.

## Chaîne retrouvée et adresses réelles

```text
aud_player_media_construct  0x10303BE0
  interface.open           0x1028D230
    FSAL_Open              veneer 0x102FD48C -> 0xF020F04C
    med_get_media_type     veneer 0x102FBFC4 -> 0xF02ADD64
      comparaison .MP3 UTF-16 -> retourne 5
    switch compact         cas 5 -> bloc 0x1028D2E8 [inférence signalée]
    pointeur DAF_Open      littéral 0x1028D368 = 0x10358255
    appel BLX R6           0x1028D32A

DAF_Open                   0x10358254
  DPMGR_Load_Internal      0x103162A8, région 3
    mapToDCMId             0x102BDE68 : 3 -> 0x010C
    DCM_Load wrapper       0x10321808
      veneer 0x102F81A4 -> logique DCM 0xF020B6C8
      callback décomp.     0x102CB0AC
  MH_Component_Open        veneer 0x102FC1BC -> 0xF02AE548
    parser table           0xF03B1BA4
    decoder table          0xF03B1BB4
      GetMemSize / Init    0x10368B0C / 0x10368B44
  DPMGR_Unload_Internal    0x103162BC, région 3
    DCM_Unload wrapper     0x103217C0
      veneer 0x102F82AC -> logique DCM 0xF021A854
```

Les noms de fonctions sont des identifications par comportement et comparaison
au SDK; les adresses, instructions et constantes viennent d'Altice.

## Ouverture fichier et détermination du format

`0x10303BE0` alloue 0x84 octets. Le littéral `0x10303C50 = 0x1028D231` est
chargé puis stocké à l'offset 0 de l'interface : son callback Open.

Dans Open, `cfg+4` désigne le nom de fichier et `self+0x2C` le contexte FSAL.
La branche fichier utilise le mode 4, attend un retour 300, puis transmet le
nom au détecteur de type. La branche buffer utilise `cfg+8`, une taille
`cfg+0xC` et le mode 3. Cela correspond au code témoin `_aud_player_media_open`
(FSAL_READ_SHARED / FSAL_ROMFILE); aucune lecture effective de SD n'est réalisée.

Le détecteur à `0xF02ADD64` normalise en majuscules et compare des suffixes
UTF-16. À `0xF02ADDF8`, ADR pointe sur `.MP3` à `0xF02ADEB0`; après comparaison,
la branche d'égalité retourne 5 à `0xF02ADE02`. Il compare aussi `.MP2`, `.AMR`,
`.WAV` et d'autres suffixes. Ce n'est pas une association de lancement MMI :
c'est la reconnaissance interne de format par le moteur média.

## Limite du switch

L'appel à `0x10015BD4` passe par un veneer ARM vers `0x70008C68`, hors des images
analysées. Ghidra décompile seulement la première partie de Open et retourne
ensuite un faux aperçu incomplet du chemin; ne pas en déduire que DAF est absent.

Table brute à `0x1028D29E` :

```text
11 0c 0c 0c 1d 37 25 29 14 14 14 14 14 0c 27 27 27 27 37 00
```

Interprétation switch8 cohérente avec les branches et le source témoin : octet
de borne, offsets en demi-mots, puis défaut. Pour le format 5, l'octet à +6
vaut `0x25`; `0x1028D29E + 2*0x25 = 0x1028D2E8`. À cette adresse, LDR charge
`R6 = 0x10358255`, puis le flux rejoint le BLX R6 à `0x1028D32A`.
Cette interprétation est conservée comme inférence, faute de corps du helper.

## Pourquoi la recherche précédente de pointeur exact échouait

`DAF_Open` utilise le littéral `0xF03B1B60` à `0x103582EC`, puis ajoute `0x54`
pour le décodeur et retire `0x10` pour le parser. Aucun littéral exact des
deux adresses de table n'était nécessaire dans cette fonction.

Le binaire conserve aussi la chaîne
`hal\audio\src\v1\cmpdrv\daf_comp_drv.c` à `0x103582F4`, utilisée par les appels
DPMGR avec numéros de ligne. La branche handler nul ouvre uniquement un parser;
la branche handler non nul demande la région 3, construit les deux composants,
puis libère la région. La structure retournée reçoit le format 5 à +0x27.

## Chargement DCM

Le mapping binaire `0x102BDE68` renvoie `0x010C` pour la région 3, `0x010D` pour
la région 1 et -1 sinon, cohérent avec les overlays DAF et wavetable extraits.
La logique DCM sélectionne une entrée de registre, appelle son callback de
chargement si nécessaire et met à jour l'état des régions qui se chevauchent.

Le wrapper fournit le callback `0x102CB0AD` (Thumb) au chargeur. Sa routine
`0x102CB0AC` utilise un buffer de travail de `0x4000`, soustrait 13 octets à la
taille compressée, décale la source de 13, passe les propriétés LZMA de taille
5 puis entretient les caches. Cela correspond à `dcmgr_decomp_load` du SDK.

Ce résultat identifie le chemin logiciel prévu pour décompresser DAF. L'état
du registre DCM sur le téléphone et son activation réelle ne sont pas observés.
L'ouverture n'est pas la lecture : le codec est déchargé après la construction;
le rechargement au Play et le trajet PCM jusqu'à la sortie restent à vérifier.

## Interface aud_player_media pour la prochaine étape

| Offset interface | Rôle par comparaison SDK | Adresse Thumb sans bit 0 |
|---|---|---|
| +0x00 | Open | `0x1028D230` |
| +0x04 | Close | `0x1029D3BC` |
| +0x08 | Play | `0x1028D394` |
| +0x0C | Stop | `0x1028D4C0` |
| +0x10 | Pause | `0x1028D378` |
| +0x14 | Resume | `0x1028D41C` |
| +0x18 | Set | `0x1028D43A` |
| +0x1C | Get | `0x1028D114` |
| +0x20 | Destroy | `0x1028D0D4` |

Prochaine action : suivre Play et le callback `MHdl.Play` enregistré par
DAF_Open (littéral `0x10358334`), vérifier DPMGR au démarrage de lecture, puis
relier le composant de sortie audio. Chercher ensuite l'appelant natif de
cette interface et le lancement utilisateur. Ne pas confondre reconnaissance
interne `.MP3` avec option Lire du File Manager.

## Reproduction et preuves conservées

Entrées et mapping identiques à S01. `audit_daf_open.py` contrôle les hashes
ALICE/ROM/composants, 25 instructions ciblées, les veneers, chaînes et tables.
Il conserve explicitement la limite du switch dans son JSON.

```powershell
.venv\Scripts\python.exe research/f2/scripts/analysis/audit_daf_open.py
```

Résultat : PASS. Sortie : `work/ghidra/alice_reports/daf_open_audit.json`.
Décompilations dans ce même dossier : `daf_open_runtime.txt`,
`daf_dispatch_runtime.txt`, `daf_file_dcm_runtime.txt`.

Chaque export s'obtient par `InspectMp3Bridge.java`, projet
`Altice_MP3_Runtime_20260929`, `-process alice-py.bin -readOnly -noanalysis`.
Racines utilisées, dans l'ordre des trois rapports :

```text
thumb:10358254 thumb:103162a8 thumb:103162bc
thumb:1028d230 thumb:102bde68 thumb:10321808 thumb:103217c0 thumb:10303be0 thumb:f020b6c8 thumb:f021a854
thumb:f02add64 thumb:f020f04c thumb:102cb0ac
```

Les prototypes Ghidra sont incomplets sans analyse globale : par exemple le
quatrième argument parser/décodeur de MH_Component_Open manque dans le C exporté,
mais R3 est établi au désassemblage. Priorité aux octets et à la convention ARM.

Sources témoins locales : `media/audio/src/aud_player_media.c`,
`hal/audio/src/v1/cmpdrv/daf_comp_drv.c`, `hal/audio/src/v1/dpmgr.c`,
`hal/system/dcmgr/src/dcmgr_pl.c` dans `work/donor_repos/MT2503-2/`.
Ces sources orientent l'identification; les preuves Altice sont les octets
vérifiés et les décompilations. Aucun accès téléphone ni écriture firmware.
