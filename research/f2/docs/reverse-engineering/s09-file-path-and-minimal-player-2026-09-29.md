# S09 — Chemins fichiers et lecteur minimal Altice

Date : 29 septembre 2026. Analyse statique hors ligne, sans écriture appareil.
État courant : [REPRISE](../../REPRISE.md). Spécification : [POC_SPEC](POC_SPEC.md).

## 1. Contexte

S09.7 suit la consigne utilisateur complète, qui remplace l'ancien checkpoint
S03. Objectif : retrouver comment le firmware physique construit un chemin
audio avec un drive dynamique, puis spécifier construct → Open → Play.
Les informations S08/S09 transmises par l'utilisateur sont recoupées avec les
octets avant d'être reprises comme preuves. Aucun donor ne sert d'entrée aux audits.

Vocabulaire : **CONFIRMÉ DANS ALTICE** = octets/flux statique identifiés;
**INFÉRÉ** = interprétation dont une dépendance manque;
**RÉFÉRENCE DONOR/SDK** = nom ou comparaison externe;
**À VÉRIFIER** = propriété non établie, notamment tout comportement sur appareil.
« Confirmé » ne signifie jamais « exécuté avec succès sur le téléphone ».

## 2. Artefacts canoniques

- `data/dumps/mobiwire_dump_2.bin` : entrée physique canonique, 0x400000 octets.
- `mobiwire_dump_3.bin` : égalité complète des octets vérifiée par le nouvel audit.
- Dump 1 exclu de toute base de patch.
- VIVA physique : dump2 `[0x4C20C,0x2950C8)`, taille 0x248EBC.
- ALICE compressé : dump2 `[0x18129C,0x2950C8)`, taille 0x113E2C.
- `work/extracted/altice_alice/alice-py.bin` : 0x157BB4 octets.
- `work/extracted/altice_platform/{zimage,boot_zimage,dcm_010c}.bin`.

Le nouvel audit compare le VIVA du package à la tranche physique complète.
Il contrôle les sorties ALICE/ZIMAGE/BOOT par hashes épinglés, sans réécrire ni
réextraire ces fichiers. Le pipeline antérieur reste documenté dans S01/S02.

## 3. Hashes SHA-256

| Artefact | SHA-256 |
|---|---|
| dump2 et dump3 | `2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922` |
| VIVA physique | `9903e1109a66e3d547f18dfad0d3e2cf0f63563ebd9072a2abbed98e2a945696` |
| ALICE compressé | `8a06970667c6af37f7a6b1fb28dde0622e396fccd5c2a0b450bd795a0257988f` |
| ALICE décompressé | `7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea` |
| ZIMAGE | `85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954` |
| BOOT_ZIMAGE | `aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e` |
| DCM 010C (S02) | `04cbf133ef50408dbb2203cd6306890c0aa2bc804bcc39d2fb890d1bc19717c7` |

`input_rom_sha256=dbebc45c8e4334e61fd85bdab8988d4f271599263ce209520e36f571f3f4e37c`
désigne le ROM logique du package, jamais le NOR complet. Les nouveaux scripts
lisent les adresses ROM dans la tranche du dump physique à base 0x10000000.

## 4. Bases runtime

| Image | Base | Taille / fin exclusive |
|---|---|---|
| ALICE | `0x1024EC00` | 0x157BB4 |
| ZIMAGE | `0xF023CA50` | 0x185E98 / `0xF03C28E8` |
| BOOT_ZIMAGE | `0xF01F19E4` | 0x4B06C |
| DCM 010C | `0xF03D84E0` | 29480 octets |

`0x101812C4` appartient au header compressé; ce n'est pas la base du code.
La translation historique ALICE +0xCD93C ne s'applique pas aux autres images.

## 5. Preuves S08 recoupées

**CONFIRMÉ DANS ALTICE** : 34 fonctions MP3 (audit S01), DAF_Open
`0x10358254` (S02), littéral `0x10358334=0x1035FB01`, Play Thumb `0x1035FB00`.
Ce Play appelle DPMGR_Load `0x103162A8` avec région 3 à `0x1035FB34`, puis
des callbacks de composants; le mapping région 3 → DCM 0x010C est audité en S02.
À `0x1035FB60`, appel du veneer Media_SetAudioFormat avec r0=5;
à `0x1035FB82`, appel AudioDrain via `0x102FCD5C → 0xF02AE5F0`.
AudioDrain configure et démarre des composants par appels indirects
(`0xF02AE62C`, `0xF02AE640`).

Les noms parser/decoder/PcmSink reposent sur les tables S01/S02 et la comparaison
SDK. L'identité de tous les objets indirects au runtime et la sortie physique
speaker/jack restent **À VÉRIFIER**. Aucun réglage de routage n'est ajouté.

## 6. Formats reconnus

**CONFIRMÉ DANS ALTICE**, fonction `0xF02ADD64`, normalisation a–z vers A–Z,
comparaisons UTF-16 et constantes de retour :

| Suffixe | Type |
|---|---|
| .VM | 0x02 |
| .IMY | 0x12 |
| .MID / .MIDI | 0x11 |
| .WAV | 0x0D |
| .PCM | 0x07 |
| .DVI | 0x0B |
| .MP3 | 0x05 |
| .MP2 | 0x20 |
| .AMR | 0x03 |
| .AAC | 0x06 |
| .JPG | 0x6E |

Le second test JPG utilise la même adresse `0xF02ADEE0`; son retour 0x6F est
inatteignable après le premier match, sous l'hypothèse usuelle d'une comparaison
déterministe. L'audit fige les chaînes et les instructions de retour; le
désassemblage complet conserve les branchements et les ADR.

## 7. Formats Open compilés

| Type | Bloc de sélection | Handler | Conclusion statique |
|---|---|---|---|
| VM 2 | 0x1028D2B6 | 0x1029D3AE | stub retourne NULL |
| AMR 3 | 0x1028D2D8 | 0x10357420 | pointeur de handler présent |
| MP3 5 | 0x1028D2E8 | 0x10358254 | DAF_Open audité |
| AAC 6 | 0x1028D2F0 | 0x10357368 | pointeur de handler présent |
| PCM 7 / DVI 11 | 0x1028D2C6 | 0x1029CF68 | handler commun présent |
| WAV 13 | 0x1028D2EC | 0x1029D3B2 | vrai constructeur média |
| MID 17 | 0x1028D30C | erreur 8 | selon interprétation switch8 |
| IMY 18 / MP2 32 | hors plage 0..17 | défaut | selon interprétation switch8 |

Les blocs, pointeurs et appels sont **CONFIRMÉS DANS ALTICE**. Leur sélection
par le helper switch8 reste **INFÉRÉE**; la consigne utilisateur la décrivait
comme confirmée, mais le corps du helper manque toujours aux images examinées.
Ne pas transformer la présence d'un handler en preuve de lecture du format.

WAV : `0x1029D3B6 → 0x102B44FC`, puis `0x102B453E → 0x1030996C`;
ce dernier construit un objet, écrit le type 0x0D à +0x27 et le retourne.
Il ne s'agit pas du stub VM adjacent.

## 8. ABI construct

`0x10303BE0` écrase ses registres d'arguments avant allocation : pas d'argument
métier observé. Allocation 0x84 octets, initialisation à zéro, retour r0=objet.

| Offset | Callback Thumb (adresse code sans bit 0) |
|---|---|
| +00 | Open 0x1028D230 |
| +04 | Close 0x1029D3BC |
| +08 | Play 0x1028D394 |
| +0C | Stop 0x1028D4C0 |
| +10 | Pause 0x1028D378 |
| +14 | Resume 0x1028D41C |
| +18 | Set 0x1028D43A |
| +1C | Get 0x1028D114 |
| +20 | Destroy 0x1028D0D4 |

+0x24 reçoit le retour du veneer 0x102FD3A4. Les pointeurs stockés ont le bit
Thumb. Le constructeur ne contient pas de gestion explicite d'un retour NULL
de son allocateur avant initialisation : contrat de l'allocateur à vérifier.

## 9. ABI Open

r0=self, r1=cfg. Champs observés : +4 chemin UTF-16, +8 buffer, +0xC taille,
+0x10 format buffer, +0x14 callback, +0x18 paramètre callback. Taille minimale
proposée 0x1C, champ +0 inconnu et padding zéro. Mode fichier FSAL=4;
succès FSAL=300; succès public Open=0; échec FSAL=4; backend NULL=7 après Close.
Le MHdl est stocké à self+0x28, FSAL intégré à self+0x2C.

**Limite nouvelle** : cfg.callback=NULL donne r0=NULL au backend (0x1028D328).
DAF_Open branche alors vers `0x102FC1B4 → 0xF02E1B00`, tandis que callback
non nul utilise la construction composant à 0x102FC1BC avec DPMGR.
DAF_Open installe ensuite le même MHdl.Play. L'acceptation de NULL est confirmée,
mais l'équivalence fonctionnelle des deux constructions n'est pas démontrée.

## 10. ABI Play

`Play(self)` : seul r0 d'entrée est utilisé. self+0x6D non nul → retour 1.
Sinon allocation/contexte à self+0x78, appel MHdl+0x78, puis MHdl+0xF0.
Retour backend 0xC8 → self+0x6D=0x1E. Mapping public via 0x102FE668.
Le démarrage et la durée de vie asynchrones restent à vérifier.

## 11. Limites du helper switch8

Veneer ARM 0x10015BD4 → 0x70008C68, hors images disponibles.
Les tables compactes sont auditées octet par octet; leur convention ne peut
pas être présentée comme une exécution observée. Le mapping intégral des
retours publics Play/Stop/Close n'est pas prouvé. Open=0 vient d'un retour
direct, sans dépendance à ce helper.

## 12. Chemins `%c:\`

**Correction de la prémisse** : aucune chaîne monolithique `%c:\Audios\`.
Deux objets sont adjacents : format ASCII `%c:\\0`, alignement, suffixe UTF-16.

| Offset ZIMAGE | Runtime | Objet |
|---|---|---|
| 0x772D8 | 0xF02B3D28 | `%c:\` ASCII |
| 0x772E0 | 0xF02B3D30 | `Audios\` UTF-16 |
| 0x7DB80 | 0xF02BA5D0 | `%c:\` ASCII |
| 0x7DB88 | 0xF02BA5D8 | `@Playlists` UTF-16 |
| 0x7DBA0 | 0xF02BA5F0 | `\` UTF-16 |
| 0x7DBA4 | 0xF02BA5F4 | `audio_play_list.sal` UTF-16 |
| 0xAD290 | 0xF02E9CE0 | autre format racine |
| 0xAEB78 | 0xF02EB5C8 | autre format racine |
| 0xAEC4C | 0xF02EB69C | autre format racine |
| 0xAFA88 | 0xF02EC4D8 | autre format playlist |

XREF exécutables identifiées par désassemblage depuis les fonctions :
0xF02B3C58→0xF02B3D28; 0xF02B3C60→0xF02B3D30;
0xF02BA56A→0xF02BA5D0; 0xF02BA572→0xF02BA5D8;
0xF02BA5B4→0xF02BA5F4. Autres sites : 0xF02E9C10/18,
0xF02EB56E/576, 0xF02EB606/60E. Il s'agit d'ADR Thumb, donc l'absence de
pointeurs absolus exacts n'est pas une absence de références.

## 13. Analyse du drive

### Construction effective

À 0xF02B3C04, r6=0xF00AD894. À 0xF02B3C56, `ldrb r2,[r6,#15]`.
0xF02B3C58 charge le format via ADR; r0 pointe sur le buffer stack; appel
0xF022DC34 à 0xF02B3C5C. Puis ADR du suffixe et appel 0xF02E2A08.

0xF022DC34 consomme un format ASCII et les arguments variadiques sauvegardés.
Le cas `%c` (test 0x63 à 0xF022DC56) lit un argument 32 bits à 0xF022DC8A,
écrit son octet bas, puis zéro, et avance la sortie de deux octets.
**CONFIRMÉ DANS ALTICE** : formatter ASCII → chaîne UTF-16LE.
**RÉFÉRENCE DONOR/SDK** : nom `kal_wsprintf`.

0xF02E2A08 appelle 0xF02AC004 : longueur UTF-16 via 0xF02DDCBC,
destination += longueur*2, puis copie terminée par deux zéros via 0xF02DD624.
**CONFIRMÉ DANS ALTICE** : concaténation UTF-16, sans borne observée.
Nom `mmi_ucs2cat` : référence SDK seulement.

### Préférence et drive courant

| Élément | Adresse | Preuve |
|---|---|---|
| contexte audio | 0xF00AD894 | littéraux ALICE et ZIMAGE |
| préférence de drive | +9 = 0xF00AD89D | getter, écriture 0x10343BF6 |
| drive courant | +15 = 0xF00AD8A3 | formatteurs et écritures |
| getter courant | 0xF02B8FE8 | fonction complète auditée |

Pseudo-code directement issu du getter :

```c
uint8_t choose_audio_drive(void) {
    uint8_t preferred = *(uint8_t *)0xF00AD89D;
    if (native_status(preferred, 0) == 0) // 0xF0216E2C
        return preferred;
    return (uint8_t)native_get_drive(8, 2, 0x18); // 0xF0229230
}
```

À 0x10343C18, appel via veneer 0x102FB754, puis stockage à +15.
Des gestionnaires de changement de drive mettent aussi +15 à jour
(0xF02EB3CC et 0xF02EB48E). Ne pas traiter le contenu RAM comme constant.
Le getter ne protège pas le POC contre une erreur négative tronquée sur 8 bits;
il faut valider la lettre et la disponibilité avant de construire le chemin.

Le SDK local `AudioPlayerPlayList.c:10379-10406` et `:18555-18578` montre
`mmi_audply_get_current_list_drv`, préférence montée sinon drive public.
Cette comparaison nomme le comportement déjà observé, sans en constituer la preuve.

### Index de stockage → lettre

0x10300DA4 initialise la table RAM à 0xF00EF090. Les appels observés sont :

| Index table | Appel natif (r0,r1,r2) | Emplacement WCHAR |
|---|---|---|
| 0 | (8,1,1) | table+0x12 |
| 1 | (8,2,1) | table+0x1A |
| 2 | (0x10,1,1) | table+0x22 |

Veneer 0x102FD54C → 0xF0229230 → 0xF0215C6C. Seuls les retours >0
sont stockés. Des racines WCHAR `lettre : \` sont aménagées avec stride 8.
0x102F1084(index) retourne le low byte du WCHAR table+0x12+8*index, ou 0
si index>=16. L'inverse 0x1030BC54 normalise les minuscules et cherche la
lettre dans les 16 entrées; échec=-1. 0x1035B810 donne un pointeur de racine.

0x103190B0 construit un masque des drives disponibles; 0x103163FA(mask,n)
sélectionne le n-ième bit puis appelle index→lettre. À 0x10343BB8 ce résultat
est ensuite stocké comme préférence à +9. Ainsi **l'index UI et la lettre ne
sont pas interchangeables**, et la préférence audio contient bien une lettre.

Le service 0xF0215C6C inspecte des structures runtime, compte des catégories,
consulte une table à 0xF022F544 et peut construire une lettre en ajoutant 0x42
à un ordinal. Il retourne aussi des erreurs négatives. Les contenus RAM
et le choix effectif monté ne sont pas observés dans un dump flash.

**INFÉRÉ / référence SDK** : catégorie 8=normal, 0x10=removable,
index 1=Phone/public et index 2=Memory Card, d'après les usages FS_GetDrive
du SDK (`AudioPlayerPlayList.c:8652-8658`). Les headers de constantes ne sont
pas présents dans la copie locale consultée. Les constantes et appels Altice
sont confirmés; le lien direct vers les libellés UI et les lettres effectives
reste **À VÉRIFIER**. Ne jamais choisir E/F/G depuis cette inférence.

## 14. Résultats S09.7 et reproduction

Le mécanisme numérique est établi jusqu'au service natif et à sa table runtime.
Pour un POC SD strict, le candidat observé est le service (0x10,1,1), sans
repli vers Phone, sous réserve de confirmer sa sémantique et son état monté.
Pour le POC 2, préférer le chemin UTF-16 complet du sélecteur natif, dont l'ABI
Altice reste à identifier. Ne pas appeler le constructeur de playlist pour
simplement obtenir une lettre : il peut ouvrir/créer des répertoires.

```powershell
.venv/Scripts/python.exe research/f2/scripts/analysis/analyze_audio_paths.py
.venv/Scripts/python.exe research/f2/scripts/analysis/audit_minimal_player_abi.py
.venv/Scripts/python.exe research/f2/scripts/analysis/audit_daf_open.py
```

Nouveaux résultats : 19 ancrages chemins, 31 ancrages ABI, 9 callbacks,
12 suffixes, 7 cas de dispatch interprétés. Rapports locaux :
`audio_path_audit.json`, `audio_path_evidence.txt`, `audio_drive_contexts.txt`,
`minimal_player_abi.json`, `minimal_player_abi_disasm.txt` sous alice_reports.
Les scans demi-mot signalent des candidats; seuls les flux relus depuis leurs
entrées et ancrés ci-dessus sont utilisés comme preuves. Les listings bruts
peuvent traverser des données après une fonction : ne pas les appeler du code.

## 15. Hypothèses

- Noms précis SDK des services et sémantique des catégories de stockage.
- Présence/initialisation du contexte audio lors d'un futur hook UI.
- Callback nul compatible avec un vrai Play MP3 malgré la branche alternative.
- Routage natif speaker/headset approprié, sans forçage ajouté par le POC.
- La présence des fonctions de playlist ne démontre pas un frontend accessible;
  elle interdit aussi de conclure sans preuve que tout frontend a été supprimé.

## 16. Éléments non démontrés

Lecture réelle, montage SD courant, lettres attribuées, liaison exacte des
labels Phone/Memory Card, UI Audio Player utilisable, ABI du sélecteur, thread
appelant requis, callbacks fin de lecture et délais d'arrêt, libération sûre
après Play, cave libre, hook sûr, patch, recovery d'écriture et read-back.
Les anciens rapports `filetype_mp3_dispatch.txt` et leur MP3→UNKNOWN sont
historiques; voir [index des preuves](../../EVIDENCE.md) et S02/S09.

## 17. Prochaine action unique

Tracer la construction **callback NULL** depuis `DAF_Open → 0xF02E1B00 →
0xF0297DC4`, vérifier les composants attendus par MHdl.Play et leur destruction.
Cela doit lever le principal risque de la spécification POC avant tout choix
d'emplacement ou hook. La liaison des labels UI pourra être vérifiée avec le
sélecteur lors du POC 2; aucune lettre n'a besoin d'être hardcodée.
