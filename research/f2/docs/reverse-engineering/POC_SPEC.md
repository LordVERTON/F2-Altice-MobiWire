# Spécification offline — POC construct → Open → Play

29 septembre 2026. **Brouillon étayé, non prêt pour injection.**
Preuves et hashes : [rapport S09](s09-file-path-and-minimal-player-2026-09-29.md).
Aucun binaire produit, aucun dump modifié, aucun accès au téléphone.

## Contrat et ABI observés

Cible ARM little endian, callbacks Thumb; adresse de code + bit 0 pour un
pointeur d'appel indirect. Ne pas appeler les veneers ARM comme du Thumb.

| Opération | Code Thumb | Entrée | Sortie connue |
|---|---|---|---|
| construct | 0x10303BE0 | pas d'argument métier | r0=objet 0x84 octets |
| Open | 0x1028D230 | r0=player, r1=&cfg | r0=0 succès |
| Play | 0x1028D394 | r0=player | mapping public non établi |
| Stop | 0x1028D4C0 | r0=player, MHdl non nul requis | mapping public non établi |
| Close | 0x1029D3BC | r0=player | mapping public non établi |
| Destroy | 0x1028D0D4 | r0=player | 0 après appel libération |

**CONFIRMÉ DANS ALTICE** : dispatch de callbacks de l'objet aux offsets
0,4,8,0xC,0x10,0x14,0x18,0x1C,0x20. Open conserve MHdl à +0x28;
callbacks applicatifs à +0x7C/+0x80. Construct alloue et met à zéro 0x84 octets.

```c
// Modèle 32 bits, pas une définition de headers officiels.
struct cfg_altice {
    uint32_t unk00;        // 00 : zéro proposé, rôle non observé
    uint16_t *file_name;   // 04 : UTF-16LE, terminé par zéro
    void *data_p;          // 08 : NULL en mode fichier
    uint32_t data_len;     // 0C : zéro
    uint8_t format;        // 10 : dérivé du nom en mode fichier
    uint8_t pad[3];
    void *cb_fct;          // 14 : NULL proposé, branche spécifique à valider
    void *cb_param;        // 18 : NULL proposé
}; // 0x1C, alignement proposé 4
```

## Drive et chemin

Ne pas utiliser la lettre d'un volume Windows. Ne pas hardcoder E/F/G.

- POC 1, candidat SD strict : service Thumb `0xF0229230`, r0=0x10,
  r1=1, r2=1. Cet appel existe dans l'initialiseur Altice de la table de drives.
  Son association à la carte amovible est **INFÉRÉE** par comparaison SDK.
- Conserver le résultat signé avant toute conversion; rejeter erreur, zéro
  ou valeur hors A..Z. Vérifier disponibilité via le service natif étudié
  `0xF0216E2C(drive,0)`; son contrat complet reste à consolider.
- Ne pas utiliser le getter audio avec repli pour un POC censé lire uniquement
  la SD : il peut sélectionner le drive public et tronque les erreurs.
- Construire le chemin UTF-16LE `[drive, ':', '\\', 'A','u','d','i','o','s','\\',
  't','e','s','t','.','m','p','3',0]`. `test.mp3` est un nom proposé pour le POC,
  pas un fichier observé sur l'appareil. Ce chemin fixe exige 19 WCHAR = 38 octets.
- Le formatter `0xF022DC34(dst, ascii_format, drive)` existe, mais n'a pas de
  borne observée. Pour un stub minimal, préférer une construction bornée locale.
- POC 2 : recevoir et copier le chemin complet choisi via le File Manager;
  la fonction et le message Altice de sélection restent à identifier.

## Pseudo-code conceptuel

```c
// Ne pas compiler/injecter avant levée des hypothèses ci-dessous.
if (session.busy) return;
int drive = native_get_drive(0x10, 1, 1);
if (drive < 'A' || drive > 'Z') return;
if (native_drive_status(drive, 0) != 0) return;
build_utf16_path_bounded(session.path, drive, "Audios\\test.mp3");
zero(session.cfg);
session.cfg.file_name = session.path;
session.player = construct();
if (!session.player) return; // allocation interne peut avoir asserté avant
int rc_open = session.player->Open(session.player, &session.cfg);
if (rc_open != 0) {
    // Open backend NULL appelle déjà Close; FSAL failure a un autre chemin.
    // Cleanup spécifique selon le chemin, à valider avant implémentation.
    record_open_failure(rc_open);
    return;
}
session.opened = true;
session.busy = true;
session.rc_play_raw = session.player->Play(session.player);
// Ne pas détruire player/cfg/path au retour de Play.
// Un retour public de Play n'est pas assimilé à succès sans preuve.
```

Le bloc d'erreur reste volontairement non exécutable : sa libération sera
spécifiée après vérification de l'ownership et des callbacks. Ce pseudo-code
n'est donc pas un stub prêt à déployer et ne prétend pas éviter toute fuite.

## Registres, stack et contexte

**Proposition ABI à respecter** : r0-r3/r12 et flags volatils; préserver r4-r11,
sp et retour; maintenir sp aligné sur 8 à chaque appel. Utiliser BLX avec le
bon bit de mode. Les pointeurs de fonctions issus de l'objet portent déjà ce bit.
Ne pas dépendre du contenu initial de r1-r3 pour Play.

Frames visibles : construct 8 octets; Open 20+28=48 octets; Play 24 octets;
ce ne sont pas des maxima transitoires, car les sous-appels allouent également.
Pas de buffer chemin durable sur la stack d'un handler qui retourne.
Contexte de tâche requis, réentrance et synchronisation média **À VÉRIFIER**;
aucun appel depuis IRQ ou callback choisi au hasard.

## Lifetime et cleanup

| Objet | Proposition conservatrice | Preuve / limite |
|---|---|---|
| player | conserver de construct jusqu'à arrêt et fermeture établis | MHdl, FSAL, buffers et callbacks résident dans l'objet |
| cfg | session persistante jusqu'à fermeture | champs copiés visibles; propriété des pointeurs transitifs non établie |
| path | session persistante UTF-16 jusqu'à fermeture | FSAL peut retenir des informations; ne pas supposer une copie complète |
| callback | NULL initialement, à valider | branche alternative de DAF_Open; fonctionnement non prouvé |
| buffer Play | ownership natif self+0x78 | allocation/libération observées, fin asynchrone à suivre |

Ordre **proposé, pas encore validé** : Stop → attendre quiescence → Close →
Destroy → effacer les pointeurs de session. Stop déréférence MHdl sans garde;
ne jamais appeler Stop si Open n'a pas fourni de MHdl. Close vérifie MHdl,
appelle MHdl+0x108, remet +0x28 à zéro, ferme FSAL si +0x6C non nul.
Destroy appelle seulement le service de libération via 0x102FD08C : aucun
Stop/Close implicite observé. Les doubles fermetures doivent être évitées.
Après échec Play, ne pas libérer tant que l'état et les opérations en vol
ne sont pas identifiés. Les échecs FSAL=4, backend=7 et sélection=8 ont des
trajets différents; traiter chaque ownership explicitement.

## Emplacement, taille et hook candidats

- **Aucune cave ni adresse d'injection validée.** Les plages remplies de zéro
  ou FF et les zones DCM peuvent être réutilisées au runtime; leur aspect ne
  prouve pas qu'elles sont libres.
- Stratégie candidate : code Thumb dans une région dont allocation, mapping,
  exécution et durée de vie seront prouvés, avec reconstruction du conteneur
  ALICE/VIVA depuis dump2. Aucune écriture brute dans ALICE canonique.
- Budget de travail proposé, non mesuré : 0x200 octets de code, 0x1C de cfg,
  38 octets de chemin fixe (ou 520 pour une capacité choisie de 260 WCHAR),
  pointeurs/état alignés. Les 0x84 de player et buffers backend sont alloués
  nativement en supplément; aucune limite globale de RAM/stack encore prouvée.
- Hook candidat fonctionnel : événement UI explicite après initialisation
  stockage et média, dans le contexte natif approprié. **Adresse inconnue**.
  Ne pas détourner Image Viewer/FM à ce stade.
- `0x10343B2C` sert de preuve de sélection/préférence, pas de hook recommandé :
  le chemin appelle aussi les routines de persistance. Ne pas le réutiliser
  pour un POC sans écriture NVRAM.
- Ne pas appeler `0xF02BA560` pour obtenir un chemin : le builder de playlist
  contient des opérations filesystem pouvant créer un répertoire.

## Rollback et validation avant toute écriture

Construire ultérieurement une image séparée depuis dump2 hashé; journaliser
chaque offset NOR et plage décompressée, octets originaux/nouveaux, justification,
hash avant/après. Vérifier redécompression et équivalence des zones non visées.
Rollback offline : appliquer le diff inverse et obtenir exactement le hash
canonique. Rollback appareil : procédure d'écriture/read-back/restauration à
préparer et valider séparément; elle n'est pas acquise par une égalité offline.
Le flash et les tests speaker/jack restent des étapes futures non autorisées
par la phase actuelle. Le stub ne doit jamais forcer le speaker.

## Hypothèses bloquant une spécification figée

1. Construction DAF avec callback NULL : quels composants sont créés et
   lesquels MHdl.Play utilise-t-il ensuite ?
2. Quiescence Stop, fin de fichier, concurrence et libérations exactes.
3. Sélection amovible stricte et liaison catégories numériques ↔ labels UI.
4. Contexte d'appel, emplacement exécutable, hook et reconstruction compressée.

**Prochaine action unique** : suivre `0xF02E1B00 → 0xF0297DC4` et comparer
les champs initialisés aux accès de `0x1035FB00`, puis suivre leur fermeture.
