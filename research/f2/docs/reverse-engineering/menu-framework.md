# Framework de menus — faits établis

## Descripteur de navigation

L’analyse statique d’ALICE montre l’utilisation cohérente des champs suivants :

| Offset | Rôle établi |
|---|---|
| `+0x14` | ID U16 du parent/menu courant |
| `+0x18` | ID U16 de l’élément sélectionné |
| `+0x40` | pointeur vers le tableau U16 des IDs enfants |
| `+0x48` | nombre d’enfants, obtenu dynamiquement |

`0x102BA458` copie l’ID sélectionné de `+0x18` vers `+0x14`, puis déclenche un rafraîchissement. `0x102731A0` demande la liste des enfants via l’API externe `0xF032ACDC` et leur nombre via `0xF02D8870`. Le buffer observé est alloué sur le heap ; `descriptor+0x40` pointe sur `heap_base+0x100`. Les éléments sont espacés de deux octets. `0x1024C4BC` recherche un ID sélectionné dans ce tableau et renvoie l’index correspondant.

## Ce qui reste inconnu

Les implémentations et données des APIs externes ne sont pas dans l’image ALICE étudiée. L’ID numérique du Main Menu, de Multimedia et de ses deux enfants n’est pas encore démontré. L’observation physique établit que le sous-menu Multimedia contient Image Viewer et FM Radio.

Voir les exports détaillés dans `research/f2/work/ghidra/alice_reports/`. Les anciens candidats non validés restent des hypothèses ; ils ne doivent pas être présentés comme des identifications.

## Pourquoi Audio/Video peuvent manquer

Le manuel NIKITI/Altice F2 décrit Audio Player et Video Player, mais le build lu dans l'appareil est `ALTICE_F2_DS_V02.1_181023_MP`. Le rapport FCC disponible pour le même modèle/HW V01 cite un build différent, `ELKI_DS_L_V01.2_181106_MP`. Comme la liste des enfants est fournie par le framework externe, une différence de variante/configuration ou de registre peut expliquer que seules Image Viewer et FM Radio soient visibles. Ce n'est pas encore prouvé : le binaire ELKI exact et les implémentations/data de l'API externe manquent. Ne pas ajouter un menu item avant d'avoir un launch handler valide.

Voir l'analyse des hypothèses dans `research/f2/work/ghidra/alice_reports/multimedia_app_presence_analysis.txt`.

Le tracé `research/f2/work/ghidra/alice_reports/multimedia_registration_launch_trace.txt` montre aussi que le handler d'activation local identifié ne fait qu'entrer dans un sous-menu lorsque l'enfant a des enfants; il ne lance pas un item feuille. Les handlers Image Viewer/FM Radio sont donc encore à rechercher dans le dispatcher ou registre externe, et aucune target Audio Player ne peut être insérée sans ce mécanisme.

Une seconde fonction ALICE, `FUN_102d43dc`, appelle les mêmes APIs plateforme de compte/IDs enfants. Elle cherche localement l'ID `parent+7` et son appelant indexe une chaîne formatée par le résultat. Ce cas confirme que les modules ALICE interrogent un registre de menus externe; il ne dévoile pas le registre d'applications ni le lancement des entrées feuille. Ne pas généraliser `parent+7` à Multimedia.
