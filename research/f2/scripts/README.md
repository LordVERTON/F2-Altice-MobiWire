# Scripts de recherche F2

Les scripts sont séparés par usage. Les commandes d’analyse sont en lecture seule sur les fichiers locaux ; les scripts d’acquisition USB sont des outils distincts et doivent être lus avant usage.

## Analyse

`analysis/` contient les inventaires, comparaisons de fonctions, analyses du framework de menus, rapports média et outils de préparation de témoins. Les scripts utilisent les chemins de `scripts/_paths.py` et attendent les sources sous `research/f2/data/` et les résultats sous `research/f2/work/`.

Lanceurs PowerShell :

- `analysis/run_extra_call_analysis.ps1` : réutilise les projets Ghidra existants et compare les exports QMobile/Altice.
- `analysis/run_f2_reference_analysis.ps1` : prépare puis compare un firmware témoin fourni en entrée.

Ces workflows supposent Ghidra installé localement ; vérifier les paramètres `-Ghidra` et `-Python` avant exécution.

## Ghidra

`ghidra/` contient les scripts Java à fournir à `analyzeHeadless -scriptPath` ainsi que des utilitaires Python pour lire les exports. Les bases de projets et exports sont sous `research/f2/work/ghidra/`.

## Acquisition

`acquisition/` contient les scripts de dump, identification BROM et extraction ALICE. Les scripts BROM peuvent effectuer des écritures de registres volatils pour accéder à la NOR ; ils ne sont pas des outils passifs. Ils ne doivent être exécutés qu’en connaissance de leur documentation et de leur effet.

## Outil ALICE

`../tools/unalice/` conserve l’extracteur et sa licence/notices. L’extraction produit des fichiers dans `work/extracted/`.
