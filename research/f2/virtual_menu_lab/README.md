# F2 Virtual Menu Lab

Laboratoire de simulation du registre et des menus
du firmware Altice/MobiWire F2 MT6261.

## Objectif

Tester, hors ligne, l'exposition virtuelle de
l'application Audio Player native 0x8928.

## Reference

- ZIMAGE base: F023CA50
- B702 record: F037BEA0
- B702 children: F0378720
- Current children: 8569, 87ED
- Audio application ID: 8928
- B703 boundary: F0378724

## Execution

Depuis la racine du depot :

    python research/f2/virtual_menu_lab/f2_virtual_menu.py

Rapport JSON :

    python research/f2/virtual_menu_lab/f2_virtual_menu.py --json

Tests :

    python -m unittest discover -s research/f2/virtual_menu_lab -p "test_*.py" -v

## Limites

Ce logiciel ne demarre pas le firmware ARM.
Il n'emule pas les peripheriques MT6261.
Les libelles sont des annotations de recherche.
Il n'execute aucun callback d'application.
Le mode Audio est une proposition de tableau virtuel.

Aucun firmware n'est modifie.
Aucun flash ou acces USB n'est effectue.
