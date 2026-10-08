# F2 Virtual Menu Lab V5 — UI observée + backend ZIMAGE

Cette V5 s'installe uniquement dans le **worktree émulation** `feature/f2-virtual-menu-lab`.
Elle **conserve** `f2_phone_ui_v4.py` (châssis dessiné), `f2_virtual_menu_v2.py` (lecteur ROM) et les fichiers V1–V4 dans l'historique Git, sans toucher à `main` ni à `mtkclient`.

## Architecture

- `ui_observed_registry.json` : grille 3×3 correcte, écrans photographiés, libellés, sous-menus, états visuels, softkeys et références des photos (aucune photo originale n'est distribuée).
- `rom_proven_registry.json` : ancrages ZIMAGE prouvés et mappings UI/ROM conservateurs. La FM radio a volontairement un ID `null`.
- `f2_phone_ui_v5.py` : interface graphique qui charge les manifestes ; le V4 est réutilisé uniquement pour la coque du téléphone et les primitives LCD.
- `test_phone_ui_v5.py` : contrôles automatiques de navigation et séparation entre UI observée, hypothèse de navigation et backend prouvé.
- `install_v5.ps1` : prévol worktree propre → copie des 4 fichiers → tests sans pycache → validation SHA256/registre du ZIMAGE → commit/push strictement sur la branche d'émulation. Ne copie jamais le dump.

## Provenance

Photos utilisateur : IMG_0833–0843 et IMG_0844–0863, octobre 2026.

**Navigation photographiée** : Main `Multimedia, Messaging, Call center / Camera, Phonebook, File manager / Profiles, Extras, Settings` ; listes `Multimedia`, `Messaging`, `Call center`, `Phonebook`, `File manager`, `Profiles`, `Extras` ; pages Image viewer, Radio FM, Options, Calculator, Torch Light, Calendar. Certains autres écrans ne sont pas photographiés et s'affichent comme tels.

**Incertitudes explicites** : la correspondance exacte B702 ↔ libellé visible Multimedia reste à prouver ; FM radio n'a pas d'ID interne attribué ; le chemin d'accès exact au dossier Photos depuis Phone ou Memory card n'est pas prouvé ; l'état actuel du profil Silent et la fréquence 98.7 sont des instantanés photographiques.

**Audio natif** : `0x8928` correspond au backend présent dans le dump (callback `0x1033D841`, init `0x1033E815` → `0x1033F83C`). Il a un parent logique `0xB702`, mais n'est présent dans **aucun tableau d'enfants** de la ROM canonique. Il est masqué par défaut et uniquement ajouté à l'écran Multimedia en mode expérimental.

## Installer et lancer (PowerShell)

Décompresser `f2_virtual_menu_v5.zip`. Depuis n'importe quel PowerShell :

```powershell
& "$HOME\Downloads\f2_virtual_menu_v5\install_v5.ps1"
```

L'installateur doit être lu avant exécution. Selon la structure de l'extraction, son chemin peut être dans un sous-dossier du ZIP.

Après installation :

```powershell
cd C:\Users\verto\F2-Altice-MobiWire-Emulator
$PY = 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe'
$ROM = 'C:\Users\verto\F2-Altice-MobiWire\research\f2\work\extracted\altice_platform\zimage.bin'
& $PY -B .\research\f2\virtual_menu_lab\f2_phone_ui_v5.py --firmware $ROM
```

Validation manifeste seule : `& $PY -B .\research\f2\virtual_menu_lab\f2_phone_ui_v5.py --validate-json`
Validation ROM : `& $PY -B .\research\f2\virtual_menu_lab\f2_phone_ui_v5.py --firmware $ROM --verify`

La V5 n'exécute **aucun code ARM**, n'accède ni au téléphone, ni aux périphériques USB/COM, ni au tuner ou flash, et ne décode pas d'images natives. Les icônes/couleurs restent des reconstructions photographiques, non des assets extraits du ZIMAGE.

## Comment ajouter une nouvelle découverte

1. Ajouter la **photo / preuve** dans `ui_observed_registry.json` et la classer `observed_ui`. Ne pas publier automatiquement les photos privées.
2. Si un ID ROM est confirmé par les audits et validé sur le ZIMAGE canonique, le reporter dans `rom_proven_registry.json` avec sa provenance. Les IDs non établis restent `null`.
3. En cas de correspondance non prouvée, garder `inferred` et documenter la question ouverte.
4. Tester : `unittest discover -s ... -p test_phone_ui_v5.py -v` et `--verify` avec le ZIMAGE canonique.
5. Commit/push **uniquement** sur `feature/f2-virtual-menu-lab`; aucune fusion vers `main` sans demande explicite.
