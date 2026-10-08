# F2 Virtual Menu Lab V2 — registre et preuves Notion

Le visualiseur vérifie SHA256/taille du ZIMAGE canonique, lit les 52 plages ID ↔ dense, reconstruit les 894 IDs effectivement mappés parmi 895 emplacements, puis inspecte les records de 16 octets et leurs tableaux d'enfants. Le navigateur affiche la structure réelle du registre et quelques annotations techniques issues du Notion F2 (A.46-A.51, A.87-A.90).

## Exécuter sous Windows

```powershell
cd C:\Users\verto\F2-Altice-MobiWire-Emulator
$PYTHON='C:\Users\verto\mtkclient\.venv\Scripts\python.exe'
$ROM='C:\Users\verto\F2-Altice-MobiWire\research\f2\work\extracted\altice_platform\zimage.bin'
& $PYTHON -B .\research\f2\virtual_menu_lab\f2_virtual_menu_v2.py --firmware $ROM
```

Ajouter `--json` pour un rapport automatisable.

## Statut des preuves

- Le chemin `B709 -> B702 -> [8569,87ED]` est une énumération ROM confirmée.
- `0x8928` dispose d'une registration native Audio mais n'appartient à aucun tableau d'enfants selon A.49.
- `0x86C0` et `0x8928` ont pour parent logique `B702` mais ne sont pas énumérés ; les liens ne sont pas systématiquement réciproques.
- `FM Radio` est visible **sur le téléphone**, mais son ID exact n'est pas identifié.
- « Ajouter 8928 » modifie le modèle en mémoire du simulateur uniquement.
- Les libellés, icônes, scènes LCD, état des filtres et vrais appels de sélection ne sont PAS émulés.

Ce programme ne fait aucune écriture sur la ROM ou le téléphone.
