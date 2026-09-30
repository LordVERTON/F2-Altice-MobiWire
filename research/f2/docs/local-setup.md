# Configuration locale

Les binaires et bases de travail ne sont pas inclus dans Git. Le fichier `.gitignore` de `research/f2` exclut `data/` et `work/`.

## Emplacements attendus

```text
research/f2/data/dumps/mobiwire_dump_2.bin
research/f2/data/firmware-packages/altice-service/altice_service_package/<package>/ROM
research/f2/data/firmware-packages/qmobile/<archive firmware>
research/f2/work/extracted/altice_alice/alice-py.bin
research/f2/work/extracted/qmobile_alice/alice-py.bin
research/f2/work/ghidra/alice_reports/
```

Les outils Python amont sont installés selon les instructions du dépôt. Le workflow Ghidra utilisé ici est headless et ARM little-endian/Thumb ; indiquer le chemin local de Ghidra dans les scripts PowerShell. Les projets Ghidra, exports massifs et composants extraits restent dans `work/`.

Les scripts partagés importent les chemins depuis `scripts/_paths.py`. Exécuter les commandes depuis la racine du dépôt sauf indication contraire. Les outils d’acquisition USB sont distincts du watcher passif : ils peuvent dialoguer avec le BootROM ou modifier des registres volatils. Lire leur documentation et leurs paramètres avant utilisation.
