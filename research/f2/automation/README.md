# Automatisation locale F2

- Branche canonique : `automate-research`, remote `github`.
- Inbox : `C:\Users\verto\Downloads`.
- Runner installé : `C:\Users\verto\Downloads\F2Automation\f2_runner.ps1`.
- Python : `C:\Users\verto\mtkclient\.venv\Scripts\python.exe`.
- Rapports : `research/f2/work/reports`.
- Jobs autorisés : `offline_analysis` uniquement. Téléphone, USB, COM,
  BROM, DA, hardware/flash, erase et repack interdits en automatisation.
- Workflow : ChatGPT job ZIP -> Downloads -> runner -> Python -> report -> commit -> push.

Commande canonique (toujours préciser la branche ; ajouter `-Once` pour un passage) :

```powershell
powershell.exe -ExecutionPolicy Bypass -File "C:\Users\verto\Downloads\F2Automation\f2_runner.ps1" -RepoRoot "C:\Users\verto\F2-Altice-MobiWire" -PythonExe "C:\Users\verto\mtkclient\.venv\Scripts\python.exe" -Inbox "C:\Users\verto\Downloads" -Branch "automate-research" -Remote "github"
```

Arrêt du mode continu : Ctrl+C. Aucun service de démarrage automatique installé.
Relire le script avant de déposer un ZIP : le manifeste et la variable offline
sont des contrôles déclaratifs, pas une isolation des capacités de Python.

## Validation du 2026-10-07

Départ propre/synchronisé : `s12-alice-extension`,
`6bec2ed4f42887d1ae2f7eec63790a66ab2ad7a9`.
Smoke réellement exécuté, PASS, exit 0, Python canonique, variable
`F2_AUTOMATION_OFFLINE=1`, receipt `completed` et quatre drapeaux matériels false.
Commit/push automatique : `5247018d35677cb68b38b06e2679e3eb7939f7bb`.

- [Rapport](../work/reports/automation_smoke_v1.txt)
- [Script](jobs/automation_smoke_v1.py)
- [Manifeste](manifests/automation_smoke_v1.job.json)
- [Receipt](results/automation_smoke_v1.result.json)
- [Runner reproductible](f2_runner.ps1)

Le mode continu a affiché `No new f2job_*.zip in Downloads.` sur trois cycles,
puis a été arrêté par Ctrl+C (code du processus interrompu : 1).
Aucun audit A.51 ni accès matériel effectué.

### Corrections du v4 téléchargé

SHA256 téléchargé : `1415ed72c8bc1a7d3295645bd6704878467e7d97854c3b59572e58b242d8b153`.
SHA256 installé et testé : `031f9b0d325894340123720859c8cb1a95061dc509acf8dfe082f98679a0a6e6`.

Les corrections v2/v3 (`Invoke-GitNative`, `git.exe`, tableaux `$jobs` et `$extra`)
étaient présentes. Trois corrections locales supplémentaires ont été nécessaires :

1. Windows PowerShell refuse `Tee-Object -LiteralPath ... -Append` :
   « Le jeu de paramètres ne peut pas être résolu à l'aide des paramètres nommés spécifiés. »
   Capture remplacée par `Add-Content -LiteralPath ... -Encoding UTF8` et affichage.
2. `work/` ignore les rapports : `git add -f --` limité au rapport explicite du job.
3. Le paramètre `$Args` du wrapper entre en conflit avec la variable automatique
   PowerShell : « git  failed with exit code 1 ». Renommé en `$GitArgs`.

Après ces corrections, un nouveau passage a validé exécution, rapport, receipt,
commit et push sans intervention. Syntaxe PowerShell vérifiée.
Le premier résultat PASS non commité a été conservé pour récupération dans
`C:\Users\verto\AppData\Local\Temp\f2automation_smoke_recovery_7e4be30d477649b7be44d8d8408a985c`.

### Nettoyage limité à l'installation

Supprimés dans Downloads : `f2_runner_v2.ps1`, `f2_runner_v3.ps1`,
`f2_runner_v4.ps1`; dans F2Automation : `f2_automation_bootstrap.zip` et les
trois fichiers du dossier bootstrap extrait (`f2_runner.ps1`, `INSTALL.txt`,
`f2job_automation_smoke_v1.zip`), puis le dossier vide; dans F2AutomationDone
et F2AutomationFailed : chacun des ZIP `f2job_automation_smoke_v1.zip`.

Conservés : runner canonique, dossiers Done/Failed vides, sauvegarde de récupération,
tous les scripts et documents de recherche S11/S12/S13, rapports utiles et checkpoints.
