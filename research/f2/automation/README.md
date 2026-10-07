# Automatisation locale F2

## Revue automatique des résultats

La boucle Notion → Codex (une fois par résultat) → prochain job offline est
documentée dans [bridge/README.md](bridge/README.md). Tâche distincte :
`F2 Research Orchestrator`. Le worker Notion existant est conservé à l'identique.
Arrêt persistant au premier véritable hardware gate, sans prochain job.

- Branche canonique : `automate-research`, remote `github`.
- Inbox : `C:\Users\verto\Downloads`.
- Runner installé : `C:\Users\verto\Downloads\F2Automation\f2_runner.ps1`.
- Python : `C:\Users\verto\mtkclient\.venv\Scripts\python.exe`.
- Rapports : `research/f2/work/reports`.
- Jobs autorisés : `offline_analysis` uniquement. Téléphone, USB, COM,
  BROM, DA, hardware/flash, erase et repack interdits en automatisation.
- Workflow principal : ChatGPT -> GitHub `automate-research` -> repo queue -> runner -> report -> GitHub.
- Fallback conservé : ChatGPT job ZIP -> Downloads -> runner -> Python -> report -> commit -> push.

## Queue Git (mode principal)

Publier ensemble dans un commit le script `jobs/<job_id>.py` et le manifeste
`queue/<job_id>.job.json`, puis pousser sur `github/automate-research`.
Le dossier `jobs/` est marqué `-text` dans `.gitattributes` pour préserver
exactement les octets SHA256 lors des checkouts Windows.

```json
{
  "schema_version": 1,
  "job_id": "example_offline",
  "enabled": true,
  "safety": {
    "mode": "offline_analysis",
    "phone_access": false,
    "flash_write": false,
    "erase": false,
    "repack": false
  },
  "script": "research/f2/automation/jobs/example_offline.py",
  "script_sha256": "REMPLACER_PAR_LE_SHA256_EXACT_64_HEXADECIMAUX",
  "report": "research/f2/work/reports/example_offline.txt",
  "args": []
}
```

Le runner effectue à chaque cycle : fetch, synchronisation, queue triée par nom,
puis ZIP inbox. Il applique `pull --ff-only` si la branche distante a avancé et
si l'arbre est propre. Un arbre modifié, y compris des fichiers non suivis ou
un index déjà préparé, bloque tous les jobs sans modifier ces fichiers.

Le script et le manifeste doivent être présents dans HEAD. Les chemins sont
limités aux dossiers prévus, sans traversée `..`, lien symbolique ou jonction.
Les scripts sont des `.py` ; le SHA256 est obligatoire. Les quatre flags de
sécurité sont des booléens JSON `false`, pas des chaînes ou valeurs numériques.
`args` est un tableau de chaînes transmis au Python canonique ; aucune commande
shell du manifeste n'est interprétée. Aucun autre interpréteur Python n'est permis.

Un receipt existant fait ignorer le job, y compris un receipt `failed` : utiliser
un nouveau job_id pour réessayer. Un rapport existant sans receipt est conservé
et bloque ce job. Un script retournant un code non nul produit un receipt `failed`
et un rapport qui inclut stderr. Un manifeste rejeté n'est jamais exécuté.

Pour la queue, seuls le rapport explicite et son receipt sont ajoutés au commit.
Le fallback ZIP archive en plus son script et son manifeste comme auparavant.
Tout changement inattendu après l'exécution bloque le commit et reste disponible
pour inspection. Le mode offline reste déclaratif : les scripts Python doivent
être relus avant publication ; le runner n'est pas un sandbox matériel.

En cas de push concurrent : conserver le commit résultat, fetch, puis
`pull --rebase` et push normal uniquement avec arbre propre et commits locaux
tous créés par la session actuelle du runner. Aucun autostash ni force push.
Les commits utilisateur ou une reprise après redémarrage nécessitent une
synchronisation manuelle. Un conflit de rebase reste disponible pour résolution,
avec le commit original conservé par Git ; le runner s'arrête.

Tests reproductibles sans GitHub ni inbox réelle :

```powershell
& "C:\Users\verto\mtkclient\.venv\Scripts\python.exe" research\f2\automation\tests\test_runner.py
```

Les fixtures Git et logs restent sous `%TEMP%\f2_repoqueue_test_*` pour diagnostic.

## Validation repo-queue du 2026-10-07

- 11 tests d'intégration PASS sous Windows PowerShell et Python canonique :
  récupération distante et staging exact, skip du receipt, manifestes invalides,
  arbre/index modifiés, commit utilisateur, push concurrent avec rebase,
  conflit conservé, erreur Python avec stderr, écriture inattendue du job,
  fallback ZIP/priorité queue, sécurité ZIP et arguments sans shell.
- Le faux job `s13_automation_repoqueue_smoke_v1` a été publié depuis un worktree
  temporaire dans `1a2735d`, pendant que le dépôt principal restait en arrière.
  Le runner a lui-même fait le `pull --ff-only`, exécuté le job et poussé
  `5de4a5adf55b2452baeab464e95e9b422e5a82ac`.
- [Rapport PASS](../work/reports/s13_automation_repoqueue_smoke_v1.txt),
  [receipt completed / exit 0](results/s13_automation_repoqueue_smoke_v1.result.json),
  [script](jobs/s13_automation_repoqueue_smoke_v1.py),
  [manifeste](queue/s13_automation_repoqueue_smoke_v1.job.json).
- Le commit résultat contient exactement deux fichiers : rapport et receipt.
  Les quatre flags matériels sont false. SHA du script validé après récupération.
- SHA256 du runner installé :
  `d66d7fe8e07b6ba15e605d82b143fbaa29ed011296c5c9a26b56d681d592f041`.
- Le BOM initial du nouveau `.gitattributes` provoquait un avertissement Git ;
  l'encodage a été corrigé sans BOM dans `1dd8ef8` avant le smoke réel.
- Le ZIP A.51 présent dans Downloads a été temporairement mis à l'écart pour
  ce test, puis restauré à l'identique sans exécution. Aucun ancien script ou
  document S11/S12/S13 modifié. Aucun runner laissé actif après le test `-Once`.

Le job smoke et ses preuves restent versionnés ; le receipt empêche sa réexécution.

Commande canonique (toujours préciser la branche ; ajouter `-Once` pour un passage) :

```powershell
powershell.exe -ExecutionPolicy Bypass -File "C:\Users\verto\Downloads\F2Automation\f2_runner.ps1" -RepoRoot "C:\Users\verto\F2-Altice-MobiWire" -PythonExe "C:\Users\verto\mtkclient\.venv\Scripts\python.exe" -Inbox "C:\Users\verto\Downloads" -Branch "automate-research" -Remote "github"
```

Arrêt du mode continu : Ctrl+C. Aucun service de démarrage automatique installé.
Relire le script avant de déposer un ZIP : le manifeste et la variable offline
sont des contrôles déclaratifs, pas une isolation des capacités de Python.

## Historique : validation ZIP du 2026-10-07

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
SHA256 de l'ancien v4 installé et testé avant repo-queue : `031f9b0d325894340123720859c8cb1a95061dc509acf8dfe082f98679a0a6e6`.

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
