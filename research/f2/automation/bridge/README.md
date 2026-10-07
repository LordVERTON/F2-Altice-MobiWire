# Revue F2 à appel unique

`research_orchestrator.py` effectue une passe déterministe. La tâche **F2 Research
Orchestrator** la déclenche chaque minute (session Windows ouverte). Queue sans
`COMPLETED/PENDING` : sortie 0 silencieuse, aucun Codex. Le worker existant et sa
tâche **F2 Notion Automation Worker** restent inchangés.

Le plus ancien résultat éligible est vérifié dans Notion et dans son commit
GitHub. Un verrou OS local couvre claim, revue et publication ; il se libère après
crash. Notion n'offre pas de compare-and-swap : garantie de claim unique sur ce
poste, pas entre plusieurs orchestrateurs sur des machines différentes. Ne pas
installer un deuxième reviewer ailleurs ni réclamer manuellement le même job.

Un seul `codex exec`, éphémère et sans outils, reçoit le rapport courant complet,
son receipt, le premier état courant de START HERE et les chemins référencés.
Limites : rapport 192 000 caractères, extrait 9 000, script 64 Ko, appel 10 minutes.
Un dépassement exige une revue manuelle ; aucun historique n'est chargé ni résumé
silencieusement. Aucune relance Codex automatique après timeout/crash/erreur.
Le prompt n'est pas journalisé ; seules les métriques d'usage sont conservées.
Authentification Codex existante, copie temporaire isolée, aucune transmission du
token Notion. Plugins, shell, web et agents sont désactivés.

Python valide la réponse structurée, recalcule le SHA, réutilise les validateurs
du worker et restreint les nouveaux scripts aux imports d'analyse et lectures
locales. Les quatre drapeaux matériels restent `false`. Ces contrôles AST sont
conservateurs ; ce n'est pas une preuve formelle d'isolation de tout Python.

Publication : bloc courant géré en haut des trois pages canoniques (historique
conservé), puis exactement un job complet `QUEUED` avec les deux attachments,
puis `Next Job ID` / `Reviewed At` / `PROCESSED`. Journal écrit avant les effets
externes. Après création réussie mais réponse perdue, retrouver et vérifier le
job par ID et parent ; jamais un second POST. Si une création reste ambiguë et
introuvable, `ERROR` exige une réconciliation manuelle. Ne pas effacer le journal
ni remettre le job en PENDING pour forcer une relance.

Un `hardware_gate` publie **AUTOMATION OFFLINE PHASE COMPLETE** et **MANUAL
HARDWARE GATE REQUIRED**, ne crée aucun job et pose un arrêt persistant local.
L'installation ne réarme jamais ce verrou matériel.

Depuis la racine du dépôt (branche canonique et arbre propres obligatoires) :

```powershell
# Installer / vérifier tests et accès Notion ; démarrer une passe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File research/f2/automation/bridge/install_orchestrator.ps1 -StartNow
# Une passe manuelle (silencieuse si aucune revue attendue)
& 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe' research/f2/automation/bridge/research_orchestrator.py
# Dernier état local + présence d'une revue en attente, sans Codex
& 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe' research/f2/automation/bridge/research_orchestrator.py --status
# Vérification de l'installation, de Notion et des deux tâches, sans Codex
powershell.exe -NoProfile -ExecutionPolicy Bypass -File research/f2/automation/bridge/verify_orchestrator.ps1
# Désinstaller uniquement l'orchestrateur
powershell.exe -NoProfile -ExecutionPolicy Bypass -File research/f2/automation/bridge/uninstall_orchestrator.ps1
```

Runtime ignoré : `state/orchestrator.json`, `state/transactions/<page_commit>/`
(journal, sortie validée, usage), `state/review/<page_commit>/` (les quatre fichiers
du contrat uniquement), `state/HARDWARE_GATE.json`. Une erreur est décrite dans
`Review Error` et le journal. La désinstallation conserve les preuves et laisse
une transaction active finir. `ORCHESTRATOR_STOP` empêche les nouvelles passes.

Tests offline : `python research/f2/automation/tests/test_orchestrator.py`.
Le programme ne lance jamais lui-même le worker, un ancien job ou un gate matériel.

Références de protocole : [Codex non interactif](https://developers.openai.com/codex/noninteractive),
[position des blocs Notion](https://developers.notion.com/reference/patch-block-children).
