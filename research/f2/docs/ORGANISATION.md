# Organisation et maintenance de la documentation

## Un seul état courant

[REPRISE.md](../REPRISE.md) est le point d'entrée obligatoire à chaque étape et
après interruption. Il reste court : objectif, conclusions validées, étape
active, dernière action terminée, commande en cours et prochaine action.
Les anciens documents d'état ne doivent plus recevoir de conclusions copiées.

## Séparer trois usages

- **État courant** : `REPRISE.md`, remplacé au fil des résultats.
- **Journal chronologique** : `docs/JOURNAL.md`, une entrée par étape/checkpoint;
  conserver les tentatives négatives et corrections sans réécrire l'histoire.
- **Détails techniques** : `docs/reverse-engineering/`, un dossier Markdown
  par question avec preuves, adresses, commandes, limites et artefacts bruts.

Les fichiers volumineux générés restent sous `work/`, les dumps sous `data/`.
Un résultat important doit être résumé dans une note technique durable : un
rapport local ignoré par Git ne suffit pas comme unique documentation.

## Quand mettre à jour

Avant une tâche longue : inscrire l'hypothèse, la commande, la sortie attendue
et « EN COURS » dans REPRISE. Après achèvement : vérifier les sorties, noter le
résultat et la prochaine action. Après changement de priorité : expliquer la
raison dans le journal. Avant de rendre la main : lever toute ambiguïté sur
les commandes actives et les travaux inachevés.

Une interruption ne permet pas d'écrire un dernier checkpoint : la protection
repose donc sur ces mises à jour avant et pendant le travail, pas seulement à
la fin. Aucun service de mise à jour automatique n'est supposé.

## Contenu d'une note technique

Question; entrées et hashes; méthode reproductible; observations; distinction
faits/inférences; limites; résultat négatif éventuel; prochaine expérience.
Préciser les espaces d'adresses et distinguer adresses historiques Ghidra,
offsets de fichiers et adresses d'exécution.

## Archives

Les snapshots pré-réorganisation sont dans
`docs/archive/snapshots-2026-09-29/`. Ils sont conservés à titre historique;
leurs liens relatifs et priorités reflètent leurs emplacements d'origine.
Ne pas les traiter comme consignes courantes.
