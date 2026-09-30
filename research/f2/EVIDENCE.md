# Preuves techniques

Le point de reprise unique et régulièrement mis à jour est [REPRISE.md](REPRISE.md).

## Preuves prioritaires

| Question | Note durable | Audit / sortie locale |
|---|---|---|
| Décodeur et mapping ALICE | [S01](docs/reverse-engineering/mp3-decoder-verdict-2026-09-29.md) | audit_mp3_bridge.py |
| DAF_Open et DCM | [S02](docs/reverse-engineering/daf-open-dispatch-2026-09-29.md) | audit_daf_open.py / daf_open_audit.json |
| Drive dynamique | [S09](docs/reverse-engineering/s09-file-path-and-minimal-player-2026-09-29.md) | analyze_audio_paths.py / audio_path_audit.json |
| ABI, formats, WAV, Play | [S09](docs/reverse-engineering/s09-file-path-and-minimal-player-2026-09-29.md) | audit_minimal_player_abi.py / minimal_player_abi.json |
| POC futur | [Spécification](docs/reverse-engineering/POC_SPEC.md) | brouillon, aucune injection |

Scripts dans scripts/analysis/, sorties dans work/ghidra/alice_reports/.
Les audits nouveaux vérifient les hashes épinglés et échouent explicitement
sur divergence; ils ne prennent aucun donor comme entrée.

## Statut des anciens rapports

`work/ghidra/alice_reports/filetype_mp3_dispatch.txt` est **historique**.
Son verdict MP3→UNKNOWN est dépassé par S02/S09 : extension MP3=5,
bloc DAF_Open identifié, sélection switch8 inférée. Le fichier brut reste intact.
Les notes Notion, anciens offsets ALICE et analyses donor ne remplacent pas
les preuves physiques. Archives : docs/archive/snapshots-2026-09-29/ et
docs/archive/pre-s09-final-2026-09-29/.
