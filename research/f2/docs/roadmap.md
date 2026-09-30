# Feuille de route

Le point de reprise unique et régulièrement mis à jour est [REPRISE.md](../REPRISE.md).

Preuves : [S09](reverse-engineering/s09-file-path-and-minimal-player-2026-09-29.md).
Une case cochée indique un acquis statique dans ses limites, jamais un test appareil.

- [x] Dump physique stable dump2/dump3 (égalité et hashes revérifiés).
- [x] Reproduction ALICE depuis dump2 (pipeline antérieur; hashes recoupés).
- [x] Mapping runtime ALICE.
- [x] Extraction PLATFORM/ZIMAGE liée à dump2.
- [x] Décodeur MP3 confirmé (S01).
- [x] DAF_Open confirmé (S02).
- [x] .MP3 → type 5 confirmé.
- [x] Mapping med_get_media_type et formats audio.
- [x] Blocs/pointeurs du dispatch Open; sélection switch8 explicitement inférée.
- [x] Backend WAV réel confirmé.
- [x] ABI aud_player_media_construct.
- [x] ABI Open.
- [x] ABI Play; mapping public des retours non établi.
- [x] S09.7 : formatter, concaténation, préférence, drive courant et service natif.
- [ ] Relier formellement les labels Phone/Memory Card aux catégories numériques.
- [x] Créer [POC_SPEC](reverse-engineering/POC_SPEC.md) avec hypothèses explicites.
- [ ] **En cours : figer POC_SPEC — vérifier la branche callback NULL.**
- [ ] Identifier lifetime / cleanup et quiescence.
- [ ] Trouver code cave ou stratégie d'injection sûre.
- [ ] Trouver hook UI temporaire sûr.
- [ ] Construire image patchée offline depuis dump2.
- [ ] Vérifier diff exact, hashes et rollback offline.
- [ ] Préparer restauration/read-back appareil.
- [ ] Flash contrôlé (phase future, hors autorisation actuelle).
- [ ] Test MP3 fixe.
- [ ] Test speaker natif.
- [ ] Test jack natif.
- [ ] Réutiliser File Manager : chemin UTF-16 choisi.
- [ ] Ajouter Audio Player au Multimedia.
- [ ] Play/Pause/Resume/Stop/Back/Prev/Next.

Prochaine action technique exacte dans REPRISE. Historique préservé dans docs/archive/.
