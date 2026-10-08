# F2 Emulator — Canonical registration layers (V5.1 / C+D)

## Scope and Git isolation

Changes belong to `feature/f2-virtual-menu-lab` worktree only. The `main` research branch and the independent `mtkclient` directory are never modified by this update. No flash, COM, USB or ARM binary execution.

## Three evidence layers

1. `ui_observed_registry.json`: UI layout, actual photographed words, navigation, observed softkeys and photograph references. No ROM IDs are asserted here.
2. `rom_proven_registry.json`: documented binary identifiers and exact static topology, pending corroboration with canonical ZIMAGE by V2 `Registry` reader. JSON claims alone are not proof.
3. `research_overlay_registry.json`: opt-in Audio Player experiment, explicitly disabled by default and disallowing claims of physical menu visibility or native execution.

The **read-only** `f2_registration_bridge.py` checks cross-layer invariants and provides `menu_items()` and `ui_rom_binding()`. V5 renders the legacy phone shell from V4, reads all three layers, and keeps `--verify` as the final test against the real ZIMAGE on the local Windows machine.

## Current confirmed vs unresolved facts

- Real Multimedia menu has exactly `Image viewer`, `FM radio` (photos). The firmware B702 enumerates `[0x8569, 0x87ED]`, but label-to-record equivalence is not proved for all entries.
- `Image viewer` identifies `0x87ED` (callback `0xF02F3F9D`).
- `FM radio` has *no proved ROM ID*. Do not map it to `0x8569` because of array position.
- Native Audio app is `0x8928`, dense index 490, callback `0x1033D841`, init `0x1033E815`, downstream `0x1033F83C`; logical parent B702 but not enumerated. The simulator's Audio page is *not native playback*.
- Do not change B702 `child_count` from 2 to 3 in place: the packed following halfword belongs to B703.

## Registering a new finding

1. Record the claim and cite its actual evidence (photo file name for appearance; immutable audit report/ROM offsets for firmware identity).
2. Update only the layer that owns that evidence, not all JSONs at once.
3. Keep unresolved fields `null` and statuses `inferred` until independent binary inspection validates them; the bridge deliberately rejects an FM ID promotion without a code-review update to the validation gate.
4. Run pure offline tests first, then `--validate-json`, then `--verify --firmware <canonical zimage>` on Windows. No writes, patches or phone connections.
5. Commit only the affected emulator files on `feature/f2-virtual-menu-lab`, with separate architecture, test and documentation commits. Push normally, **never** `--force`.

## Future development

- A verified label-to-ID association should add its audit reference, exact ZIMAGE hash, relevant address/record evidence and a dedicated regression test. Only then promote a candidate ROM ID. Never infer it from visual selection order.
- New screenshots advance the observed UI manifest without changing ROM identity.
- Keep new UI controls behind feature flags until observed or experimentally marked.
- Derive future callback selection from audited dispatch signatures, not only from a menu item ID.

## Three suggested Git commits

1. `refactor(emulator): separate experimental Audio overlay from observed UI`
2. `test(emulator): guard UI-ROM provenance and Audio visibility invariants`
3. `docs(emulator): document F2 registration layers and promotion gates`

Releasing V5.1 does not rewrite existing V5 Git commits or merge `main`.
