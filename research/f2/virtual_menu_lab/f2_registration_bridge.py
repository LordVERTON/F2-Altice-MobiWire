#!/usr/bin/env python3
"""Read-only contract between photographed UI, canonical ROM facts and research overlay.

Deliberately imports no hardware/transport and never modifies a firmware image.
An association present in JSON is documentation, not independently verified proof.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
UI_PATH = HERE / 'ui_observed_registry.json'
ROM_PATH = HERE / 'rom_proven_registry.json'
OVERLAY_PATH = HERE / 'research_overlay_registry.json'
HOME = ('Multimedia', 'Messaging', 'Call center', 'Camera', 'Phonebook',
        'File manager', 'Profiles', 'Extras', 'Settings')


class ContractError(ValueError):
    """A claimed registration/UI mapping violates currently known evidence."""


def _json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def validate_layers(ui, rom, overlay):
    """Fail closed when an undocumented binding leaks into the observed UI."""
    if any(layer.get('schema_version') != 5 for layer in (ui, rom, overlay)):
        raise ContractError('All three registration layers must use schema_version 5')
    if 'research_overlay' in ui or 'id_bindings' in ui:
        raise ContractError('Observed UI cannot contain research or ROM bindings')
    grid = sorted(ui['home_grid'], key=lambda row: row['slot'])
    if [row['slot'] for row in grid] != list(range(9)):
        raise ContractError('Main menu is not a 3x3 grid of unique slots 0..8')
    if tuple(row['label'] for row in grid) != HOME:
        raise ContractError('Real main menu labels/order diverge from photographs')
    screens = ui['screens']
    if any(row['target'] not in screens for row in grid):
        raise ContractError('Main menu references absent screen')
    for page, screen in screens.items():
        if any(key in screen for key in ('rom_id', 'callback_va', 'virtual_experimental')):
            raise ContractError(f'ROM or virtual metadata leaked into screen: {page}')
        for item in screen.get('items', []):
            target = item.get('target')
            if target and target not in screens and target not in ui.get('undocumented_targets', []):
                raise ContractError(f'Unknown navigation target: {page} -> {target}')
            if any(key in item for key in ('rom_id','callback_va','rom_public_id')):
                raise ContractError(f'ROM identity leaked into observed item: {page}')
    if [row['label'] for row in screens['multimedia']['items']] != ['Image viewer', 'FM radio']:
        raise ContractError('Observed Multimedia has exactly Image viewer and FM radio')
    if any(row.get('target') == 'audio_player' for screen in screens.values()
           for row in screen.get('items', [])):
        raise ContractError('Audio cannot be part of observed screens')

    binds = rom['id_bindings']
    associations = rom['ui_rom_associations']
    if binds['fm_radio']['rom_id'] is not None or associations['fm_radio']['rom_id'] is not None:
        raise ContractError('FM radio ROM ID remains unknown: promotion needs a new independent audit')
    if binds['image_viewer']['rom_id'] != '0x87ED':
        raise ContractError('Image Viewer canonical ID unexpectedly changed')
    if binds['audio_player']['rom_id'] != '0x8928':
        raise ContractError('Audio canonical ID unexpectedly changed')
    if binds['audio_player']['callback_va'] != '0x1033D841':
        raise ContractError('Audio callback changed')
    if binds['audio_player']['audio_init_va'] != '0x1033E815':
        raise ContractError('Audio init changed')
    if binds['audio_player']['enumerated_in_any_child_array'] is not False:
        raise ContractError('Audio must not be claimed as physically enumerated')
    if rom['topology']['multimedia_children_rom'] != ['0x8569','0x87ED']:
        raise ContractError('B702 child array changed without ROM re-audit')
    if rom['ui_rom_associations']['multimedia']['status'] != 'inferred_group_link':
        raise ContractError('B702 to visible Multimedia is not confirmed as an exact binding')
    if rom['ui_rom_associations']['audio_player']['status'] != 'virtual_experimental_visibility':
        raise ContractError('Audio visibility may not be promoted into observed ROM state')

    if overlay['enabled_by_default'] is not False or overlay['requires_opt_in'] is not True:
        raise ContractError('Research overlay must be disabled by default and opt-in only')
    if overlay['append_to'] != 'multimedia':
        raise ContractError('Audio overlay would change a non-target screen')
    entry = overlay['entry']
    if entry.get('target') != 'audio_player' or entry.get('visibility') != 'virtual_experimental':
        raise ContractError('Research entry must stay virtual and target audio_player')
    if entry.get('rom_public_id') != binds['audio_player']['rom_id']:
        raise ContractError('Audio overlay does not match proven backend ID')
    if overlay['registration']['native_exec_supported'] is not False:
        raise ContractError('Laboratory must never advertise native execution')
    if overlay['registration']['phone_ui_visible'] is not False:
        raise ContractError('Laboratory must never assert physical Audio visibility')
    return {
        'observed_home_slots': 9,
        'observed_multimedia_items': 2,
        'rom_audio_id': binds['audio_player']['rom_id'],
        'fm_rom_id': None,
        'experimental_audio_opt_in': True,
        'native_execution': False,
        'physical_firmware_modified': False,
    }


def load_layers(ui_path=UI_PATH, rom_path=ROM_PATH, overlay_path=OVERLAY_PATH):
    ui, rom, overlay = _json(ui_path), _json(rom_path), _json(overlay_path)
    validate_layers(ui, rom, overlay)
    return ui, rom, overlay


def menu_items(ui, overlay, page, research_enabled=False):
    if page == 'home':
        return sorted(ui['home_grid'], key=lambda row: row['slot'])
    result = list(ui['screens'].get(page, {}).get('items', []))
    if research_enabled and page == overlay['append_to']:
        result.append(dict(overlay['entry']))
    return result


def ui_rom_binding(rom, page):
    """Return documented evidence, never fabricate an ID from menu position."""
    return dict(rom.get('ui_rom_associations', {}).get(page, {
        'rom_id': None, 'status': 'undocumented'}))
