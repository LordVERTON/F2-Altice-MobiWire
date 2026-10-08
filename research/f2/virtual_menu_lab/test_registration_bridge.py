"""C/D V5.1 contract regressions. No Tk window, USB/COM, flash or network."""
import copy
import unittest
from f2_registration_bridge import ContractError, load_layers, menu_items, ui_rom_binding, validate_layers


class RegistrationSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ui, cls.rom, cls.overlay = load_layers()

    def layers(self):
        return copy.deepcopy(self.ui), copy.deepcopy(self.rom), copy.deepcopy(self.overlay)

    def test_canonical_real_menu_has_only_two_entries(self):
        self.assertEqual([x['label'] for x in menu_items(self.ui,self.overlay,'multimedia')],
                         ['Image viewer', 'FM radio'])

    def test_explicit_opt_in_appends_only_to_multimedia(self):
        self.assertEqual(len(menu_items(self.ui,self.overlay,'multimedia',True)),3)
        self.assertEqual(len(menu_items(self.ui,self.overlay,'messaging',True)),7)
        self.assertEqual(menu_items(self.ui,self.overlay,'multimedia',True)[2]['rom_public_id'],'0x8928')

    def test_audio_cannot_be_in_real_screens(self):
        ui,rom,overlay=self.layers()
        ui['screens']['multimedia']['items'].append({'label':'Audio Player','target':'audio_player'})
        with self.assertRaises(ContractError): validate_layers(ui,rom,overlay)

    def test_unverified_fm_mapping_is_rejected(self):
        ui,rom,overlay=self.layers()
        rom['id_bindings']['fm_radio']['rom_id']='0x8569'
        with self.assertRaises(ContractError): validate_layers(ui,rom,overlay)

    def test_main_grid_mapping_corrected(self):
        self.assertEqual([row['label'] for row in menu_items(self.ui,self.overlay,'home')],
            ['Multimedia','Messaging','Call center','Camera','Phonebook','File manager','Profiles','Extras','Settings'])

    def test_audio_backend_and_visibility_distinct(self):
        bind=self.rom['id_bindings']['audio_player']
        self.assertEqual(bind['rom_id'],'0x8928')
        self.assertEqual(bind['callback_va'],'0x1033D841')
        self.assertEqual(bind['audio_init_va'],'0x1033E815')
        self.assertFalse(bind['enumerated_in_any_child_array'])
        self.assertFalse(self.overlay['registration']['phone_ui_visible'])
        self.assertFalse(self.overlay['registration']['native_exec_supported'])

    def test_overlay_without_opt_in_rejected(self):
        ui,rom,overlay=self.layers()
        overlay['enabled_by_default']=True
        with self.assertRaises(ContractError): validate_layers(ui,rom,overlay)

    def test_audio_wrong_id_rejected(self):
        ui,rom,overlay=self.layers()
        overlay['entry']['rom_public_id']='0x8569'
        with self.assertRaises(ContractError): validate_layers(ui,rom,overlay)

    def test_ambiguous_group_binding_not_promoted(self):
        ui,rom,overlay=self.layers()
        rom['ui_rom_associations']['multimedia']['status']='dump_proven'
        with self.assertRaises(ContractError): validate_layers(ui,rom,overlay)

    def test_unknown_screens_do_not_gain_rom_id(self):
        self.assertIsNone(ui_rom_binding(self.rom,'fm_radio')['rom_id'])
        self.assertIsNone(ui_rom_binding(self.rom,'phonebook')['rom_id'])

    def test_rom_metadata_does_not_leak_into_observed(self):
        ui,rom,overlay=self.layers()
        ui['screens']['fm_radio']['rom_id']='0x8569'
        with self.assertRaises(ContractError): validate_layers(ui,rom,overlay)

    def test_no_firmware_or_transport_dependencies(self):
        import inspect
        import f2_registration_bridge as bridge
        body=inspect.getsource(bridge)
        self.assertNotIn('serial.Serial(', body)
        self.assertNotIn('.write(', body)
        self.assertNotIn('usb.core', body)


if __name__=='__main__':unittest.main()
