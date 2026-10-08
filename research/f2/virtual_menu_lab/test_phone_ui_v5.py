"""V5 tests: pure Python; no Tk display, phone, ROM, USB or network needed."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock
from f2_phone_ui_v5 import UiModelV5, load_contract, validate_against_registry, Registry


class V5ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ui,cls.rom=load_contract()

    def model(self):return UiModelV5(self.ui)

    def test_home_grid_labels_exact(self):
        m=self.model()
        self.assertEqual(m.options(),['Multimedia','Messaging','Call center','Camera','Phonebook','File manager','Profiles','Extras','Settings'])
        self.assertEqual(m.index,4)
        m.index=0;m.enter();self.assertEqual(m.page,'multimedia')

    def test_multimedia_real_vs_overlay(self):
        m=self.model();m.go('multimedia')
        self.assertEqual(m.options(),['Image viewer','FM radio'])
        m.virtual_audio=True
        self.assertEqual(m.options(),['Image viewer','FM radio','Audio Player [virtuel]'])
        m.index=2;m.enter()
        self.assertEqual(m.page,'audio_player')

    def test_real_image_viewer_options(self):
        m=self.model();m.go('multimedia');m.enter()
        self.assertEqual(m.page,'image_viewer')
        m.left_softkey();self.assertEqual(m.page,'image_options')
        self.assertEqual(m.options(),['Storage'])
        m.enter();self.assertEqual(m.options(),['Phone','Memory card'])

    def test_fm_without_hardware_and_options(self):
        m=self.model();m.go('fm_radio')
        m.tune(0.1);self.assertEqual(m.frequency,98.7)
        m.earphones=True;m.tune(0.1);self.assertEqual(m.frequency,98.8)
        m.left_softkey()
        self.assertEqual(m.options(),['Channel list','Manual input','Auto search'])

    def test_new_submenus(self):
        m=self.model();m.go('messaging')
        self.assertEqual(len(m.options()),7)
        self.assertEqual(m.options()[0],'Write message')
        m.back();m.go('call_center')
        self.assertEqual(m.options(),['Call history','Call settings'])
        m.back();m.go('extras');self.assertEqual(len(m.options()),7)
        m.index=1;m.enter();self.assertEqual(m.page,'torch_light')
        self.assertFalse(m.torch_on);m.left_softkey();self.assertTrue(m.torch_on)
        m.back();m.index=2;m.enter();self.assertEqual(m.page,'calendar')

    def test_profiles_observed_state(self):
        m=self.model();m.go('profiles')
        self.assertEqual(m.index,1)
        self.assertEqual(m.options(),['General','Silent','Meeting','Outdoor'])

    def test_storage_folder_provenance(self):
        m=self.model();m.go('file_manager')
        self.assertEqual(m.options(),['Phone','Memory card'])
        m.index=1;m.enter();self.assertEqual(m.options(),['Photos'])
        m.enter();self.assertEqual(m.page,'file_empty')
        self.assertEqual(self.ui['screens']['file_empty']['message'],'No files')
        self.assertIn('hypothèse',self.ui['screens']['storage_folders']['provenance_warning'])

    def test_rom_bindings_no_unsafe_mapping(self):
        b=self.rom['id_bindings']
        self.assertIsNone(b['fm_radio']['rom_id'])
        self.assertEqual(b['image_viewer']['rom_id'],'0x87ED')
        self.assertEqual(b['audio_player']['rom_id'],'0x8928')
        self.assertEqual(b['audio_player']['audio_init_va'],'0x1033E815')
        self.assertFalse(b['audio_player']['enumerated_in_any_child_array'])
        self.assertFalse(self.ui['research_overlay']['enabled_by_default'])

    def test_registry_guards_test_double(self):
        records={
            0xB702: {'children':[0x8569,0x87ED]},
            0xB709: {'children':[int(x,16) for x in self.rom['topology']['root_children']]},
            0x8928: {'parent':0xB702, 'index':490, 'children':[]}
        }
        # Registry records must be 894, but synthetic test can pad with empty records.
        for i in range(894-len(records)): records[0x100000+i]={'children':[]}
        fake=SimpleNamespace(records=records,read_u16=lambda address:0xA07B)
        result=validate_against_registry(fake,self.rom)
        self.assertFalse(result['audio_enumerated'])
        self.assertIsNone(result['fm_id'])
        fake.records[0xB709]['children']=[0]
        with self.assertRaises(ValueError):validate_against_registry(fake,self.rom)

    def test_no_device_or_rom_writes(self):
        m=self.model()
        self.assertFalse(hasattr(m,'flash'))
        self.assertFalse(hasattr(m,'phone_connect'))
        self.assertFalse(hasattr(m,'rom_write'))


if __name__=='__main__':unittest.main()
