"""Navigation regression tests: no display, ROM access or hardware required."""
import unittest
from f2_phone_ui_v4 import UiModel, HOME

class F2V4Tests(unittest.TestCase):
    def test_original_multimedia_excludes_audio(self):
        m=UiModel();m.go('multimedia')
        self.assertEqual(m.options(),['Image viewer','FM radio'])
        m.virtual_audio=True
        self.assertEqual(m.options(),['Image viewer','FM radio','Audio player [virtuel]'])
    def test_home_grid(self):
        m=UiModel();self.assertEqual(len(HOME),9)
        self.assertEqual(HOME[m.index][0],'Phonebook')
        m.index=7;m.enter();self.assertEqual(m.page,'multimedia')
    def test_image_options_storage(self):
        m=UiModel();m.go('multimedia');m.enter()
        self.assertEqual(m.page,'image');m.left_softkey()
        self.assertEqual(m.options(),['Storage'])
        m.enter();self.assertEqual(m.options(),['Phone','Memory card'])
        m.back();self.assertEqual(m.page,'image_options')
    def test_fm_controls(self):
        m=UiModel();m.go('fm')
        m.tune(0.1);self.assertEqual(m.frequency,98.7)
        m.earphones=True;m.tune(0.1);self.assertEqual(m.frequency,98.8)
        m.left_softkey();self.assertEqual(m.options(),['Channel list','Manual input','Auto search'])
    def test_no_native_execution(self):
        m=UiModel();m.go('multimedia');m.virtual_audio=True;m.index=2;m.enter()
        self.assertEqual(m.page,'audio')
        self.assertFalse(hasattr(m,'rom_write'))
if __name__=='__main__':unittest.main()
