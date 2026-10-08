import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from f2_virtual_menu import (
    load_registry,
    build_model,
    EXPECTED_CHILDREN,
    AUDIO_ID,
)


class VirtualMenuTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.registry = load_registry()

    def test_original_children(self):
        self.assertEqual(
            self.registry["children"],
            list(EXPECTED_CHILDREN)
        )

    def test_virtual_audio_added(self):
        model = build_model(self.registry, True)
        self.assertEqual(
            model["children"],
            [*EXPECTED_CHILDREN, AUDIO_ID]
        )

    def test_original_unchanged(self):
        original = build_model(self.registry)
        virtual = build_model(self.registry, True)

        self.assertEqual(original["children"], list(EXPECTED_CHILDREN))
        self.assertEqual(len(virtual["children"]), 3)
        self.assertEqual(self.registry["child_count"], 2)

    def test_no_execution_claim(self):
        model = build_model(self.registry, True)
        self.assertFalse(model["native_execution_proven"])
        self.assertFalse(model["visibility_proven"])
        self.assertFalse(model["firmware_modified"])

    def test_packed_boundary(self):
        self.assertTrue(self.registry["boundary_preserved"])


if __name__ == "__main__":
    unittest.main()
