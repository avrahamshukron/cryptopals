import unittest

from set02 import core


class Set02Tests(unittest.TestCase):

    def test_task01(self):
        orig = "YELLOW_SUBMARINE"
        expected = "YELLOW_SUBMARINE\x04\x04\x04\x04"
        self.assertEqual(core.pad_pkcs7(orig, 20), expected)
