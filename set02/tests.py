import base64
import functools
import os
import unittest

from Crypto.Cipher import AES

import core
import aes


class Set02Tests(unittest.TestCase):

    def test_task09(self):
        orig = "YELLOW_SUBMARINE"
        expected = "YELLOW_SUBMARINE\x04\x04\x04\x04"
        self.assertEqual(core.pad_pkcs7(orig, 20), expected)

    def test_task10(self):
        plaintext_start = "I'm back and I'm ringin' the bell"
        cipher = aes.AESCipherCBC("YELLOW SUBMARINE")
        input_file = os.path.join(os.path.dirname(__file__), "10.txt")
        with open(input_file, "rb") as f:
            ciphertext = f.read()
        ciphertext = base64.b64decode(ciphertext)
        plaintext = cipher.decrypt(ciphertext)
        self.assertTrue(plaintext.startswith(plaintext_start))

    def test_task11(self):
        ecb_encrypt = functools.partial(aes.aes_encrypt, mode=AES.MODE_ECB)
        cbc_encrypt = functools.partial(aes.aes_encrypt, mode=AES.MODE_CBC)
        for i in range(100):
            self.assertEqual(aes.ecb_cbc_oracle(ecb_encrypt), AES.MODE_ECB)
            self.assertEqual(aes.ecb_cbc_oracle(cbc_encrypt), AES.MODE_CBC)
