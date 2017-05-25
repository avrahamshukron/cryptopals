import os
import unittest

import binascii

from set01 import b64_encode_hex, xor_buffer, crack_xor_single_byte_key


class Set01Tests(unittest.TestCase):

    def test_task01(self):
        initial_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        computed_b64 = b64_encode_hex(initial_string)
        self.assertEqual(computed_b64, expected)

    def test_task02(self):
        s1 = "1c0111001f010100061a024b53535009181c"
        s2 = "686974207468652062756c6c277320657965"
        expected_xor = "746865206b696420646f6e277420706c6179"

        xored = xor_buffer(binascii.unhexlify(s1), binascii.unhexlify(s2))
        self.assertEqual(binascii.hexlify(xored), expected_xor)

    def test_task03(self):
        encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        # solution found by actually running the code
        solution = "Cooking MC's like a pound of bacon"
        decrypted, key, score = crack_xor_single_byte_key(
            binascii.unhexlify(encrypted))
        self.assertEqual(solution, decrypted)
        print "%s decrypted using %s" % (decrypted, score)

    def test_task04(self):
        # solution found by actually running the code. These madafuckers put
        # an actual \n in the string to mess with me
        solution = "Now that the party is jumping\n"
        path = os.path.join(os.path.dirname(__file__), "4.txt")
        with open(path, "rb") as f:
            lines = f.read().splitlines()
        lines = [binascii.unhexlify(line) for line in lines]
        # Find the best decryption, key and score for each line
        cracked = [crack_xor_single_byte_key(line) for line in lines]
        decrypted, key, score = max(cracked, key=lambda x: x[2])
        self.assertEqual(solution, decrypted)
        print "%s decrypted using %s" % (decrypted, score)
