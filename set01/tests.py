import os
import base64
import unittest
import binascii

from Crypto.Cipher import AES

import core


class Set01Tests(unittest.TestCase):

    def test_task01(self):
        initial_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        computed_b64 = core.b64_encode_hex(initial_string)
        self.assertEqual(computed_b64, expected)

    def test_task02(self):
        s1 = "1c0111001f010100061a024b53535009181c"
        s2 = "686974207468652062756c6c277320657965"
        expected_xor = "746865206b696420646f6e277420706c6179"

        xored = core.xor_buffer(binascii.unhexlify(s1), binascii.unhexlify(s2))
        self.assertEqual(binascii.hexlify(xored), expected_xor)

    def test_task03(self):
        encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        # solution found by actually running the code
        solution = "Cooking MC's like a pound of bacon"
        decrypted, key, score = core.crack_single_byte_xor_key(
            binascii.unhexlify(encrypted))
        self.assertEqual(solution, decrypted)
        print "%s decrypted using %s with score of %s" % (decrypted, key, score)

    def test_task04(self):
        # solution found by actually running the code. These madafuckers put
        # an actual \n in the string to mess with me
        solution = "Now that the party is jumping\n"
        path = os.path.join(os.path.dirname(__file__), "4.txt")
        with open(path, "rb") as f:
            lines = f.read().splitlines()
        lines = [binascii.unhexlify(line) for line in lines]
        # Find the best decryption, key and score for each line
        cracked = [core.crack_single_byte_xor_key(line) for line in lines]
        decrypted, key, score = max(cracked, key=lambda x: x[2])
        self.assertEqual(solution, decrypted)
        print "%s decrypted using %s with score of %s" % (decrypted, key, score)

    def test_task05(self):
        plaintext = "Burning 'em, if you ain't quick and nimble\n" \
                    "I go crazy when I hear a cymbal"
        expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c" \
                   "2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b" \
                   "2027630c692b20283165286326302e27282f"
        key = "ICE"
        result = core.xor_buffer(plaintext, key)
        hexlified = binascii.hexlify(result)
        self.assertEqual(hexlified, expected)

    def test_hamming_distance(self):
        a = "this is a test"
        b = "wokka wokka!!!"
        distance = core.hamming_distance(a, b)
        self.assertEqual(distance, 37)

    def test_task06(self):
        # expected_key found by running this test and printing the key
        expected_key = "Terminator X: Bring the noise"
        input_file = os.path.join(os.path.dirname(__file__), "6.txt")
        with open(input_file, "rb") as f:
            data = f.read()
        ciphertext = base64.b64decode(data)
        key_len, distance = core.find_xor_key_len(
            ciphertext, max_len=40, min_len=2)
        print "The key is probably of %s length" % (key_len,)
        key = core.crack_repeating_xor_key(ciphertext, key_len)
        self.assertEqual(key, expected_key)
        print "Key cracked: %s" % (key,)

    def test_task07(self):
        input_file = os.path.join(os.path.dirname(__file__), "7.txt")
        key = "YELLOW SUBMARINE"
        # Trust me
        expected_plaintext_start = "I'm back and I'm ringin' the bell"
        with open(input_file, "rb") as f:
            data = f.read()
        ciphertext = base64.b64decode(data)
        cipher = AES.new(key, mode=AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        self.assertTrue(plaintext.startswith(expected_plaintext_start))

    def test_task08(self):
        expected_line = 132  # Trust me
        expected_identical_blocks = 3  # Again, trust me
        input_file = os.path.join(os.path.dirname(__file__), "8.txt")
        with open(input_file, "rb") as f:
            data = f.read()
        lines = [binascii.unhexlify(line) for line in data.splitlines()]
        found_blocks = [core.count_identical_blocks(line, 16) for line in lines]
        for i, num_blocks in enumerate(found_blocks):
            self.assertEqual(
                num_blocks,
                0 if i != expected_line else expected_identical_blocks
            )
