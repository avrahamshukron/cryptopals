from Crypto.Cipher import AES
from cStringIO import StringIO
from Crypto import Random
from Crypto.Random import random

import core


class AESCipherCBC(object):

    VALID_BLOCK_SIZES = (16, 24, 32)

    def __init__(self, key, iv=None):
        """
        :param key: The key. Must be of length of (16, 24, 32).
        :type key: basestring
        :param iv: Initialization Vector for CBC. If None will be all zeros.
        :type iv: basestring 
        """
        self._cipher = AES.new(key, mode=AES.MODE_ECB)
        self._prev = iv if iv is not None else "\x00" * len(key)
        self._block_size = len(key)

    def encrypt(self, plaintext):
        blocks = (plaintext[i: i + self._block_size]
                  for i in range(0, len(plaintext), self._block_size))
        ciphertext = StringIO()
        for block in blocks:
            ciphertext.write(self._encrypt_block(block))
        return ciphertext.getvalue()

    def _encrypt_block(self, plaintext):
        l = len(plaintext)
        if l > self._block_size:
            raise ValueError("Cannot encrypt block with size %s" % (l,))
        if l < self._block_size:
            plaintext = core.pad_pkcs7(plaintext, self._block_size)
        xored = core.xor_buffer(plaintext, self._prev)
        self._prev = self._cipher.encrypt(xored)
        return self._prev

    def decrypt(self, ciphertext):
        blocks = (ciphertext[i: i + self._block_size]
                  for i in range(0, len(ciphertext), self._block_size))
        plaintext = StringIO()
        for block in blocks:
            plaintext.write(self._decrypt_block(block))
        return plaintext.getvalue()

    def _decrypt_block(self, ciphertext):
        if len(ciphertext) != self._block_size:
            raise ValueError("Cannot decrypt block with size %s" %
                             (len(ciphertext),))
        plaintext = self._cipher.decrypt(ciphertext)
        plaintext = core.xor_buffer(plaintext, self._prev)
        self._prev = ciphertext
        return plaintext


def aes_encrypt(plaintext, mode=AES.MODE_ECB):
    randfile = Random.new()
    prefix = randfile.read(random.randint(5, 10))
    suffix = randfile.read(random.randint(5, 10))
    key = randfile.read(AES.block_size)
    iv = randfile.read(AES.block_size)
    cipher = AES.new(key, mode=mode, IV=iv)
    return cipher.encrypt(pad_to_block(prefix + plaintext + suffix))


def ecb_cbc_oracle(encrypt_func):
    """
    Detect AES encryption mode by feeding a large, repeating input that, if
    used in ECB mode, will produce at least two identical blocks.
    
    :param encrypt_func: A function that accept plaintext and encrypts it in
        either ECB or CBC mode.
    :return: `AES.MODE_ECB` or `AES.MODE_CBC`
    """
    plaintext = "a" * 10 * AES.block_size
    ciphertext = encrypt_func(plaintext)
    blocks = [ciphertext[i: i + AES.block_size]
              for i in range(0, len(ciphertext), AES.block_size)]
    unique_blocks = set(blocks)
    return AES.MODE_ECB if len(unique_blocks) != len(blocks) else AES.MODE_CBC


def pad_to_block(plaintext):
    length = len(plaintext)
    remainder = length % AES.block_size
    if remainder == 0:
        return plaintext
    padded = core.pad_pkcs7(plaintext, length + (AES.block_size - remainder))
    return padded
