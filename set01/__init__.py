import base64
import binascii
import itertools

from cStringIO import StringIO


def b64_encode_hex(hex_string):
    data = binascii.unhexlify(hex_string)
    return base64.b64encode(data)


def xor_buffer(buf, key):
    """
    :type key: basestring 
    """
    key = itertools.cycle(key)
    output = StringIO()
    for b in buf:
        output.write(chr(ord(b) ^ ord(key.next())))
    return output.getvalue()


class TextRecognizer(object):
    ASCII_PRINTABLES = set(chr(c) for c in range(32, 127))
    ENGLISH_AVG_WORD_LEN = 5.0
    FREQ_MAP = {
        " ": 0.2,
        "E": 1.202,
        "T": 0.910,
        "A": 0.812,
        "O": 0.768,
        "I": 0.731,
        "N": 0.695,
        "S": 0.628,
        "R": 0.602,
        "H": 0.592,
        "D": 0.432,
        "L": 0.398,
        "U": 0.288,
        "C": 0.271,
        "M": 0.261,
        "F": 0.230,
        "Y": 0.211,
        "W": 0.209,
        "G": 0.203,
        "P": 0.182,
        "B": 0.149,
        "V": 0.111,
        "K": 0.069,
        "X": 0.017,
        "Q": 0.011,
        "J": 0.010,
        "Z": 0.007,
    }

    @classmethod
    def grade(cls, text):
        score = 0
        for c in text.upper():
            if c in cls.FREQ_MAP:
                score += cls.FREQ_MAP.get(c, 0)
        return score * cls.grade_number_of_words(text)

    @classmethod
    def grade_number_of_words(cls, text):
        expected_words = len(text) / cls.ENGLISH_AVG_WORD_LEN
        num_words = len([w for w in text.split(" ") if w])

        num_words = min(num_words, expected_words * 2)
        normalized = abs(expected_words - num_words) / expected_words
        return 1 - normalized  # as a score. 1 means perfect.


def crack_xor_single_byte_key(encrypted_text):
    grader = TextRecognizer()
    top_score = -1
    found_key = None
    decrypted = None
    for key in xrange(256):
        keystr = chr(key)
        maybe = xor_buffer(encrypted_text, keystr)
        score = grader.grade(maybe)
        if score > top_score:
            top_score = score
            found_key = keystr
            decrypted = maybe
    return decrypted, found_key, top_score
