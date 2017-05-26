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
    ASCII_PRINTABLES = set(chr(c) for c in range(32, 127)).union("\r\n\t")
    FREQ_MAP = {
        " ": 0.2,
        "E": 0.1202,
        "T": 0.0910,
        "A": 0.0812,
        "O": 0.0768,
        "I": 0.0731,
        "N": 0.0695,
        "S": 0.0628,
        "R": 0.0602,
        "H": 0.0592,
        "D": 0.0432,
        "L": 0.0398,
        "U": 0.0288,
        "C": 0.0271,
        "M": 0.0261,
        "F": 0.0230,
        "Y": 0.0211,
        "W": 0.0209,
        "G": 0.0203,
        "P": 0.0182,
        "B": 0.0149,
        "V": 0.0111,
        "K": 0.0069,
        "X": 0.0017,
        "Q": 0.0011,
        "J": 0.0010,
        "Z": 0.0007,
    }

    @classmethod
    def grade(cls, text):
        score = 0
        for c in text.upper():
            if c not in cls.ASCII_PRINTABLES:
                return -1
            if c in cls.FREQ_MAP:
                score += cls.FREQ_MAP.get(c, 0)
        return score


def crack_single_byte_xor_key(encrypted_text):
    top_score = -1
    found_key = None
    decrypted = None
    for key in xrange(256):
        keystr = chr(key)
        maybe = xor_buffer(encrypted_text, keystr)
        score = TextRecognizer.grade(maybe)
        if score > top_score:
            top_score = score
            found_key = keystr
            decrypted = maybe
    return decrypted, found_key, top_score


def hamming_distance(a, b):
    xored = xor_buffer(a, b)
    binary = "".join(bin(ord(c))[2:] for c in xored)
    distance = binary.count("1")
    return distance


def grade_xor_key_length(buf, key_length):
    if len(buf) < 2 * key_length:
        raise ValueError(
            "Cannot score key size %s. Not enough data" % (key_length,))
    chunks = [buf[i:i + key_length] for i in range(0, len(buf), key_length)]
    pairs = [chunks[i: i + 2] for i in range(0, len(chunks), 2)]

    # The last "pair" might be single
    if len(pairs[-1]) == 1:
        pairs = pairs[:-1]

    total = sum(hamming_distance(a, b) / float(key_length) for a, b in pairs)
    return total / len(pairs)


def find_xor_key_len(buf, max_len, min_len=1):
    max_len = min(max_len, len(buf) / 2)
    distances = ((size, grade_xor_key_length(buf, size))
                 for size in range(min_len, max_len + 1))
    sorted_distances = sorted(distances, key=lambda x: x[1])
    return sorted_distances[0]


def key_generator(length):
    """
    Generator that yields all possible strings of length `length`
    :param length: The required key length
    """
    for data in itertools.product(range(256), repeat=length):
        yield "".join(chr(c) for c in data)


def transpose(matrix):
    """
    Matrix Transpose
    :param matrix: An iterable of iterables, all with the same length.
        E.g [[1,2,3], [4,5,6]]
    :return: `matrix` transposed
    """
    n = len(matrix)  # Number of rows
    # Number of columns. Assuming all columns have the same length.
    # If not - IndexError will be raised
    m = len(matrix[0])
    return [[matrix[i][j] for i in range(n)] for j in range(m)]


def crack_repeating_xor_key(ciphertext, key_len):
    chunks = [ciphertext[i: i + key_len]
              for i in range(0, len(ciphertext), key_len)]

    # I only need the first `key_len` chunks to crack the key
    chunks = chunks[:key_len]
    transposed = transpose(chunks)
    transposed = ["".join(t) for t in transposed]  # seq of chars to string
    cracked = [crack_single_byte_xor_key(text) for text in transposed]
    _, key_chars, _ = transpose(cracked)
    key = "".join(key_chars)
    return key


def count_identical_blocks(buf, block_size):
    chunks = [buf[i: i + block_size]
              for i in range(0, len(buf), block_size)]
    return len(chunks) - len(set(chunks))
