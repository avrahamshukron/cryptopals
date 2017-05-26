PKCS7_PAD_BYTE = "\x04"  # EOT


def pad_pkcs7(buf, size):
    """
    :type buf: str
    """
    return buf.ljust(size, PKCS7_PAD_BYTE)
