"""
Challenge 1: Convert hex to base64
"""

import math
import random

# To ensure that the implementation is correct, we should first establish some
# standard test cases. We'll use `pytest` to perform the tests, and we'll put
# them directly in line with the code so that the criteria for correctness are
# clear to anyone reading the implementation.
import pytest
import base64


# ##############################################################################
#
# Main Implementation
#
# ##############################################################################

# The overall encoding of bytes to base64 in this implementation depends on the
# following facts:
#
# 1. A byte is 8 bits, while each b64 character is 6 bits, so the least common
#    multiple is 24 bits, or 3 bytes.
#
# 2. Every number of bytes can be seen as either a) 3n bytes for some n, b)
#    3n + 1 bytes for some n, or c) 3n + 2 bytes for some n.
#
# We can thus convert the whole bytestring into base 64 by converting each
# triple octet. If there is a remaining 2 or 1 byte left over, we can then pad.

# Thus, to convert hex to base 64, we simply convert each triple octet in the
# input bytes:
def hex_to_base64(some_bytes):
    """
    Convert hex to base64.
    """

    return bytes(''.join([encode_triple_octet(some_bytes[i:i + 3])
                          for i in range(0, len(some_bytes), 3)]), encoding='ascii')


# Encoding each triple octet in this version is a little bit nastier to read.
# We need to do a bunch of bit twiddling to pull out each sextet as a number.
# It's not too hard tho: We simply shift over the right number of bytes, then
# bitwise and with a sextet of all '1's. For padding, we shift different amounts
# and the final sextet is constructed by shifting some 0's in on the right. We
# of course do all of this after converting our bytes to a single large number.
def encode_triple_octet(some_bytes):
    """
    Encode up to three octets, accounting for padding.
    """

    sextet = 0b111111

    if len(some_bytes) == 3:
        some_bytes = list(some_bytes)
        some_bytes = 256 * 256 * some_bytes[0] + \
            256 * some_bytes[1] + \
            some_bytes[2]
        return encoding_for_sextet((some_bytes >> 18) & sextet) + \
            encoding_for_sextet((some_bytes >> 12) & sextet) + \
            encoding_for_sextet((some_bytes >> 6) & sextet) + \
            encoding_for_sextet(some_bytes & sextet)

    elif len(some_bytes) == 2:
        some_bytes = list(some_bytes)
        some_bytes = 256 * some_bytes[0] + some_bytes[1]
        return encoding_for_sextet((some_bytes >> 10) & sextet) + \
            encoding_for_sextet((some_bytes >> 4) & sextet) + \
            encoding_for_sextet((some_bytes & 0b1111) << 2) + \
            '='

    elif len(some_bytes) == 1:
        some_bytes = list(some_bytes)
        some_bytes = some_bytes[0]
        return encoding_for_sextet((some_bytes >> 2) & sextet) + \
            encoding_for_sextet((some_bytes & 0b11) << 4) + \
            '=='


# Encoding a sextet can be done with no converting to a number now, since we're
# no longer using an intermediate string encoding in this version.
def encoding_for_sextet(sextet):
    """
    Encode a single sextet as a character.
    """

    if sextet in range(0, 26):
        return chr(ord('A') + sextet)
    elif sextet in range(26, 52):
        return chr(ord('a') + (sextet - 26))
    elif sextet in range(52, 62):
        return chr(ord('0') + (sextet - 52))
    elif sextet == 62:
        return '+'
    elif sextet == 63:
        return '/'
    else:
        raise ValueError(sextet)


# ##############################################################################
#
# Testing
#
# ##############################################################################

# The Cryptopals site provides us with one test, which we ought to include.
# First we'll make sure that the builtin `base64` library encodes it correctly:
test_hex_string = bytes.fromhex(
    '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
test_b64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


# Next we'll make sure that the reference implementation in the `base64` library
# gives us the expected result:
def test_cryptopals_challenge1_reference_implementation():
    assert base64.b64encode(test_hex_string) == test_b64


# And finally we'll check that the custom implementation of the hex-to-base64
# conversion is correct:
def test_cryptopals_challenge1_custom_implementation():
    assert hex_to_base64(test_hex_string) == test_b64


# It's also useful to have some randomized property based testing, so let's
# generate some random hex strings and test those too:
def generate_random_hex():
    l = 2 * random.randrange(5, 25)
    chars = ''.join([random.choice('0123456789abcdef') for _ in range(l)])
    return bytes.fromhex(chars)


# Now we can test 100000 random hex strings against the reference implementation:
def test_100_random_hex_strings():
    for _ in range(100000):
        a_random_hex_string = generate_random_hex()
        assert base64.b64encode(a_random_hex_string) == \
            hex_to_base64(a_random_hex_string)
