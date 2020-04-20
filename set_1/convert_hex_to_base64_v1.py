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


def byte_to_bitstring(some_byte_as_an_int):
    """
    Convert a byte to a literal string of 1s and 0s.
    """

    bitstring = ''
    for i in range(8):
        if (1 << (7 - i)) & some_byte_as_an_int == 0:
            bitstring += '0'
        else:
            bitstring += '1'
    return bitstring


def bytes_to_bitstring(some_bytes):
    """
    Convert a bytestring to a literal string of 1s and 0s.
    """

    return ''.join([byte_to_bitstring(b) for b in some_bytes])


def bytes_to_6bits_list(some_bytes):
    """
    Convert a bytestring to a list of 6 bit long bit strings.

    The last string may be less than 6 bits.
    """

    initial_bitstring = bytes_to_bitstring(some_bytes)
    bitstrings = [initial_bitstring[i:i + 6]
                  for i in range(0, len(initial_bitstring), 6)]

    return bitstrings


def bits_to_int(bits):
    """
    Convert a bitstring to an integer.
    """

    return sum([0 if b == '0' else (1 << i) for i, b in enumerate(reversed(bits))])


def encoding_for_sextet(bits):
    """
    Encode a single sextet as a character.
    """

    o = bits_to_int(bits)
    if o in range(0, 26):
        return chr(ord('A') + o)
    elif o in range(26, 52):
        return chr(ord('a') + (o - 26))
    elif o in range(52, 62):
        return chr(ord('0') + (o - 52))
    elif o == 62:
        return '+'
    elif o == 63:
        return '/'


def encode_triple_octet(some_bytes):
    """
    Encode up to three octets, accounting for padding.
    """

    bitstrings = bytes_to_6bits_list(some_bytes)

    if len(some_bytes) == 3:
        # raise ValueError(bitstrings)
        return encoding_for_sextet(bitstrings[0]) +\
            encoding_for_sextet(bitstrings[1]) +\
            encoding_for_sextet(bitstrings[2]) +\
            encoding_for_sextet(bitstrings[3])

    elif len(some_bytes) == 2:
        return encoding_for_sextet(bitstrings[0]) +\
            encoding_for_sextet(bitstrings[1]) +\
            encoding_for_sextet(bitstrings[2] + '00') +\
            '='

    elif len(some_bytes) == 1:
        return encoding_for_sextet(bitstrings[0]) +\
            encoding_for_sextet(bitstrings[1] + '0000') +\
            '=='


def hex_to_base64(some_bytes):
    """
    Convert hex to base64.
    """

    return bytes(''.join([encode_triple_octet(some_bytes[i:i + 3])
                          for i in range(0, len(some_bytes), 3)]), encoding='ascii')


# The Cryptopals site provides us with one test, which we ought to include.
# First we'll make sure that the builtin `base64` library encodes it correctly:
test_hex_string = bytes.fromhex(
    '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
test_b64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


# Next we'll make sure that the reference implementation in the `base64` library
# gives us the expected result:
def test_cryptopals_challenge1_reference_implementation():
    assert base64.encodebytes(test_hex_string).strip() == test_b64


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


# Now we can test 100 random hex strings against the reference implementation:
def test_100_random_hex_strings():
    for _ in range(100):
        a_random_hex_string = generate_random_hex()
        assert base64.encodebytes(a_random_hex_string).strip() == \
            hex_to_base64(a_random_hex_string)
