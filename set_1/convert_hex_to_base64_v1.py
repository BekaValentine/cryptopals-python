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


# To convert any given triple octet, we just convert its respective sextet parts
# accounting for the need to pad when there are fewer than 3 bytes.
def encode_triple_octet(some_bytes):
    """
    Encode up to three octets, accounting for padding.
    """

    # This particular implementation uses stringy representation of bit strings
    # and thus for sextets. We'll clean this up in a subsequent implementation.
    bitstrings = bytes_to_6bits_list(some_bytes)

    if len(some_bytes) == 3:
        # Three bytes means four sextets and we're good to encode them all.
        return encoding_for_sextet(bitstrings[0]) +\
            encoding_for_sextet(bitstrings[1]) +\
            encoding_for_sextet(bitstrings[2]) +\
            encoding_for_sextet(bitstrings[3])

    elif len(some_bytes) == 2:
        # Two bytes means we have only 16 bits, so we need to pad to get a
        # multiple of 6. By convention, we pad with 0's up to 18, and then
        # encode. After the encoded sextets, we append a single '=' to indicate
        # that we've padded with '00'.
        return encoding_for_sextet(bitstrings[0]) +\
            encoding_for_sextet(bitstrings[1]) +\
            encoding_for_sextet(bitstrings[2] + '00') +\
            '='

    elif len(some_bytes) == 1:
        # One byte means we have only 8 bits, and need to pad to get a multiple
        # of 6. By convention, we pad with 0's up to 12, and then encode. After
        # the encoded sextents, we append a double '=' to indicate that we've
        # padded with '0000'.
        return encoding_for_sextet(bitstrings[0]) +\
            encoding_for_sextet(bitstrings[1] + '0000') +\
            '=='


# We need a way to convert some bytes to lists of sextents, so we just convert
# the bytes to a bit string and chop it up.
def bytes_to_6bits_list(some_bytes):
    """
    Convert a bytestring to a list of 6 bit long bit strings.

    The last string may be less than 6 bits.
    """

    initial_bitstring = bytes_to_bitstring(some_bytes)
    bitstrings = [initial_bitstring[i:i + 6]
                  for i in range(0, len(initial_bitstring), 6)]

    return bitstrings


# Converting some bytes to a bitstring is easy: we just convert each byte and
# concatenate.
def bytes_to_bitstring(some_bytes):
    """
    Convert a bytestring to a literal string of 1s and 0s.
    """

    return ''.join([byte_to_bitstring(b) for b in some_bytes])


# Converting some byte to a bit string is each, we just append a '1' or '0' as
# we move through each bit.
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


# Encoding a sextet is easy enough. We'll take advantage of the fact that the
# encoding for base 64 isn't random, but instead, that the sextets increment as
# the ASCII code for the encoding increments. For instance, the sextet '000000'
# is encoded as 'A' which is ASCII 65, '000001' is encoded as 'B' i.e. ASCII 66,
# and so on. We can thus just figure out which range of ASCII we need to encode
# into based on the numeric value of the sextet, and convert straight from the
# ASCII code.
#
# The use of a convertion from bitstrings to ints is unfortunate, because it
# adds some inefficiencies, but it's a good first representation due to its
# straightforwardness.
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


# Finally, to convert a bit string to an int, we just need to do some bit
# twiddling and addition.
def bits_to_int(bits):
    """
    Convert a bitstring to an integer.
    """

    return sum([0 if b == '0' else (1 << i) for i, b in enumerate(reversed(bits))])


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
