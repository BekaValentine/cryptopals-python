"""
Challenge 2: Fixed XOR
"""


# To ensure that the implementation is correct, we should first establish some
# standard test cases. We'll use `pytest` to perform the tests, and we'll put
# them directly in line with the code so that the criteria for correctness are
# clear to anyone reading the implementation.
import pytest


# ##############################################################################
#
# Main Implementation
#
# ##############################################################################


def multibyte_xor(bs0, bs1):
    # type: (bytes, bytes) -> bytes

    return bytes(map(int.__xor__, bs0, bs1))


# ##############################################################################
#
# Testing
#
# ##############################################################################


# Cryptopals gives us the following baseline test:
def test_cryptopals_challenge2():
    assert multibyte_xor(bytes.fromhex('1c0111001f010100061a024b53535009181c'),
                         bytes.fromhex('686974207468652062756c6c277320657965')) \
        == bytes.fromhex('746865206b696420646f6e277420706c6179')
