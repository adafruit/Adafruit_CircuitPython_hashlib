# SPDX-FileCopyrightText: 1991-1992 RSA Data Security, Inc
# SPDX-FileCopyrightText: 2021 Tim Hawes
#
# SPDX-License-Identifier: RSA-MD
#
# Derived from:
#
# MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
#
# Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
# rights reserved.
#
# License to copy and use this software is granted provided that it
# is identified as the "RSA Data Security, Inc. MD5 Message-Digest
# Algorithm" in all material mentioning or referencing this software
# or this function.
#
# License is also granted to make and use derivative works provided
# that such works are identified as "derived from the RSA Data
# Security, Inc. MD5 Message-Digest Algorithm" in all material
# mentioning or referencing the derived work.
#
# RSA Data Security, Inc. makes no representations concerning either
# the merchantability of this software or the suitability of this
# software for any particular purpose. It is provided "as is"
# without express or implied warranty of any kind.
#
# These notices must be retained in any copies of any part of this
# documentation and/or software.

"""
`_md5.py`
======================================================
MD5 Hash Algorithm.

Based on:
https://tools.ietf.org/html/rfc1321
https://gist.github.com/HoLyVieR/11e464a91b290e33b38e

Modified for Python3 and CircuitPython by Tim Hawes.

* Author(s): RSA Data Security, Olivier Arteau, Tim Hawes
"""
# pylint: disable=invalid-name,missing-function-docstring,too-many-arguments

import binascii
import struct
from micropython import const


# Constants


S11 = const(7)
S12 = const(12)
S13 = const(17)
S14 = const(22)
S21 = const(5)
S22 = const(9)
S23 = const(14)
S24 = const(20)
S31 = const(4)
S32 = const(11)
S33 = const(16)
S34 = const(23)
S41 = const(6)
S42 = const(10)
S43 = const(15)
S44 = const(21)
PADDING = b"\x80" + (b"\x00" * 63)


# F, G, H and I are basic MD5 functions.


def F(x, y, z):
    return (x & y) | ((~x) & z)


def G(x, y, z):
    return (x & z) | (y & (~z))


def H(x, y, z):
    return x ^ y ^ z


def I(x, y, z):
    return y ^ (x | (~z))


# ROTATE_LEFT rotates x left n bits.


def ROTATE_LEFT(x, n):
    x = x & 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
# Rotation is separate from addition to prevent recomputation.


def FF(a, b, c, d, x, s, ac):
    a = a + F(b, c, d) + x + ac
    a = ROTATE_LEFT(a, s)
    a = a + b
    return a


def GG(a, b, c, d, x, s, ac):
    a = a + G(b, c, d) + x + ac
    a = ROTATE_LEFT(a, s)
    a = a + b
    return a


def HH(a, b, c, d, x, s, ac):
    a = a + H(b, c, d) + x + ac
    a = ROTATE_LEFT(a, s)
    a = a + b
    return a


def II(a, b, c, d, x, s, ac):
    a = a + I(b, c, d) + x + ac
    a = ROTATE_LEFT(a, s)
    a = a + b
    return a


def encode(data, length):
    """Encodes input (UINT4) into output (unsigned char). Assumes length is
    a multiple of 4.
    """
    k = length >> 2
    return struct.pack(*("%iI" % k,) + tuple(data[:k]))


def decode(data, length):
    """Decodes input (unsigned char) into output (UINT4). Assumes length is
    a multiple of 4.
    """
    k = length >> 2
    return struct.unpack("%iI" % k, data[:length])


class md5:
    """Returns a md5 hash object; optionally initialized with a string"""

    digest_size = 16
    block_size = 64
    name = "md5"

    def __init__(self, string=b""):
        """Constructs an MD5 hash object."""
        self.count = 0
        self.buffer = b""

        # Load magic initialization constants.
        self.state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

        if string:
            self.update(string)

    def update(self, data):
        """Update the hash object with the bytes-like object."""
        data_len = len(data)

        # Compute number of bytes mod 64
        index = int(self.count >> 3) & 0x3F

        # Update number of bits
        self.count = self.count + (data_len << 3)

        part_len = md5.block_size - index

        # Transform as many times as possible.
        if data_len >= part_len:
            self.buffer = self.buffer[:index] + data[:part_len]
            self._transform(self.buffer)
            i = part_len
            while i + 63 < data_len:
                self._transform(data[i : i + md5.block_size])
                i = i + md5.block_size
            index = 0
        else:
            i = 0

        # Buffer remaining input
        self.buffer = self.buffer[:index] + data[i:data_len]

    def digest(self):
        """Return the digest of the data passed to the update() method so far."""
        # Save digest state
        _buffer, _count, _state = self.buffer, self.count, self.state

        # Save number of bits
        bits = self.count

        # Pad out to 56 mod 64.
        index = (self.count >> 3) & 0x3F
        if index < 56:
            pad_len = 56 - index
        else:
            pad_len = 120 - index
        self.update(PADDING[:pad_len])

        # Append length (before padding)
        self.update(encode((bits & 0xFFFFFFFF, bits >> 32), 8))

        # Save digest output
        result = self.state

        # Restore digest state
        self.buffer, self.count, self.state = _buffer, _count, _state

        return encode(result, md5.digest_size)

    def hexdigest(self):
        """Like digest() except the digest is returned as a string object of
        double length, containing only hexadecimal digits.
        """
        return binascii.hexlify(self.digest()).decode("ascii")

    def copy(self):
        """Return a copy (“clone”) of the hash object."""
        new = md5()
        new.count = self.count
        new.buffer = self.buffer
        new.state = self.state
        return new

    def _transform(self, block):
        """MD5 basic transformation. Transforms state based on block."""
        # pylint: disable=invalid-name,too-many-statements
        a, b, c, d = self.state
        x = decode(block, md5.block_size)

        # Round 1
        a = FF(a, b, c, d, x[0], S11, 0xD76AA478)
        d = FF(d, a, b, c, x[1], S12, 0xE8C7B756)
        c = FF(c, d, a, b, x[2], S13, 0x242070DB)
        b = FF(b, c, d, a, x[3], S14, 0xC1BDCEEE)
        a = FF(a, b, c, d, x[4], S11, 0xF57C0FAF)
        d = FF(d, a, b, c, x[5], S12, 0x4787C62A)
        c = FF(c, d, a, b, x[6], S13, 0xA8304613)
        b = FF(b, c, d, a, x[7], S14, 0xFD469501)
        a = FF(a, b, c, d, x[8], S11, 0x698098D8)
        d = FF(d, a, b, c, x[9], S12, 0x8B44F7AF)
        c = FF(c, d, a, b, x[10], S13, 0xFFFF5BB1)
        b = FF(b, c, d, a, x[11], S14, 0x895CD7BE)
        a = FF(a, b, c, d, x[12], S11, 0x6B901122)
        d = FF(d, a, b, c, x[13], S12, 0xFD987193)
        c = FF(c, d, a, b, x[14], S13, 0xA679438E)
        b = FF(b, c, d, a, x[15], S14, 0x49B40821)

        # Round 2
        a = GG(a, b, c, d, x[1], S21, 0xF61E2562)
        d = GG(d, a, b, c, x[6], S22, 0xC040B340)
        c = GG(c, d, a, b, x[11], S23, 0x265E5A51)
        b = GG(b, c, d, a, x[0], S24, 0xE9B6C7AA)
        a = GG(a, b, c, d, x[5], S21, 0xD62F105D)
        d = GG(d, a, b, c, x[10], S22, 0x02441453)
        c = GG(c, d, a, b, x[15], S23, 0xD8A1E681)
        b = GG(b, c, d, a, x[4], S24, 0xE7D3FBC8)
        a = GG(a, b, c, d, x[9], S21, 0x21E1CDE6)
        d = GG(d, a, b, c, x[14], S22, 0xC33707D6)
        c = GG(c, d, a, b, x[3], S23, 0xF4D50D87)
        b = GG(b, c, d, a, x[8], S24, 0x455A14ED)
        a = GG(a, b, c, d, x[13], S21, 0xA9E3E905)
        d = GG(d, a, b, c, x[2], S22, 0xFCEFA3F8)
        c = GG(c, d, a, b, x[7], S23, 0x676F02D9)
        b = GG(b, c, d, a, x[12], S24, 0x8D2A4C8A)

        # Round 3
        a = HH(a, b, c, d, x[5], S31, 0xFFFA3942)
        d = HH(d, a, b, c, x[8], S32, 0x8771F681)
        c = HH(c, d, a, b, x[11], S33, 0x6D9D6122)
        b = HH(b, c, d, a, x[14], S34, 0xFDE5380C)
        a = HH(a, b, c, d, x[1], S31, 0xA4BEEA44)
        d = HH(d, a, b, c, x[4], S32, 0x4BDECFA9)
        c = HH(c, d, a, b, x[7], S33, 0xF6BB4B60)
        b = HH(b, c, d, a, x[10], S34, 0xBEBFBC70)
        a = HH(a, b, c, d, x[13], S31, 0x289B7EC6)
        d = HH(d, a, b, c, x[0], S32, 0xEAA127FA)
        c = HH(c, d, a, b, x[3], S33, 0xD4EF3085)
        b = HH(b, c, d, a, x[6], S34, 0x04881D05)
        a = HH(a, b, c, d, x[9], S31, 0xD9D4D039)
        d = HH(d, a, b, c, x[12], S32, 0xE6DB99E5)
        c = HH(c, d, a, b, x[15], S33, 0x1FA27CF8)
        b = HH(b, c, d, a, x[2], S34, 0xC4AC5665)

        # Round 4
        a = II(a, b, c, d, x[0], S41, 0xF4292244)
        d = II(d, a, b, c, x[7], S42, 0x432AFF97)
        c = II(c, d, a, b, x[14], S43, 0xAB9423A7)
        b = II(b, c, d, a, x[5], S44, 0xFC93A039)
        a = II(a, b, c, d, x[12], S41, 0x655B59C3)
        d = II(d, a, b, c, x[3], S42, 0x8F0CCC92)
        c = II(c, d, a, b, x[10], S43, 0xFFEFF47D)
        b = II(b, c, d, a, x[1], S44, 0x85845DD1)
        a = II(a, b, c, d, x[8], S41, 0x6FA87E4F)
        d = II(d, a, b, c, x[15], S42, 0xFE2CE6E0)
        c = II(c, d, a, b, x[6], S43, 0xA3014314)
        b = II(b, c, d, a, x[13], S44, 0x4E0811A1)
        a = II(a, b, c, d, x[4], S41, 0xF7537E82)
        d = II(d, a, b, c, x[11], S42, 0xBD3AF235)
        c = II(c, d, a, b, x[2], S43, 0x2AD7D2BB)
        b = II(b, c, d, a, x[9], S44, 0xEB86D391)

        self.state = (
            0xFFFFFFFF & (self.state[0] + a),
            0xFFFFFFFF & (self.state[1] + b),
            0xFFFFFFFF & (self.state[2] + c),
            0xFFFFFFFF & (self.state[3] + d),
        )
