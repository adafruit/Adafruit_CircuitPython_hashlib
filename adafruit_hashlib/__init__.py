# The MIT License (MIT)
#
# Copyright (c) 2017 Paul Sokolovsky
# Modified by Brent Rubell for Adafruit Industries, 2019
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
`adafruit_hashlib`
================================================================================

Secure hashes and message digests


* Author(s): Paul Sokolovsky, Brent Rubell

Implementation Notes
--------------------

**Hardware:**

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases
"""
try:
    import hashlib
except ImportError:
    from adafruit_hashlib._sha256 import sha224, sha256
    from adafruit_hashlib._sha512 import sha384, sha512
    from adafruit_hashlib._sha1 import sha1
    from adafruit_hashlib._md5 import md5

__version__ = "0.0.0-auto.0"
__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_hashlib.git"

# FIPS secure hash algorithms supported by this library
ALGOS_AVAIL = ["sha1", "md5", "sha224", "sha256", "sha384", "sha512"]


def new(algo, data=b""):
    """Creates a new hashlib object.
    :param str algo: Name of the desired algorithm.
    :param str data: First parameter.
    """
    try:
        hash_object = globals()[algo]
        return hash_object(data)
    except KeyError:
        raise ValueError(algo)


@property
def algorithms_available():
    """Returns a list containing the names of the hash
    algorithms that are available in this module.
    """
    return ALGOS_AVAIL
