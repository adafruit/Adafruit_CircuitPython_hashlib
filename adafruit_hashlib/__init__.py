# SPDX-FileCopyrightText: 2017 Paul Sokolovsky
# SPDX-FileCopyrightText: 2019 Brent Rubell for Adafruit Industries
#
# SPDX-License-Identifier: MIT

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
    from typing import List, Optional, Union
except ImportError:
    pass


try:
    from hashlib import md5, sha1, sha224, sha256, sha512
    from hashlib import sha3_384 as sha384
except ImportError:
    from adafruit_hashlib._md5 import md5
    from adafruit_hashlib._sha1 import sha1
    from adafruit_hashlib._sha256 import sha224, sha256
    from adafruit_hashlib._sha512 import sha384, sha512

__version__ = "0.0.0+auto.0"
__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_hashlib.git"

# FIPS secure hash algorithms supported by this library
ALGOS_AVAIL = ["sha1", "md5", "sha224", "sha256", "sha384", "sha512"]


def new(algo, data: Optional[bytes] = b"") -> Union[md5, sha1, sha224, sha256, sha512]:
    """Creates a new hashlib object.

    :param str algo: Name of the desired algorithm.
    :param str data: First parameter.
    """
    try:
        hash_object = globals()[algo]
        return hash_object(data)
    except KeyError as err:
        raise ValueError(algo) from err


@property
def algorithms_available() -> List[str]:
    """Returns a list containing the names of the hash
    algorithms that are available in this module.
    """
    return ALGOS_AVAIL
