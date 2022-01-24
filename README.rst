Introduction
============

.. image:: https://readthedocs.org/projects/adafruit-circuitpython-hashlib/badge/?version=latest
    :target: https://docs.circuitpython.org/projects/hashlib/en/latest/
    :alt: Documentation Status

.. image:: https://img.shields.io/discord/327254708534116352.svg
    :target: https://adafru.it/discord
    :alt: Discord

.. image:: https://github.com/adafruit/Adafruit_CircuitPython_hashlib/workflows/Build%20CI/badge.svg
    :target: https://github.com/adafruit/Adafruit_CircuitPython_hashlib/actions/
    :alt: Build Status

This module implements a common interface to many different secure hash and message digest algorithms.
Included are the FIPS secure hash algorithms SHA1, SHA224, SHA256, SHA384, and SHA512 (defined in FIPS 180-2)
as well as RSA’s MD5 algorithm (defined in Internet RFC 1321).

The SHA1 algorithm is not supported by the CircuitPython module.


`This library is based on the work performed in the micropython-lib hashlib module by Paul Sokolovsky <https://github.com/micropython/micropython-lib/tree/master/hashlib>`_


Dependencies
=============
This driver depends on:

* `Adafruit CircuitPython <https://github.com/adafruit/circuitpython>`_

Please ensure all dependencies are available on the CircuitPython filesystem.
This is easily achieved by downloading
`the Adafruit library and driver bundle <https://github.com/adafruit/Adafruit_CircuitPython_Bundle>`_.

Installing from PyPI
=====================
On supported GNU/Linux systems like the Raspberry Pi, you can install the driver locally `from
PyPI <https://pypi.org/project/adafruit-circuitpython-hashlib/>`_. To install for current user:

.. code-block:: shell

    pip3 install adafruit-circuitpython-hashlib

To install system-wide (this may be required in some cases):

.. code-block:: shell

    sudo pip3 install adafruit-circuitpython-hashlib

To install in a virtual environment in your current project:

.. code-block:: shell

    mkdir project-name && cd project-name
    python3 -m venv .env
    source .env/bin/activate
    pip3 install adafruit-circuitpython-hashlib

Usage Example
=============

.. code-block:: python

        import adafruit_hashlib as hashlib
        m = hashlib.sha256()
        m.update(b"CircuitPython")
        print("Msg Hex Digest: {}\nMsg Digest Size: {}\nMsg Block Size: {}".format(
                m.hexdigest(), m.digest_size, m.block_size))

Documentation
=============

API documentation for this library can be found on `Read the Docs <https://docs.circuitpython.org/projects/hashlib/en/latest/>`_.

Contributing
============

Contributions are welcome! Please read our `Code of Conduct
<https://github.com/adafruit/Adafruit_CircuitPython_hashlib/blob/main/CODE_OF_CONDUCT.md>`_
before contributing to help this project stay welcoming.

Documentation
=============

For information on building library documentation, please check out `this guide <https://learn.adafruit.com/creating-and-sharing-a-circuitpython-library/sharing-our-docs-on-readthedocs#sphinx-5-1>`_.
