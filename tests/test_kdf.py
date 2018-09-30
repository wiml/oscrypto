# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import binascii

from oscrypto import kdf, _pkcs5

from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


class KDFTests(unittest.TestCase):

    def test_pbkdf1(self):
        key = kdf.pbkdf1('sha1', b'password', b'\x78\x57\x8E\x5A\x5D\x63\xCB\x06', 1000, 16)
        self.assertEqual(b'\xDC\x19\x84\x7E\x05\xC6\x4D\x2F\xAF\x10\xEB\xFB\x4A\x3D\x2A\x20', key)

    def test_pbkdf2(self):
        key = kdf.pbkdf2('sha1', b'password', b'\x78\x57\x8E\x5A\x5D\x63\xCB\x06', 2048, 24)
        self.assertEqual(
            b'\xBF\xDE\x6B\xE9\x4D\xF7\xE1\x1D\xD4\x09\xBC\xE2\x0A\x02\x55\xEC\x32\x7C\xB9\x36\xFF\xE9\x36\x43',
            key
        )

    def test_python_pbkdf2(self):
        key = _pkcs5.pbkdf2('sha1', b'password', b'\x78\x57\x8E\x5A\x5D\x63\xCB\x06', 2048, 24)
        self.assertEqual(
            b'\xBF\xDE\x6B\xE9\x4D\xF7\xE1\x1D\xD4\x09\xBC\xE2\x0A\x02\x55\xEC\x32\x7C\xB9\x36\xFF\xE9\x36\x43',
            key
        )

    def test_pkcs12_kdf(self):
        key = kdf.pkcs12_kdf('sha1', b'sesame', b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', 2048, 24, 1)
        self.assertEqual(
            b'\x7C\xD9\xFD\x3E\x2B\x3B\xE7\x69\x1A\x44\xE3\xBE\xF0\xF9\xEA\x0F\xB9\xB8\x97\xD4\xE3\x25\xD9\xD1',
            key
        )

    def test_python_X9_63(self):
        def _test(hash_algorithm, Z_, shared_, output_):
            Z = binascii.a2b_hex(Z_)
            shared = binascii.a2b_hex(shared_)
            output = binascii.a2b_base64(output_)

            computed = kdf.x963_kdf(
                hash_algorithm,
                Z, len(output), shared
            )
            self.assertEqual(computed, output)

        # This is a selection of test vectors
        # from NIST CAVS for ANS X9.63-2001

        _test('sha1',
              '1c7d7b5f0597b03d06a018466ed1a93e30ed4b04dc64ccdd',
              '',
              'v3Hf/Y9NmSI5Nr60b+6MzA==')

        _test('sha256',
              '22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d',
              '75eef81aa3041e33b80971203d2c0c52',
              'xJivdxYcxZ8pYrmnE+KyFRUtE5dmzjSndt8Rhmppvy5SoT2cfG/IeMUM'
              'XqC8ewDg2iRHz9h09s+S8w0AlxEUhVAMkMOvi0h4ctBGhdFMjR3I1/oI'
              'vrDOCrq8EfC9SWJpFC1DUlp45bx5oX9ZZ2pXBtxU1U1NHwvX44YSjsJq'
              '/CE=')

        _test('sha384',
              '75a43f6464c2954efd9558d2d9c76cfcafefec3f07fe14af',
              '6744c4a41d5bd7f4ca94ea488605c3d3',
              'UEWmJSybbrgN68Z+DRGgKL+OHwsnTROuvMfVZeG3PtIoxfQZXr0QRKr5'
              'p1XGlFpyl2f482l62ylB3w9En9/Kj4Sr78UBHUuWitH3m1Nb8STj3PEx'
              '+PiU7mM6BAw0pkcFREl649lsHkvNxZFNQMSnPx4XSym9V1XRqgo93T+U'
              'KNU=')
