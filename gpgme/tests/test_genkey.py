# pygpgme - a Python wrapper for the gpgme library
# Copyright (C) 2006  James Henstridge
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import unittest
import StringIO

import gpgme
from gpgme.tests.util import GpgHomeTestCase


class GenerateKeyTestCase(GpgHomeTestCase):

    def test_key_generation(self):
        ctx = gpgme.Context()

        # See /usr/share/doc/gnupg/DETAILS.gz
        # XXX we are using a passwordless key because the passphrase_cb
        # backend seems to be currently broken.
        param = """
        <GnupgKeyParms format="internal">
           Key-Type: RSA
           Key-Length: 1024
           Name-Real: Testing
           Expire-Date: 0
        </GnupgKeyParms>
        """
        result = ctx.genkey(param)
        self.assertEquals(result, None)

        # The generated key is part of the current keyring.
        [key] = ctx.keylist(None, True)
        self.assertEqual(key.revoked, False)
        self.assertEqual(key.expired, False)
        self.assertEqual(key.secret, True)
        self.assertEqual(key.protocol, gpgme.PROTOCOL_OpenPGP)

        # Signing-only RSA keys contain only one subkey.
        self.assertEqual(len(key.subkeys), 1)
        self.assertTrue(key.subkeys[0].secret)

        # The only UID available matches the given parameters.
        [uid] = key.uids
        self.assertEqual(uid.name, 'Testing')
        self.assertEqual(uid.comment, '')
        self.assertEqual(uid.email, '')

        # The generated key is able to sign.
        ctx.armor = True
        ctx.signers = [key]
        plaintext = StringIO.StringIO('Hello World\n')
        signature = StringIO.StringIO()

        new_sigs = ctx.sign(
            plaintext, signature, gpgme.SIG_MODE_DETACH)

        signature.seek(0)
        plaintext.seek(0)
        sigs = ctx.verify(signature, plaintext, None)

        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0].fpr, key.subkeys[0].fpr)


def test_suite():
    loader = unittest.TestLoader()
    return loader.loadTestsFromName(__name__)


if __name__ == '__main__':
    unittest.main()
