import unittest

def test_suite():
    import gpgme.tests.test_context
    import gpgme.tests.test_keys
    import gpgme.tests.test_keylist
    import gpgme.tests.test_import
    import gpgme.tests.test_export
    import gpgme.tests.test_sign_verify
    import gpgme.tests.test_encrypt_decrypt
    suite = unittest.TestSuite()
    suite.addTest(gpgme.tests.test_context.test_suite())
    suite.addTest(gpgme.tests.test_keys.test_suite())
    suite.addTest(gpgme.tests.test_keylist.test_suite())
    suite.addTest(gpgme.tests.test_import.test_suite())
    suite.addTest(gpgme.tests.test_export.test_suite())
    suite.addTest(gpgme.tests.test_sign_verify.test_suite())
    suite.addTest(gpgme.tests.test_encrypt_decrypt.test_suite())
    return suite
