import unittest

try:
    import interpreters
except ModuleNotFoundError:
    try:
        from interpreters_backport import interpreters
    except ModuleNotFoundError:
        interpreters = None

import gpgme
from tests.util import GpgHomeTestCase


@unittest.skipIf(interpreters is None, "interpreters module required")
class MultipleInterpretersTestCase(GpgHomeTestCase):

    import_keys = ['key1.pub']

    def setUp(self) -> None:
        super().setUp()
        self.interp = interpreters.create()
        self.addCleanup(self.interp.close)
        self.queue = interpreters.create_queue()
        # FIXME: Passing a queue between interpreters fails if the
        # interpreter hasn't imported the _interpqueues module:
        # https://github.com/ericsnowcurrently/interpreters/issues/20
        self.interp.exec(f"import {interpreters.queues.__name__}")
        self.interp.prepare_main(queue=self.queue)

    def test_types_are_distinct(self) -> None:
        @self.interp.call
        def f() -> None:
            import gpgme

            queue.put((
                ('Context', id(gpgme.Context)),
                ('Key', id(gpgme.Key)),
                ('PubkeyAlgo', id(gpgme.PubkeyAlgo)),
            ))

        classes = dict(self.queue.get())
        self.assertNotEqual(classes['Context'], id(gpgme.Context))
        self.assertNotEqual(classes['Key'], id(gpgme.Key))
        self.assertNotEqual(classes['PubkeyAlgo'], id(gpgme.PubkeyAlgo))

    def test_verify(self) -> None:
        @self.interp.call
        def f() -> None:
            from io import BytesIO
            from textwrap import dedent
            import gpgme

            signature = BytesIO(dedent('''
                -----BEGIN PGP MESSAGE-----
                Version: GnuPG v1.4.1 (GNU/Linux)

                owGbwMvMwCTotjv0Q0dM6hLG00JJDM7nNx31SM3JyVcIzy/KSeHqsGdmBQvCVAky
                pR9hmGfw0qo3bfpWZwun5euYAsUcVkyZMJlhfvkU6UBjD8WF9RfeND05zC/TK+H+
                EQA=
                =HCW0
                -----END PGP MESSAGE-----
                ''').encode('ASCII'))
            plaintext = BytesIO()
            ctx = gpgme.Context()
            sigs = ctx.verify(signature, None, plaintext)
            assert plaintext.getvalue() == b'Hello World\n'
