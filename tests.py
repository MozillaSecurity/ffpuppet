import os
import sys
import tempfile
import unittest

import ffpuppet


class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class PuppetTests(TestCase):

    def test_0(self):
        fd, fn = tempfile.mkstemp()
        os.close(fd)
        try:
            ffp = ffpuppet.FFPuppet()
            with self.assertRaisesRegex(IOError, "is not an executable"):
                try:
                    ffp.launch(fn)
                finally:
                    ffp.close()
                    ffp.save_log(fn)
                    ffp.clean_up()
        finally:
            os.unlink(fn)

