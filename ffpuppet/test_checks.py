# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import re
import shutil
import tempfile
import unittest

from .checks import CheckLogContents, CheckLogSize, CheckMemoryUsage


class CheckTests(unittest.TestCase):
    def setUp(self):
        _fd, self.tmpfn = tempfile.mkstemp(prefix="check_test_")
        os.close(_fd)
        self.tmpdir = tempfile.mkdtemp(prefix="check_test_")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        if os.path.isfile(self.tmpfn):
            os.remove(self.tmpfn)

    def test_01(self):
        "test CheckLogContents()"
        # input contains token
        with open(self.tmpfn, "w") as in_fp:
            in_fp.write("blah\nfoo\ntest\n123")
        checker = CheckLogContents([self.tmpfn], [re.compile("test")])
        self.assertTrue(checker.check())
        with open(self.tmpfn, "wb") as log_fp:
            checker.dump_log(log_fp)
            self.assertGreater(log_fp.tell(), 1)
        # input does not contains token
        checker = CheckLogContents([self.tmpfn], [re.compile("no_token")])
        self.assertFalse(checker.check())
        with open(self.tmpfn, "wb") as log_fp:
            checker.dump_log(log_fp)
            self.assertEqual(log_fp.tell(), 0)
        # log does not exist
        checker = CheckLogContents(["missing_log"], [re.compile("no_token")])
        self.assertFalse(checker.check())
        with open(self.tmpfn, "wb") as log_fp:
            checker.dump_log(log_fp)
            self.assertEqual(log_fp.tell(), 0)
        # input exceeds line buffer
        try:
            CheckLogContents.buf_limit = 10
            with open(self.tmpfn, "w") as in_fp:
                in_fp.write("A" * 9)
                in_fp.write("test")
                in_fp.write("A" * 20)
            checker = CheckLogContents([self.tmpfn], [re.compile("test")])
            self.assertFalse(checker.check())
            self.assertTrue(checker.check())
        finally:
            CheckLogContents.buf_limit = 0x20000
        with open(self.tmpfn, "wb") as log_fp:
            checker.dump_log(log_fp)
            self.assertGreater(log_fp.tell(), 1)

    def test_02(self):
        "test CheckLogSize()"
        stde = os.path.join(self.tmpdir, "stderr")
        stdo = os.path.join(self.tmpdir, "stdout")
        with open(stde, "w") as out_fp:
            out_fp.write("test\n")
        with open(stdo, "w") as out_fp:
            out_fp.write("test\n")
        checker = CheckLogSize(1, stde, stdo)
        self.assertTrue(checker.check())
        with open(self.tmpfn, "wb") as log_fp:
            checker.dump_log(log_fp)
            self.assertGreater(log_fp.tell(), 1)
        checker = CheckLogSize(12, stde, stdo)
        self.assertFalse(checker.check())
        with open(self.tmpfn, "wb") as log_fp:
            checker.dump_log(log_fp)
            self.assertEqual(log_fp.tell(), 0)

    def test_03(self):
        "test CheckMemoryUsage()"
        checker = CheckMemoryUsage(os.getpid(), 300 * 1024 * 1024)
        self.assertFalse(checker.check())
        with open(self.tmpfn, "wb") as log_fp:
            checker.dump_log(log_fp)
            self.assertEqual(log_fp.tell(), 0)
        checker = CheckMemoryUsage(os.getpid(), 10)
        self.assertTrue(checker.check())
        with open(self.tmpfn, "wb") as log_fp:
            checker.dump_log(log_fp)
            self.assertGreater(log_fp.tell(), 1)
