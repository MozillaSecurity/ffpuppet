# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import shutil
import sys
import tempfile
import unittest

from ffpuppet import FFPuppet
from .main import main

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")

CWD = os.path.realpath(os.path.dirname(__file__))
TESTFF_BIN = os.path.join(CWD, "testff", "testff.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testff.py")
TESTMDSW_BIN = os.path.join(CWD, "testmdsw", "testmdsw.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testmdsw.py")

FFPuppet.MDSW_BIN = TESTMDSW_BIN
FFPuppet.MDSW_MAX_STACK = 8

class TestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sys.platform.startswith('win') and not os.path.isfile(TESTFF_BIN):
            raise EnvironmentError("testff.exe is missing see testff.py for build instructions") # pragma: no cover
        if sys.platform.startswith('win') and not os.path.isfile(TESTMDSW_BIN):
            raise EnvironmentError("testmdsw.exe is missing see testmdsw.py for build instructions") # pragma: no cover

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)

class MainTests(TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ffp_test")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_01(self):
        "test calling main with '-h'"
        with self.assertRaisesRegex(SystemExit, "0"):
            main(["-h"])

    def test_02(self):
        "test calling main with test binary/script"
        out_logs = os.path.join(self.tmpdir, "logs")
        prefs = os.path.join(self.tmpdir, "pref.js")
        with open(prefs, "w") as prefs_fp:
            prefs_fp.write("//fftest_exit_code_0\n")
        main([TESTFF_BIN, "-d", "-l", out_logs, "-p", prefs])
        self.assertTrue(os.path.isdir(out_logs))
        self.assertGreater(len(os.listdir(out_logs)), 0)

    def test_03(self):
        "test calling main with test binary/script"
        prefs = os.path.join(self.tmpdir, "pref.js")
        with open(prefs, "w") as prefs_fp:
            prefs_fp.write("//fftest_big_log\n")
        main([TESTFF_BIN, "-v", "-d", "-p", prefs, "--log-limit", "1", "-a", "blah_test"])
