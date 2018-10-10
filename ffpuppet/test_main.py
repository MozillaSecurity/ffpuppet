# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

import ffpuppet
from .main import main

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")

CWD = os.path.realpath(os.path.dirname(__file__))
TESTFF_BIN = os.path.join(CWD, "testff", "testff.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testff.py")
TESTMDSW_BIN = os.path.join(CWD, "testmdsw", "testmdsw.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testmdsw.py")

ffpuppet.FFPuppet.MDSW_BIN = TESTMDSW_BIN
ffpuppet.FFPuppet.MDSW_MAX_STACK = 8

class TestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sys.platform.startswith('win') and not os.path.isfile(TESTFF_BIN):
            raise EnvironmentError("testff.exe is missing see testff.py for build instructions") # pragma: no cover
        if sys.platform.startswith('win') and not os.path.isfile(TESTMDSW_BIN):
            raise EnvironmentError("testmdsw.exe is missing see testmdsw.py for build instructions") # pragma: no cover


class MainTests(TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ffp_test")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_01(self):
        "test calling main with '-h'"
        with self.assertRaises(SystemExit):
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

    def test_04(self):
        "test sending SIGINT"
        out_logs = os.path.join(self.tmpdir, "logs")
        with tempfile.TemporaryFile() as console:
            proc = subprocess.Popen(
                [sys.executable, "-m", "ffpuppet", TESTFF_BIN, "-l", out_logs],
                cwd=os.path.split(os.path.split(ffpuppet.__file__)[0])[0],
                shell=False,
                stderr=console,
                stdout=console)
            self.assertIsNone(proc.poll())
            while proc.poll() is None:
                console.seek(0)
                if b"launched" in console.read():
                    break
            os.kill(proc.pid, signal.SIGINT)
            self.assertIsNotNone(proc.wait())
            console.seek(0)
            output = console.read()
        self.assertIn(b"Ctrl+C detected", output)
        self.assertTrue(os.path.isdir(out_logs))
        self.assertGreater(len(os.listdir(out_logs)), 0)
