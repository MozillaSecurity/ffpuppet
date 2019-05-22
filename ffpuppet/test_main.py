# coding=utf-8
"""ffpuppet main.py tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=missing-docstring

import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

import ffpuppet
from .main import dump_to_console, main

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")  # pylint: disable=invalid-name

CWD = os.path.realpath(os.path.dirname(__file__))
PLAT = sys.platform.lower()

TESTFF_BIN = os.path.join(CWD, "resources", "testff.py")
TESTMDSW_BIN = os.path.join(CWD, "resources", "testmdsw.py")

ffpuppet.FFPuppet.MDSW_BIN = TESTMDSW_BIN
ffpuppet.FFPuppet.MDSW_MAX_STACK = 8


class MainTests(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ffp_test")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_01(self):
        "test calling main with '-h' and invalid input"
        with self.assertRaises(SystemExit):
            main(["-h"])

        with self.assertRaises(SystemExit):
            main([TESTFF_BIN, "-p", "/missing/prefs/file"])

        with self.assertRaises(SystemExit):
            main([TESTFF_BIN, "-e", "/missing/ext/file"])

        with self.assertRaises(SystemExit):
            main([TESTFF_BIN, "--gdb", "--valgrind"])

        with self.assertRaises(SystemExit):
            main([TESTFF_BIN, "--rr"])

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

    @unittest.skipIf(PLAT.startswith('win'), "This test is unsupported on Windows")
    def test_04(self):
        "test sending SIGINT"
        prefs = os.path.join(self.tmpdir, "pref.js")
        with open(prefs, "w") as prefs_fp:
            # spam logs
            prefs_fp.write("//fftest_big_log\n")
        out_logs = os.path.join(self.tmpdir, "logs")
        with tempfile.TemporaryFile() as console:
            proc = subprocess.Popen(
                [sys.executable, "-m", "ffpuppet", TESTFF_BIN, "-d", "-p", prefs, "-l", out_logs],
                cwd=os.path.split(os.path.split(ffpuppet.__file__)[0])[0],
                stderr=console,
                stdout=console)
            while proc.poll() is None:
                console.seek(0)
                output = console.read()
                if b"Running Firefox" in output:
                    break
            # verify we are in a good state otherwise display console output
            self.assertIn(b"Running Firefox", output)
            self.assertIsNone(proc.poll())
            proc.send_signal(signal.SIGINT)
            self.assertIsNotNone(proc.wait())
            console.seek(0)
            output = console.read()
        self.assertIn(b"Ctrl+C detected", output)
        self.assertIn(b"Firefox process closed", output)
        self.assertTrue(os.path.isdir(out_logs))
        self.assertGreater(len(os.listdir(out_logs)), 0)

    def test_05(self):
        "test dump_to_console()"
        # call with no logs
        dump_to_console(self.tmpdir, False)
        # call with dummy logs
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            for _ in range(1024):
                log_fp.write("test")
        dump_to_console(self.tmpdir, True, log_quota=100)
