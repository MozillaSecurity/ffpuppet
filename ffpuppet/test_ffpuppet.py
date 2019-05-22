# coding=utf-8
"""ffpuppet tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=invalid-name,protected-access

import errno
import logging
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
try:  # py 2-3 compatibility
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler  # pylint: disable=import-error
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler  # pylint: disable=import-error

from psutil import AccessDenied, NoSuchProcess, Process, wait_procs

from .core import  FFPuppet
from .exceptions import BrowserTimeoutError, BrowserTerminatedError, LaunchError
from .helpers import get_processes, onerror
from .minidump_parser import MinidumpParser

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")

CWD = os.path.realpath(os.path.dirname(__file__))
PLAT = sys.platform.lower()
TESTFF_BIN = os.path.join(CWD, "resources", "testff.py")
TESTMDSW_BIN = os.path.join(CWD, "resources", "testmdsw.py")

MinidumpParser.MDSW_BIN = TESTMDSW_BIN
MinidumpParser.MDSW_MAX_STACK = 8

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):  # pylint: disable=arguments-differ
            return self.assertRegexpMatches(*args, **kwds)  # pylint: disable=deprecated-method

        def assertRaisesRegex(self, *args, **kwds):  # pylint: disable=arguments-differ
            return self.assertRaisesRegexp(*args, **kwds)  # pylint: disable=deprecated-method


class ReqHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello world")


class HTTPTestServer(object):
    def __init__(self, handler=None):
        self._handler = handler if handler is not None else ReqHandler
        while True:
            try:
                self._httpd = HTTPServer(("127.0.0.1", 0), self._handler)
            except socket.error as soc_e:  # pragma: no cover
                if soc_e.errno in (errno.EADDRINUSE, 10013):  # Address already in use
                    continue
                raise
            break
        self._thread = threading.Thread(target=HTTPTestServer._srv_thread, args=(self._httpd,))
        self._thread.start()

    def get_addr(self):
        return "http://127.0.0.1:%d" % self._httpd.server_address[1]

    def shutdown(self):
        if self._httpd is not None:
            self._httpd.shutdown()
        if self._thread is not None:
            self._thread.join()

    @staticmethod
    def _srv_thread(httpd):
        try:
            httpd.serve_forever()
        finally:
            httpd.socket.close()


class PuppetTests(TestCase):  # pylint: disable=too-many-public-methods
    @classmethod
    def setUpClass(cls):
        cls.tsrv = HTTPTestServer()

    @classmethod
    def tearDownClass(cls):
        cls.tsrv.shutdown()

    def setUp(self):
        tmpfd, self.tmpfn = tempfile.mkstemp(prefix="ffp_test_log_")
        os.close(tmpfd)
        self.logs = tempfile.mkdtemp(prefix="ffp_test_log_")

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.unlink(self.tmpfn)
        if os.path.isdir(self.logs):
            shutil.rmtree(self.logs, onerror=onerror)

    @unittest.skipIf(PLAT.startswith("win"), "Unsupported on Windows")
    def test_00(self):
        "test that invalid executables raise the right exception"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with self.assertRaisesRegex(IOError, "is not an executable"):
            ffp.launch(self.tmpfn)

    def test_01(self):
        "test basic launch and close"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertEqual(ffp.launches, 0)
        self.assertEqual(ffp.reason, ffp.RC_CLOSED)
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        self.assertEqual(len(ffp._checks), 0)
        self.assertEqual(ffp.launches, 1)
        self.assertIsNone(ffp.wait(timeout=0))
        self.assertTrue(ffp.is_running())
        self.assertTrue(ffp.is_healthy())
        self.assertIsNone(ffp.reason)
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_CLOSED)
        self.assertIsNone(ffp._proc)
        self.assertFalse(ffp.is_running())
        self.assertFalse(ffp.is_healthy())
        self.assertIsNone(ffp.wait(timeout=10))

    def test_02(self):
        "test crash on start"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_startup_crash\n')
        with self.assertRaisesRegex(BrowserTerminatedError, "Failure during browser startup"):
            ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
        ffp.close()
        self.assertFalse(ffp.is_running())  # process should be gone
        self.assertEqual(ffp.launches, 0)
        self.assertEqual(ffp.reason, ffp.RC_ALERT)

    def test_03(self):
        "test hang on start"
        ffp = FFPuppet()
        default_timeout = ffp.LAUNCH_TIMEOUT_MIN
        try:
            ffp.LAUNCH_TIMEOUT_MIN = 1
            self.addCleanup(ffp.clean_up)
            with open(self.tmpfn, 'w') as prefs:
                prefs.write('//fftest_startup_hang\n')
            start = time.time()
            with self.assertRaisesRegex(BrowserTimeoutError, "Launching browser timed out"):
                ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, launch_timeout=1)
            duration = time.time() - start
            ffp.close()
            self.assertEqual(ffp.reason, ffp.RC_CLOSED)
            self.assertGreater(duration, ffp.LAUNCH_TIMEOUT_MIN)
            self.assertLess(duration, 30)
        finally:
            ffp.LAUNCH_TIMEOUT_MIN = default_timeout

    def test_04(self):
        "test logging"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.close()
        ffp.save_logs(os.path.join(self.logs, "no_logs"))
        with open(self.tmpfn, "w") as prefs:
            prefs.write("//fftest_exit_code_0\n")
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr(), prefs_js=self.tmpfn)
        ffp.wait(timeout=10)
        ffp.close()
        self.assertTrue(ffp._logs.closed)
        log_ids = ffp.available_logs()
        self.assertEqual(len(log_ids), 2)
        self.assertIn("stderr", log_ids)
        self.assertIn("stdout", log_ids)
        log_dir = os.path.join(self.logs, "some_dir")  # nonexistent directory
        ffp.save_logs(log_dir, meta=True)
        self.assertTrue(os.path.isdir(log_dir))
        log_list = os.listdir(log_dir)
        self.assertIn("log_stderr.txt", log_list)
        self.assertIn("log_stdout.txt", log_list)
        self.assertIn(ffp._logs.META_FILE, log_list)
        with open(os.path.join(log_dir, "log_stdout.txt"), "r") as log_fp:
            self.assertIn("url: 'http://", log_fp.read())
        for fname in log_list:
            with open(os.path.join(log_dir, fname)) as log_fp:
                log_data = log_fp.read().splitlines()
            if fname.startswith("log_stderr"):
                self.assertEqual(len(log_data), 3)
                self.assertTrue(log_data[0].startswith('[ffpuppet] Launch command:'))
                self.assertTrue(log_data[-1].startswith('[ffpuppet] Reason code:'))
            elif fname.startswith("log_stdout"):
                self.assertEqual(log_data[0], "hello world")
            elif fname.startswith(ffp._logs.META_FILE):
                continue  # ignore
            else:
                raise AssertionError("Unknown log file %r" % fname)

    def test_05(self):
        "test get_pid()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.get_pid())
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        self.assertGreater(ffp.get_pid(), 0)
        ffp.close()
        self.assertIsNone(ffp.get_pid())

    def test_06(self):
        "test is_running()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertFalse(ffp.is_running())
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        self.assertTrue(ffp.is_running())
        ffp.close()
        self.assertFalse(ffp.is_running())
        self.assertFalse(ffp.is_running())  # call 2x

    def test_07(self):
        "test wait()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.wait())
        with open(self.tmpfn, "w") as prefs:
            prefs.write("//fftest_exit_code_0\n")
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr(), prefs_js=self.tmpfn)
        self.assertIsNotNone(ffp.wait(timeout=10))
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_EXITED)
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        self.assertTrue(ffp.is_running())
        self.assertIsNone(ffp.wait(timeout=0))
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_CLOSED)

    def test_08(self):
        "test clone_log()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.clone_log("stdout", target_file=self.tmpfn))
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        ffp.wait(timeout=0.25)  # wait for log prints
        # make sure logs are available
        self.assertEqual(ffp.clone_log("stdout", target_file=self.tmpfn), self.tmpfn)
        with open(self.tmpfn, "rb") as tmpfp:
            orig = tmpfp.read()
        self.assertGreater(len(orig), 5)
        self.assertEqual(ffp.clone_log("stdout", target_file=self.tmpfn, offset=5), self.tmpfn)
        with open(self.tmpfn, "rb") as tmpfp:
            self.assertEqual(tmpfp.read(), orig[5:])
        # grab log without giving a target file name
        rnd_log = ffp.clone_log("stdout")
        self.assertIsNotNone(rnd_log)
        try:
            ffp.close()
            # make sure logs are available
            self.assertEqual(ffp.clone_log("stdout", target_file=self.tmpfn), self.tmpfn)
            with open(self.tmpfn, "rb") as tmpfp:
                self.assertTrue(tmpfp.read().startswith(orig))
        finally:
            if os.path.isfile(rnd_log):
                os.remove(rnd_log)
        # verify clean_up() removed the logs
        ffp.clean_up()
        self.assertIsNone(ffp.clone_log("stdout", target_file=self.tmpfn))

    def test_09(self):
        "test hitting memory limit"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_memory\n')
        # launch with 1MB memory limit
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr(), prefs_js=self.tmpfn, memory_limit=0x100000)
        for _ in range(100):
            if not ffp.is_healthy():
                break
            time.sleep(0.1)
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_WORKER)
        self.assertEqual(len(ffp.available_logs()), 3)
        ffp.save_logs(self.logs)
        worker_log = os.path.join(self.logs, "log_ffp_worker_memory_usage.txt")
        self.assertTrue(os.path.isfile(worker_log))
        with open(worker_log, "rb") as log_fp:
            self.assertIn(b"MEMORY_LIMIT_EXCEEDED", log_fp.read())

    def test_10(self):
        "test calling launch() multiple times"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        for _ in range(10):
            ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
            ffp.close()
        # call 2x without calling close()
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        with self.assertRaisesRegex(LaunchError, "Process is already running"):
            ffp.launch(TESTFF_BIN)
        self.assertEqual(ffp.launches, 11)
        ffp.close()

    def test_11(self):
        "test abort tokens"
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_soft_assert\n')
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.add_abort_token(r"TEST\dREGEX\.+")
        ffp.add_abort_token("simple_string")
        with self.assertRaises(AssertionError):
            ffp.add_abort_token(None)
        ffp.add_abort_token(r"ASSERTION:\s\w+")
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr(), prefs_js=self.tmpfn)
        for _ in range(200):
            if not ffp.is_healthy():
                break
            time.sleep(0.05)
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_WORKER)
        self.assertEqual(len(ffp.available_logs()), 3)
        ffp.save_logs(self.logs)
        worker_log = os.path.join(self.logs, "log_ffp_worker_log_contents.txt")
        self.assertTrue(os.path.isfile(worker_log))
        with open(worker_log, "rb") as log_fp:
            self.assertIn(b"TOKEN_LOCATED: ASSERTION: test", log_fp.read())

    def test_12(self):
        "test using an existing profile directory"
        prf_dir = tempfile.mkdtemp(prefix="ffp_test_prof_")
        self.addCleanup(shutil.rmtree, prf_dir)
        ffp = FFPuppet(use_profile=prf_dir)
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN)
        ffp.clean_up()
        self.assertTrue(os.path.isdir(prf_dir))

    def test_13(self):
        "test calling close() and clean_up() in multiple states"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.close()
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        self.assertIsNone(ffp.reason)
        ffp.close()
        ffp.clean_up()
        with self.assertRaises(AssertionError):
            ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        with self.assertRaises(AssertionError):
            ffp.close()

    def test_14(self):
        "test launching under Xvfb"
        if not PLAT.startswith("linux"):
            with self.assertRaisesRegex(EnvironmentError, "Xvfb is only supported on Linux"):
                ffp = FFPuppet(use_xvfb=True)
        else:
            ffp = FFPuppet(use_xvfb=True)
            self.addCleanup(ffp.clean_up)

    def test_15(self):
        "test passing a file and a non existing file to launch() via location"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with self.assertRaisesRegex(IOError, "Cannot find"):
            ffp.launch(TESTFF_BIN, location="fake_file.none")
        ffp.close()
        with open(self.tmpfn, "w") as prefs:
            prefs.write("//fftest_exit_code_0\n")
        tmpfd, test_file = tempfile.mkstemp()
        os.close(tmpfd)
        self.addCleanup(os.remove, test_file)
        with open(test_file, "w") as test_fp:
            test_fp.write("test")
        # needs realpath() for OSX & normcase() for Windows
        fname = os.path.normcase(os.path.realpath(test_file))
        ffp.launch(TESTFF_BIN, location=fname, prefs_js=self.tmpfn)
        ffp.wait(timeout=10)
        ffp.close()
        ffp.save_logs(self.logs)
        with open(os.path.join(self.logs, "log_stdout.txt"), "r") as log_fp:
            self.assertIn("url: 'file:///", log_fp.read())
            log_fp.seek(0)
            for line in log_fp:
                if "file:///" in line:
                    location = os.path.normcase(line.split("'")[1].split("file:///")[1])
                    break
            else:
                assert False, "Could not parse location"
        self.assertFalse(location.startswith("/"))
        self.assertEqual(os.path.normpath(os.path.join("/", location)), fname)

    def test_16(self):
        "test passing nonexistent file to launch() via prefs_js"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with self.assertRaisesRegex(IOError, "prefs.js file does not exist"):
            ffp.launch(TESTFF_BIN, prefs_js="fake_file.js")

    def test_17(self):
        "test launching with gdb"
        if not PLAT.startswith("linux"):
            with self.assertRaisesRegex(EnvironmentError, "GDB is only supported on Linux"):
                FFPuppet(use_gdb=True)
            return
        try:
            subprocess.check_call(["which", "gdb"])
        except subprocess.CalledProcessError:
            raise unittest.SkipTest("GDB is not installed")
        ffp = FFPuppet(use_gdb=True)
        self.addCleanup(ffp.clean_up)
        bin_path = str(subprocess.check_output(["which", "echo"]).strip().decode("ascii"))
        # launch will fail b/c 'echo' will exit right away but that's fine
        with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
            self.assertEqual(ffp.launch(bin_path), 0)
        ffp.close()
        ffp.save_logs(self.logs)
        with open(os.path.join(self.logs, "log_stdout.txt"), "rb") as log_fp:
            log_data = log_fp.read()
        # verify GDB ran and executed the script
        self.assertRegex(log_data, br"[Inferior \d+ (process \d+) exited with code \d+]")
        self.assertRegex(log_data, br"\+quit_with_code")

    def test_18(self):
        "test calling save_logs() before close()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        with self.assertRaises(AssertionError):
            ffp.save_logs(self.logs)

    def test_19(self):
        "test launching with Valgrind"
        if not PLAT.startswith("linux"):
            with self.assertRaisesRegex(EnvironmentError, "Valgrind is only supported on Linux"):
                FFPuppet(use_valgrind=True)
            return
        try:
            subprocess.check_call(["which", "valgrind"])
        except subprocess.CalledProcessError:
            raise unittest.SkipTest("Valgrind is not installed")
        vmv = FFPuppet.VALGRIND_MIN_VERSION
        try:
            FFPuppet.VALGRIND_MIN_VERSION = 9999999999.99
            with self.assertRaisesRegex(EnvironmentError, r"Valgrind >= \d+\.\d+ is required"):
                ffp = FFPuppet(use_valgrind=True)
            FFPuppet.VALGRIND_MIN_VERSION = 0
            ffp = FFPuppet(use_valgrind=True)
            self.addCleanup(ffp.clean_up)
            bin_path = str(subprocess.check_output(["which", "echo"]).strip().decode("ascii"))
            # launch will fail b/c 'echo' will exit right away but that's fine
            with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
                self.assertEqual(ffp.launch(bin_path), 0)
            ffp.close()
            ffp.save_logs(self.logs)
            with open(os.path.join(self.logs, "log_stderr.txt"), "rb") as log_fp:
                log_data = log_fp.read()
            # verify Valgrind ran and executed the script
            self.assertIn(b"valgrind -q", log_data)
            self.assertIn(b"[ffpuppet] Reason code: EXITED", log_data)
        finally:
            FFPuppet.VALGRIND_MIN_VERSION = vmv

    def test_20(self):
        "test detecting invalid prefs file"
        with open(self.tmpfn, 'w') as prefs_fp:
            prefs_fp.write('//fftest_invalid_js\n')
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with self.assertRaisesRegex(LaunchError, "'.+?' is invalid"):
            ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr(), prefs_js=self.tmpfn)

    def test_21(self):
        "test log_length()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.log_length("INVALID"))
        self.assertIsNone(ffp.log_length("stderr"))
        ffp.launch(TESTFF_BIN)
        self.assertGreater(ffp.log_length("stderr"), 0)
        ffp.close()
        self.assertGreater(ffp.log_length("stderr"), 0)
        ffp.clean_up()
        # verify clean_up() removed the logs
        self.assertIsNone(ffp.log_length("stderr"))

    def test_22(self):
        "test running multiple instances in parallel"
        ffps = list()
        # use test pool size of 10
        for _ in range(10):
            ffps.append(FFPuppet())
            self.addCleanup(ffps[-1].clean_up)
            # NOTE: launching truly in parallel can DoS the test webserver
            ffps[-1].launch(TESTFF_BIN, location=self.tsrv.get_addr())
        # list of ffps needs to be reversed to deal with inheriting open file handles in Popen
        # this is not a problem in production only in the test environment
        for ffp in reversed(ffps):
            self.assertEqual(ffp.launches, 1)
            ffp.close()

    def test_23(self):
        "test hitting log size limit"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_big_log\n')
        limit = 0x100000 # 1MB
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, log_limit=limit)
        for _ in range(100):
            if not ffp.is_healthy():
                break
            time.sleep(0.1)
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_WORKER)
        ffp.save_logs(self.logs)
        total_size = 0
        for fname in os.listdir(self.logs):
            self.assertIn(fname, ["log_ffp_worker_log_size.txt", "log_stderr.txt", "log_stdout.txt"])
            total_size += os.stat(os.path.join(self.logs, fname)).st_size
        self.assertLess(limit, total_size)
        with open(os.path.join(self.logs, "log_ffp_worker_log_size.txt"), "r") as log_fp:
            self.assertIn("LOG_SIZE_LIMIT_EXCEEDED", log_fp.read())

    def test_24(self):
        "test collecting and cleaning up ASan logs"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN)
        test_logs = list()
        asan_prefix = os.path.join(ffp._logs.working_path, ffp._logs.PREFIX_SAN)
        for i in range(3):
            test_logs.append(".".join([asan_prefix, str(i)]))
        # small log with nothing interesting
        with open(test_logs[0], "w") as log_fp:
            log_fp.write("SHORT LOG\n")
            log_fp.write("filler line")
        # crash on another thread
        with open(test_logs[1], "w") as log_fp:
            log_fp.write("GOOD LOG\n")
            log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x00000BADF00D")
            log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T0)\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        # child log that should be ignored (created when parent crashes)
        with open(test_logs[2], "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000")
            log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T2)\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        self.assertFalse(ffp.is_healthy())
        self.assertTrue(ffp.is_running())
        ffp.close()
        ffp.save_logs(self.logs)
        dir_list = os.listdir(self.logs)
        self.assertEqual(len(dir_list), 5)
        for fname in dir_list:
            if not fname.startswith("log_ffp_asan_"):
                self.assertIn(fname, ["log_stderr.txt", "log_stdout.txt"])
                continue
            with open(os.path.join(self.logs, fname), "r") as log_fp:
                self.assertIn(log_fp.readline(), ["BAD LOG\n", "GOOD LOG\n", "SHORT LOG\n"])
        ffp.clean_up()
        self.assertFalse(any(os.path.isfile(f) for f in test_logs))

    def test_25(self):
        "test multiple minidumps"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN)
        md_dir = os.path.join(ffp.profile, "minidumps")
        if not os.path.isdir(md_dir):
            os.mkdir(md_dir)
        ffp._last_bin_path = ffp.profile
        sym_dir = os.path.join(ffp.profile, "symbols") # needs to exist to satisfy a check
        if not os.path.isdir(sym_dir):
            os.mkdir(sym_dir)
        # create "test.dmp" files
        with open(os.path.join(md_dir, "test1.dmp"), "w") as out_fp:
            out_fp.write("1a\n1b")
        with open(os.path.join(md_dir, "test2.dmp"), "w") as out_fp:
            out_fp.write("2a\n2b")
        with open(os.path.join(md_dir, "test3.dmp"), "w") as out_fp:
            out_fp.write("3a\n3b")
        self.assertFalse(ffp.is_healthy())
        # process .dmp file
        ffp.close()
        ffp.save_logs(self.logs)
        logs = os.listdir(self.logs)
        self.assertIn("log_minidump_01.txt", logs)
        self.assertIn("log_minidump_02.txt", logs)
        self.assertIn("log_minidump_03.txt", logs)

    def test_26(self):
        "test multiprocess target"
        with open(self.tmpfn, "w") as prefs_fp:
            prefs_fp.write("//fftest_multi_proc\n")
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, location=self.tsrv.get_addr())
        self.assertTrue(ffp.is_running())
        self.assertIsNone(ffp.wait(timeout=0))
        c_procs = Process(ffp.get_pid()).children()
        self.assertGreater(len(c_procs), 0)
        # terminate one of the child processes
        c_procs[-1].terminate()
        self.assertTrue(ffp.is_running())
        ffp.close()
        self.assertFalse(ffp.is_running())
        self.assertIsNone(ffp.wait(timeout=0))

    def test_27(self):
        "test multiprocess (target terminated)"
        with open(self.tmpfn, "w") as prefs_fp:
            prefs_fp.write("//fftest_multi_proc\n")
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, location=self.tsrv.get_addr())
        self.assertTrue(ffp.is_running())
        procs = get_processes(ffp.get_pid())
        # when running the browser the children exit if the parent disappears
        # since the first item in procs is the parent iterate over the list
        # calling terminate()
        for proc in procs:
            try:
                proc.terminate()
            except (AccessDenied, NoSuchProcess):
                pass
        self.assertFalse(wait_procs(procs, timeout=10)[1])
        ffp.close()
        self.assertFalse(ffp.is_running())
        self.assertIsNone(ffp.wait(timeout=0))

    def test_28(self):
        "test launching with rr"
        if not PLAT.startswith("linux"):
            with self.assertRaisesRegex(EnvironmentError, "rr is only supported on Linux"):
                FFPuppet(use_rr=True)
            return
        try:
            # TODO: this can hang if ptrace is blocked by seccomp  # pylint: disable=fixme
            proc = subprocess.Popen(["rr", "record", "echo"])
        except OSError:
            self.skipTest("rr not installed")
        assert proc.wait() == 0, "'rr record echo' returned %r" % (proc.returncode,)
        ffp = FFPuppet(use_rr=True)
        self.addCleanup(ffp.clean_up)
        rr_dir = tempfile.mkdtemp(prefix="test_ffp_rr")
        self.addCleanup(shutil.rmtree, rr_dir, onerror=onerror)
        bin_path = str(subprocess.check_output(["which", "echo"]).strip().decode("ascii"))
        # launch will fail b/c 'echo' will exit right away but that's fine
        with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
            ffp.launch(bin_path, env_mod={"_RR_TRACE_DIR": rr_dir})
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_EXITED)
        ffp.save_logs(self.logs)
        with open(os.path.join(self.logs, "log_stderr.txt"), "rb") as log_fp:
            log_data = log_fp.read()
        # verify rr ran and executed the script
        self.assertIn(b"rr record", log_data)
        self.assertIn(b"[ffpuppet] Reason code:", log_data)

    def test_29(self):
        "test rmtree error handler"
        # normal profile creation
        # - just create a puppet, write a readonly file in its profile, then call close()
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN)
        ro_file = os.path.join(ffp.profile, "read-only-test.txt")
        with open(ro_file, "w"):
            pass
        os.chmod(ro_file, stat.S_IREAD)
        ffp.close()
        self.assertFalse(os.path.isfile(ro_file))
        ffp.clean_up()

        # use template profile that contains a readonly file
        prf_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, prf_dir, onerror=onerror)
        ro_file = os.path.join(prf_dir, "read-only.txt")
        with open(ro_file, "w"):
            pass
        os.chmod(ro_file, stat.S_IREAD)
        ffp = FFPuppet(use_profile=prf_dir)
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN)
        working_prf = ffp.profile
        self.assertTrue(os.path.isdir(working_prf))
        ffp.close()
        self.assertFalse(os.path.isdir(working_prf))

    def test_30(self):
        "test using a readonly prefs.js and extension"
        prefs = os.path.join(self.logs, "prefs.js")
        with open(prefs, "w"):
            pass
        os.chmod(prefs, stat.S_IREAD)
        ext = os.path.join(self.logs, "ext.xpi")
        with open(ext, "w"):
            pass
        os.chmod(ext, stat.S_IREAD)
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN, extension=ext, prefs_js=prefs)
        working_prf = ffp.profile
        ffp.close()
        self.assertFalse(os.path.isdir(working_prf))

    def test_31(self):
        "test _crashreports()"
        class StubbedLaunch(FFPuppet):
            def __init__(self):
                super(StubbedLaunch, self).__init__()
                self._use_valgrind = True

            def launch(self):  # pylint: disable=arguments-differ
                self.profile = tempfile.mkdtemp(prefix="ffp_test_profile_")
                os.mkdir(os.path.join(self.profile, "minidumps"))

            def close(self, force_close=False):
                if os.path.isdir(self.profile):
                    shutil.rmtree(self.profile)
                self.profile = None

        ffp = StubbedLaunch()
        self.addCleanup(ffp.clean_up)
        ffp.launch()
        self.assertFalse(list(ffp._crashreports()))

        san_log = "%s.1" % ffp._logs.PREFIX_SAN
        vg1_log = "%s.1" % ffp._logs.PREFIX_VALGRIND
        vg2_log = "%s.2" % ffp._logs.PREFIX_VALGRIND
        with open(os.path.join(ffp._logs.working_path, san_log), "w") as ofp:
            ofp.write("test\n")
        with open(os.path.join(ffp._logs.working_path, vg1_log), "w") as ofp:
            ofp.write("test\n")
        with open(os.path.join(ffp._logs.working_path, vg2_log), "w") as ofp:
            pass
        with open(os.path.join(ffp._logs.working_path, "junk.log"), "w") as ofp:
            ofp.write("test\n")
        with open(os.path.join(ffp.profile, "minidumps", "test.dmp"), "w") as ofp:
            ofp.write("test\n")
        with open(os.path.join(ffp.profile, "minidumps", "test.junk"), "w") as ofp:
            pass

        self.assertEqual(len(list(ffp._crashreports())), 3)
        self.assertEqual(len(list(ffp._crashreports(skip_md=True))), 2)

    def test_32(self):
        "test build_launch_cmd()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        cmd = ffp.build_launch_cmd("bin_path", ["test"])
        self.assertEqual(len(cmd), 3)
        self.assertEqual(cmd[0], "bin_path")
        self.assertEqual(cmd[-1], "test")

        # GDB
        ffp._use_gdb = True
        cmd = ffp.build_launch_cmd("bin_path")
        self.assertGreater(len(cmd), 2)
        self.assertEqual(cmd[0], "gdb")
        ffp._use_gdb = False

        # RR
        ffp._use_rr = True
        cmd = ffp.build_launch_cmd("bin_path")
        self.assertGreater(len(cmd), 2)
        self.assertEqual(cmd[0], "rr")
        ffp._use_rr = False

        # Valgrind
        ffp._use_valgrind = True
        try:
            os.environ["VALGRIND_SUP_PATH"] = "blah"
            with self.assertRaises(IOError):
                ffp.build_launch_cmd("bin_path")
            os.environ["VALGRIND_SUP_PATH"] = self.tmpfn
            cmd = ffp.build_launch_cmd("bin_path")
            self.assertGreater(len(cmd), 2)
            self.assertEqual(cmd[0], "valgrind")
        finally:
            os.environ.pop("VALGRIND_SUP_PATH")
        ffp._use_valgrind = False
