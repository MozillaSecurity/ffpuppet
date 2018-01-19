import errno
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
try: # py 2-3 compatibility
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler # pylint: disable=import-error
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler # pylint: disable=import-error

from psutil import Process

from ffpuppet import FFPuppet, LaunchError
from .minidump_parser import MinidumpParser

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")

CWD = os.path.realpath(os.path.dirname(__file__))
TESTFF_BIN = os.path.join(CWD, "testff", "testff.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testff.py")
TESTMDSW_BIN = os.path.join(CWD, "testmdsw", "testmdsw.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testmdsw.py")

FFPuppet.LOG_POLL_RATE = 0.01
FFPuppet.LOG_POLL_WAIT = 0.1
MinidumpParser.MDSW_BIN = TESTMDSW_BIN
MinidumpParser.MDSW_MAX_STACK = 8

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
            except socket.error as soc_e: # pragma: no cover
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


class PuppetTests(TestCase): # pylint: disable=too-many-public-methods
    @classmethod
    def setUpClass(cls):
        cls.tsrv = HTTPTestServer()

    @classmethod
    def tearDownClass(cls):
        cls.tsrv.shutdown()

    def setUp(self):
        fd, self.tmpfn = tempfile.mkstemp(prefix="ffp_test_log_")
        os.close(fd)
        self.logs = tempfile.mkdtemp(prefix="ffp_test_log_")

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.unlink(self.tmpfn)
        if os.path.isdir(self.logs):
            shutil.rmtree(self.logs)

    @unittest.skipIf(sys.platform.startswith('win'), "Unsupported on Windows")
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
        self.assertEqual(ffp.returncode, 0)
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        self.assertEqual(len(ffp._workers), 0) # pylint: disable=protected-access
        self.assertEqual(ffp.launches, 1)
        self.assertIsNone(ffp.wait(0))
        self.assertTrue(ffp.is_running())
        self.assertIsNone(ffp.reason)
        self.assertIsNone(ffp.returncode)
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_CLOSED)
        self.assertIsNotNone(ffp.returncode)
        self.assertIsNone(ffp._proc) # pylint: disable=protected-access
        self.assertFalse(ffp.is_running())
        self.assertIsNone(ffp.wait(10))

    def test_02(self):
        "test crash on start"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_startup_crash\n')
        with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
            ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
        self.assertEqual(ffp.wait(10), 1) # test crash returns 1
        ffp.close()
        self.assertEqual(ffp.launches, 0)
        self.assertEqual(ffp.reason, ffp.RC_EXITED)
        self.assertEqual(ffp.returncode, 1)

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
            with self.assertRaisesRegex(LaunchError, "Launching browser timed out"):
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
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        ffp.wait(0.25) # wait for log prints
        ffp.close()
        self.assertTrue(ffp._logs.closed) # pylint: disable=protected-access
        log_ids = ffp.available_logs()
        self.assertEqual(len(log_ids), 2)
        self.assertIn("stderr", log_ids)
        self.assertIn("stdout", log_ids)
        log_dir = os.path.join(self.logs, "some_dir") # nonexistent directory
        ffp.save_logs(log_dir)
        self.assertTrue(os.path.isdir(log_dir))
        dir_list = os.listdir(log_dir)
        self.assertIn("log_stderr.txt", dir_list)
        self.assertIn("log_stdout.txt", dir_list)
        with open(os.path.join(log_dir, "log_stdout.txt"), "r") as log_fp:
            self.assertIn("url: http://", log_fp.read().strip())
        for fname in os.listdir(log_dir):
            with open(os.path.join(log_dir, fname)) as log_fp:
                log_data = log_fp.read().splitlines()
            if fname.startswith("log_stderr"):
                self.assertEqual(len(log_data), 3)
                self.assertTrue(log_data[0].startswith('[ffpuppet] Launch command:'))
                self.assertTrue(log_data[-1].startswith('[ffpuppet] Exit code:')) # exit code differs between platforms
            elif fname.startswith("log_stdout"):
                self.assertEqual(log_data[0], "hello world")
            else:
                raise AssertionError("Unknown log file %r" % fname)

    def test_05(self):
        "test get_pid()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.get_pid())
        ffp.launch(TESTFF_BIN)
        self.assertGreater(ffp.get_pid(), 0)
        ffp.close()
        self.assertIsNone(ffp.get_pid())

    def test_06(self):
        "test is_running()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertFalse(ffp.is_running())
        ffp.launch(TESTFF_BIN)
        self.assertTrue(ffp.is_running())
        ffp.close()
        self.assertFalse(ffp.is_running())
        self.assertFalse(ffp.is_running())  # call 2x

    def test_07(self):
        "test wait()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        # call when ffp._proc is None
        self.assertIsNone(ffp.wait())
        ffp.launch(TESTFF_BIN)
        # call when ffp._proc is running
        self.assertTrue(ffp.is_running())
        self.assertIsNone(ffp.wait(0))
        ffp._terminate()  # pylint: disable=protected-access
        # call when ffp._proc is not running
        self.assertFalse(ffp.is_running())
        self.assertIsNotNone(ffp.wait(0))  # with a timeout of zero
        self.assertIsNotNone(ffp.wait())  # without a timeout
        ffp.close()
        self.assertIsNotNone(ffp.returncode)
        with self.assertRaisesRegex(AssertionError, ""):
            ffp._terminate()  # pylint: disable=protected-access
        self.assertIsNone(ffp.wait(None))

    def test_08(self):
        "test clone_log()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.clone_log("stdout", target_file=self.tmpfn))
        ffp.launch(TESTFF_BIN, location=self.tsrv.get_addr())
        ffp.wait(0.25) # wait for log prints
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
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, memory_limit=0x100000) # 1MB
        self.assertIsNotNone(ffp.wait(30))
        ffp.close()
        self.assertIsNotNone(ffp.returncode)
        self.assertEqual(ffp.reason, ffp.RC_WORKER)
        ffp.save_logs(self.logs)
        with open(os.path.join(self.logs, "log_stderr.txt"), "rb") as log_fp:
            self.assertRegex(log_fp.read(), b"MEMORY_LIMIT_EXCEEDED")

    def test_10(self):
        "test calling launch() multiple times"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        for _ in range(10):
            ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
            ffp.close()
        # call 2x without calling close()
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
        with self.assertRaisesRegex(LaunchError, "Process is already running"):
            ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
        ffp.close()

    def test_11(self):
        "test abort tokens"
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_soft_assert\n')
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.add_abort_token(re.compile(r"TEST\dREGEX\.+"))
        with self.assertRaisesRegex(TypeError, "Expecting 'str' or 're._pattern_type' got: 'NoneType'"):
            ffp.add_abort_token(None)
        ffp.add_abort_token("###!!! ASSERTION:")
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
        self.assertIsNotNone(ffp.wait(10))
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_WORKER)
        self.assertIsNotNone(ffp.returncode)
        ffp.save_logs(self.logs)
        with open(os.path.join(self.logs, "log_stderr.txt"), "r") as log_fp:
            self.assertIn("TOKEN_LOCATED", log_fp.read())

    def test_12(self):
        "test using an existing profile directory"
        prf_dir = tempfile.mkdtemp(prefix="ffp_test_prof_")
        ffp = FFPuppet(use_profile=prf_dir)
        self.addCleanup(ffp.clean_up)
        try:
            ffp.launch(TESTFF_BIN)
            ffp.clean_up()
            self.assertTrue(os.path.isdir(prf_dir))
        finally:
            shutil.rmtree(prf_dir)

    def test_13(self):
        "test calling close() and clean_up() in multiple states"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.close()
        ffp.launch(TESTFF_BIN)
        self.assertIsNone(ffp.reason)
        ffp.close()
        ffp.clean_up()
        ffp.close()

    def test_14(self):
        "test launching under Xvfb"
        if not sys.platform.startswith("linux"):
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
        with tempfile.NamedTemporaryFile() as test_fp:
            test_fp.write(b"test")
            test_fp.seek(0)
            # needs realpath() for OSX & normcase() for Windows
            fname = os.path.realpath(os.path.normcase(test_fp.name))
            ffp.launch(TESTFF_BIN, location=fname)
            ffp.wait(0.25) # wait for log prints
            ffp.close()
            ffp.save_logs(self.logs)
        with open(os.path.join(self.logs, "log_stdout.txt"), "r") as log_fp:
            location = log_fp.read().strip()
        self.assertIn("url: file:///", location)
        location = os.path.normcase(location.split("file:///")[-1])
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
        if not sys.platform.startswith("linux"):
            with self.assertRaisesRegex(EnvironmentError, "GDB is only supported on Linux"):
                FFPuppet(use_gdb=True)
        else:
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
        with self.assertRaisesRegex(RuntimeError, "Logs are still in use.+"):
            ffp.save_logs(self.logs)

    def test_19(self):
        "test launching with Valgrind"
        if not sys.platform.startswith("linux"):
            with self.assertRaisesRegex(EnvironmentError, "Valgrind is only supported on Linux"):
                FFPuppet(use_valgrind=True)
        else:
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
            self.assertRegex(log_data, br"valgrind -q")
            self.assertRegex(log_data, br"\[ffpuppet\] Exit code: 0")

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
        "test parallel launches"
        ffps = list()
        launch_threads = list()
        # use test pool size of 20
        for _ in range(20):
            ffps.append(FFPuppet())
            self.addCleanup(ffps[-1].clean_up)
            launch_threads.append(threading.Thread(target=ffps[-1].launch, args=(TESTFF_BIN,)))
            launch_threads[-1].start()
        for lthread in launch_threads:
            lthread.join()
        for ffp in ffps:
            self.assertTrue(ffp.is_running())
            ffp.close()
            self.assertFalse(ffp.is_running())

    def test_23(self):
        "test hitting log size limit"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_big_log\n')
        limit = 0x100000 # 1MB
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, log_limit=limit)
        self.assertIsNotNone(ffp.wait(10))
        self.assertIsNotNone(ffp.returncode)
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_WORKER)
        self.assertIsNotNone(ffp.returncode)
        ffp.save_logs(self.logs)
        total_size = 0
        for fname in os.listdir(self.logs):
            self.assertIn(fname, ["log_stderr.txt", "log_stdout.txt"])
            total_size += os.stat(os.path.join(self.logs, fname)).st_size
        self.assertLess(limit, total_size)
        with open(os.path.join(self.logs, "log_stderr.txt"), "r") as log_fp:
            self.assertIn("LOG_SIZE_LIMIT_EXCEEDED", log_fp.read())

    def test_24(self):
        "test collecting and cleaning up ASan logs"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN)
        test_logs = list()
        asan_prefix = os.path.join(ffp._logs.working_path, ffp._logs.LOG_ASAN_PREFIX) # pylint: disable=protected-access
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
        for t_log in test_logs:
            self.assertFalse(os.path.isfile(t_log))

    def test_25(self):
        "test multiple minidumps"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN)
        md_dir = os.path.join(ffp.profile, "minidumps")
        if not os.path.isdir(md_dir):
            os.mkdir(md_dir)
        ffp._last_bin_path = ffp.profile # pylint: disable=protected-access
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
        # process .dmp file
        ffp.close()
        ffp.save_logs(self.logs)
        logs = os.listdir(self.logs)
        self.assertIn("log_minidump_01.txt", logs)
        self.assertIn("log_minidump_02.txt", logs)
        self.assertIn("log_minidump_03.txt", logs)

    def test_26(self):
        "test exhausting bootstrap ports"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        init_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(init_soc.close)
        if sys.platform.startswith("win"):
            init_soc.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)  # pylint: disable=no-member
        init_soc.bind(("127.0.0.1", 0))  # bind to a random free port
        try:
            ffp.BS_PORT_MAX = init_soc.getsockname()[1]
            ffp.BS_PORT_MIN = ffp.BS_PORT_MAX
            with self.assertRaisesRegex(LaunchError, "Could not find available port"):
                ffp.launch(TESTFF_BIN, launch_timeout=5)
        finally:
            ffp.BS_PORT_MAX = 0xFFFF
            ffp.BS_PORT_MIN = 0x4000

    def test_27(self):
        "test multiprocess target"
        with open(self.tmpfn, "w") as prefs_fp:
            prefs_fp.write("//fftest_multi_proc\n")
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, location=self.tsrv.get_addr())
        self.assertTrue(ffp.is_running())
        self.assertIsNone(ffp.wait(0))
        c_procs = Process(ffp.get_pid()).children()
        self.assertGreater(len(c_procs), 0)
        # terminate one of the processes
        c_procs[-1].terminate()
        ffp.close()
        self.assertFalse(ffp.is_running())
        self.assertIsNone(ffp.wait(0))

    def test_28(self):
        "test returncode"
        with open(self.tmpfn, "w") as prefs_fp:
            prefs_fp.write("//fftest_exit_code_3\n")
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp = FFPuppet()
        self.assertEqual(ffp.returncode, 0)
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, location=self.tsrv.get_addr())
        ffp.wait(10)
        self.assertFalse(ffp.is_running())
        # verify private member is set when using returncode property
        self.assertIsNone(ffp._returncode)  # pylint: disable=protected-access
        self.assertEqual(ffp.returncode, 3)
        self.assertEqual(ffp._returncode, 3)  # pylint: disable=protected-access
        # verify private member is set when calling close()
        ffp._returncode = None  # pylint: disable=protected-access
        ffp.close()
        self.assertEqual(ffp.reason, ffp.RC_EXITED)
        self.assertEqual(ffp.returncode, 3)
