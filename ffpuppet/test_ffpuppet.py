import errno
import logging
import os
import random
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

from ffpuppet import FFPuppet, LaunchError, main


logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")

CWD = os.path.realpath(os.path.dirname(__file__))
TESTFF_BIN = os.path.join(CWD, "testff", "testff.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testff.py")
TESTMDSW_BIN = os.path.join(CWD, "testmdsw", "testmdsw.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testmdsw.py")

FFPuppet.LOG_POLL_RATE = 0.01 # reduce this for testing
FFPuppet.MDSW_BIN = TESTMDSW_BIN
FFPuppet.MDSW_MAX_STACK = 8

class TestCase(unittest.TestCase):

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
                self._httpd = HTTPServer(('127.0.0.1', random.randint(0x800, 0xFFFF)), self._handler)
            except socket.error as soc_e: # pragma: no cover
                if soc_e.errno == errno.EADDRINUSE: # Address already in use
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
        if sys.platform.startswith('win') and not os.path.isfile(TESTFF_BIN):
            raise EnvironmentError("testff.exe is missing see testff.py for build instructions") # pragma: no cover

    def setUp(self):
        fd, self.tmpfn = tempfile.mkstemp(prefix="ffp_test_log_")
        os.close(fd)
        self.logs = tempfile.mkdtemp(prefix="ffp_test_log_")

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.unlink(self.tmpfn)
        if os.path.isdir(self.logs):
            shutil.rmtree(self.logs)

    if not sys.platform.startswith('win'):
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
        self.assertEqual(ffp.get_launch_count(), 0)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        self.assertEqual(len(ffp._workers), 0) # pylint: disable=protected-access
        self.assertEqual(ffp.get_launch_count(), 1)
        self.assertIsNone(ffp.wait(0))
        ffp.close()
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

    def test_03(self):
        "test hang on start"
        ffp = FFPuppet()
        default_timeout = ffp.LAUNCH_TIMEOUT_MIN
        try:
            ffp.LAUNCH_TIMEOUT_MIN = 1
            self.addCleanup(ffp.clean_up)
            with open(self.tmpfn, 'w') as prefs:
                prefs.write('//fftest_hang\n')
            start = time.time()
            with self.assertRaisesRegex(LaunchError, "Launching browser timed out"):
                ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, launch_timeout=1)
            duration = time.time() - start
            ffp.close()
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
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
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
                raise RuntimeError("Unknown log file %r" % fname)

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
        self.assertFalse(ffp.is_running())

    def test_07(self):
        "test wait()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.wait())
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        self.assertIsNone(ffp.wait(0))
        ffp._terminate() # pylint: disable=protected-access
        self.assertFalse(ffp.is_running())
        self.assertIsNotNone(ffp.wait())
        self.assertNotEqual(ffp.wait(), 0)
        ffp.close()
        ffp._terminate() # should not raise # pylint: disable=protected-access
        self.assertIsNone(ffp.wait(None))

    def test_08(self):
        "test clone_log()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.clone_log("stdout", target_file=self.tmpfn))
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
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
            ffp.clean_up()
        finally:
            if os.path.isfile(rnd_log):
                os.remove(rnd_log)
        # verify clean_up() removed the logs
        self.assertIsNone(ffp.clone_log("stdout", target_file=self.tmpfn))

    def test_09(self):
        "test hitting memory limit"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_memory\n')
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr(), prefs_js=self.tmpfn, memory_limit=0x100000) # 1MB
        self.assertIsNotNone(ffp.wait(60))
        ffp.close()
        ffp.save_logs(self.logs)
        with open(os.path.join(self.logs, "log_stderr.txt"), "rb") as log_fp:
            self.assertRegex(log_fp.read(), b"MEMORY_LIMIT_EXCEEDED")

    def test_10(self):
        "test calling launch() multiple times"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        for _ in range(10):
            ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
            ffp.close()
        # call 2x without calling launch
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        with self.assertRaisesRegex(LaunchError, "Process is already running"):
            ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
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
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr(), prefs_js=self.tmpfn)
        self.assertIsNotNone(ffp.wait(10))
        ffp.close()
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
            ffp.close()
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
        ffp.close()
        ffp.clean_up()
        ffp.close()

    def test_14(self):
        "test manually setting ASAN_SYMBOLIZER_PATH"
        os.environ["ASAN_SYMBOLIZER_PATH"] = "foo/bar"
        ffp = FFPuppet()
        env = ffp.get_environ("fake/bin/path")
        ffp.clean_up()
        os.environ.pop("ASAN_SYMBOLIZER_PATH", None)
        self.assertEqual(env["ASAN_SYMBOLIZER_PATH"], "foo/bar")

    def test_15(self):
        "test automatically using bundled llvm-symbolizer"
        test_bin = "llvm-symbolizer.exe" if sys.platform.startswith('win') else "llvm-symbolizer"
        test_dir = tempfile.mkdtemp()
        with open(os.path.join(test_dir, test_bin), "w") as log_fp:
            log_fp.write("test")
        ffp = FFPuppet()
        env = ffp.get_environ(os.path.join(test_dir, "fake_bin"))
        ffp.clean_up()
        shutil.rmtree(test_dir)
        self.assertIn("ASAN_SYMBOLIZER_PATH", env)
        self.assertEqual(env["ASAN_SYMBOLIZER_PATH"], os.path.join(test_dir, test_bin))

    def test_16(self):
        "test launching under Xvfb"
        ffp = None
        if not sys.platform.startswith("linux"):
            with self.assertRaisesRegex(EnvironmentError, "Xvfb is only supported on Linux"):
                ffp = FFPuppet(use_xvfb=True)
        else:
            ffp = FFPuppet(use_xvfb=True)
        if ffp is not None:
            ffp.clean_up()

    def test_17(self):
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

    def test_18(self):
        "test passing nonexistent file to launch() via prefs_js"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with self.assertRaisesRegex(IOError, "prefs.js file does not exist"):
            ffp.launch(TESTFF_BIN, prefs_js="fake_file.js")

    def test_19(self):
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

    def test_20(self):
        "test create_profile()"
        with self.assertRaisesRegex(IOError, "Cannot find template profile: 'fake_dir'"):
            FFPuppet.create_profile(template="fake_dir")

        with self.assertRaisesRegex(IOError, "prefs.js file does not exist: 'fake_prefs'"):
            FFPuppet.create_profile(prefs_js="fake_prefs")

        # try creating a profile from scratch, does nothing but create a directory to be populated
        prof = FFPuppet.create_profile()
        self.assertTrue(os.path.isdir(prof))
        contents = os.listdir(prof)
        shutil.rmtree(prof)
        self.assertEqual(len(contents), 0)

        # create dummy profile
        prf_dir = tempfile.mkdtemp(prefix="ffp_test_prof_")
        invalid_js = os.path.join(prf_dir, "Invalidprefs.js")
        with open(invalid_js, "w") as log_fp:
            log_fp.write("blah!")
        # try creating a profile from a template
        prof = FFPuppet.create_profile(prefs_js=self.tmpfn, template=prf_dir)
        shutil.rmtree(prf_dir)
        self.assertTrue(os.path.isdir(prof))
        contents = os.listdir(prof)
        shutil.rmtree(prof)
        self.assertIn("prefs.js", contents)
        self.assertIn("times.json", contents)
        self.assertNotIn("Invalidprefs.js", contents)

    def test_21(self):
        "test calling save_logs() before close()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        with self.assertRaisesRegex(RuntimeError, "Logs are still in use.+"):
            ffp.save_logs(self.logs)

    def test_22(self):
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

    def test_23(self):
        "test check_prefs()"
        with open(self.tmpfn, 'w') as prefs_fp: # browser prefs.js dummy
            prefs_fp.write('// comment line\n')
            prefs_fp.write('# comment line\n')
            prefs_fp.write(' \n\n')
            prefs_fp.write('user_pref("a.a", 0);\n')
            prefs_fp.write('user_pref("a.b", "test");\n')
            prefs_fp.write('user_pref("a.c", true);\n')
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertFalse(ffp.check_prefs(self.tmpfn)) # test with profile == None
        try:
            fd, custom_prefs = tempfile.mkstemp(prefix="ffp_test_log_")
            os.close(fd)
            with open(custom_prefs, 'w') as prefs_fp: # custom prefs.js
                prefs_fp.write('// comment line\n')
                prefs_fp.write('# comment line\n')
                prefs_fp.write('/* comment block.\n')
                prefs_fp.write('*\n')
                prefs_fp.write(' \n\n')
                prefs_fp.write('user_pref("a.a", 0); // test comment\n')
                prefs_fp.write('user_pref("a.c", true);\n')
            ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
            self.assertTrue(ffp.check_prefs(custom_prefs))
            # test detects missing prefs
            with open(custom_prefs, 'w') as prefs_fp: # custom prefs.js
                prefs_fp.write('user_pref("a.a", 0);\n')
                prefs_fp.write('user_pref("b.a", false);\n')
            self.assertFalse(ffp.check_prefs(custom_prefs))
        finally:
            os.remove(custom_prefs)

    def test_24(self):
        "test detecting invalid prefs file"
        with open(self.tmpfn, 'w') as prefs_fp:
            prefs_fp.write('//fftest_invalid_js\n')
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with self.assertRaisesRegex(LaunchError, "'.+?' is invalid"):
            ffp.launch(TESTFF_BIN, location=tsrv.get_addr(), prefs_js=self.tmpfn)

    def test_25(self):
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

    def test_26(self):
        "test parallel launches"
        # use soft_assert test mode because it hangs around for 5s
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_soft_assert\n')
        # use a dummy token to make ffp launch worker threads
        token = re.compile(r"DUMMY\dREGEX\.+")
        ffps = list()
        # use test pool size of 20
        for _ in range(20):
            ffps.append(FFPuppet())
            self.addCleanup(ffps[-1].clean_up)
            ffps[-1].add_abort_token(token)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        for ffp in ffps:
            ffp.launch(TESTFF_BIN, location=tsrv.get_addr(), prefs_js=self.tmpfn)
            self.assertTrue(ffp.is_running())
        for ffp in ffps:
            self.assertTrue(ffp.is_running())
            ffp.close()
            self.assertFalse(ffp.is_running())

    def test_27(self):
        "test hitting log size limit"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_big_log\n')
        limit = 0x100000 # 1MB
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr(), prefs_js=self.tmpfn, log_limit=limit)
        self.assertIsNotNone(ffp.wait(60))
        ffp.close()
        ffp.save_logs(self.logs)
        total_size = 0
        for fname in os.listdir(self.logs):
            self.assertIn(fname, ["log_stderr.txt", "log_stdout.txt"])
            total_size += os.stat(os.path.join(self.logs, fname)).st_size
        self.assertLess(limit, total_size)
        with open(os.path.join(self.logs, "log_stderr.txt"), "r") as log_fp:
            self.assertIn("LOG_SIZE_LIMIT_EXCEEDED", log_fp.read())

    def test_28(self):
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

    def test_29(self):
        "test minidump stack processing"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        # create "test.dmp" file
        out_dmp = [
            "OS|Linux|0.0.0 sys info...", "CPU|amd64|more info|8", "GPU|||", "Crash|SIGSEGV|0x7fff27aaeff8|0",
            "Module|firefox||firefox|a|0x1|0x1|1", "Module|firefox||firefox|a|0x1|0x2|1", "Module|firefox||firefox|a|0x1|0x3|1",
            "  ", "", "0|0|blah|foo|a/bar.c|123|0x0", "0|1|blat|foo|a/bar.c|223|0x0", "0|2|blas|foo|a/bar.c|423|0x0",
            "0|3|blas|foo|a/bar.c|423|0x0", "1|0|libpthread-2.23.so||||0xd360", "1|1|swrast_dri.so||||0x7237f3",
            "1|2|libplds4.so|_fini|||0x163", "2|0|swrast_dri.so||||0x723657", "2|1|libpthread-2.23.so||||0x76ba",
            "2|3|libc-2.23.so||||0x1073dd"]
        md_dir = os.path.join(ffp.profile, "minidumps")
        if not os.path.isdir(md_dir):
            os.mkdir(md_dir)
        ffp._last_bin_path = ffp.profile # pylint: disable=protected-access
        sym_dir = os.path.join(ffp.profile, "symbols") # needs to exist to satisfy a check
        if not os.path.isdir(sym_dir):
            os.mkdir(sym_dir)
        with open(os.path.join(md_dir, "test.dmp"), "w") as out_fp:
            out_fp.write("\n".join(out_dmp))
        # create a dummy file
        with open(os.path.join(md_dir, "not_a_dmp.txt"), "w") as out_fp:
            out_fp.write("this file should be ignored")
        # process .dmp file
        ffp.close()
        ffp.save_logs(self.logs)
        self.assertIn("log_minidump_01.txt", os.listdir(self.logs))
        with open(os.path.join(self.logs, "log_minidump_01.txt"), "r") as in_fp:
            md_lines = in_fp.read().splitlines()
        self.assertEqual(len(set(out_dmp) - set(md_lines)), 11)
        self.assertTrue(md_lines[-1].startswith("WARNING: Hit line output limit!"))
        md_lines.pop() # remove the limit msg
        self.assertEqual(len(md_lines), FFPuppet.MDSW_MAX_STACK)

    def test_30(self):
        "test poll_file()"
        def populate_file(filename, size, end_token, delay, abort):
            open(filename, "wb").close()
            while True:
                with open(filename, "ab") as out_fp:
                    out_fp.write(b"a")
                    out_fp.flush()
                if os.stat(filename).st_size >= size:
                    break
                if abort.is_set():
                    return
                time.sleep(delay)
            with open(filename, "ab") as out_fp:
                out_fp.write(end_token)
        abort_evt = threading.Event()
        e_token = b"EOF"
        # test with invalid file
        self.assertIsNone(FFPuppet.poll_file("invalid_file"))
        # wait for a file to finish being written
        t_size = 10
        w_thread = threading.Thread(
            target=populate_file,
            args=(self.tmpfn, t_size, e_token, 0.1, abort_evt))
        w_thread.start()
        try:
            FFPuppet.poll_file(self.tmpfn)
        finally:
            abort_evt.set()
            w_thread.join()
            abort_evt.clear()
        with open(self.tmpfn, "rb") as in_fp:
            data = in_fp.read()
        self.assertEqual(len(data), t_size + len(e_token))
        self.assertTrue(data.endswith(e_token))
        # timeout while waiting for a file to finish being written
        t_size = 100
        w_thread = threading.Thread(
            target=populate_file,
            args=(self.tmpfn, t_size, e_token, 0.05, abort_evt))
        w_thread.start()
        try:
            result = FFPuppet.poll_file(self.tmpfn, idle_wait=1.99, timeout=2)
        finally:
            abort_evt.set()
            w_thread.join()
            abort_evt.clear()
        with open(self.tmpfn, "rb") as in_fp:
            data = in_fp.read()
        self.assertIsNone(result)
        self.assertLess(len(data), t_size + len(e_token))
        self.assertFalse(data.endswith(e_token))

    def test_31(self):
        "test create_profile() extension support"

        # create a profile with a non-existent ext
        with self.assertRaisesRegex(RuntimeError, "Unknown extension: 'fake_ext'"):
            FFPuppet.create_profile(extension="fake_ext")

        # create a profile with an xpi ext
        with open("xpi-ext.xpi", "w"):
            pass
        self.addCleanup(os.unlink, "xpi-ext.xpi")
        prof = FFPuppet.create_profile(extension="xpi-ext.xpi")
        self.addCleanup(shutil.rmtree, prof)
        self.assertEqual(os.listdir(prof), ["extensions"])
        self.assertEqual(os.listdir(os.path.join(prof, "extensions")), ["xpi-ext.xpi"])

        # create a profile with an unknown ext
        os.mkdir("dummy_ext")
        self.addCleanup(os.rmdir, "dummy_ext")
        with self.assertRaisesRegex(RuntimeError, "Failed to find extension id in manifest: 'dummy_ext'"):
            FFPuppet.create_profile(extension="dummy_ext")

        # create a profile with a bad legacy ext
        os.mkdir("bad_legacy")
        self.addCleanup(shutil.rmtree, "bad_legacy")
        with open(os.path.join("bad_legacy", "install.rdf"), "w"):
            pass
        with self.assertRaisesRegex(RuntimeError, "Failed to find extension id in manifest: 'bad_legacy'"):
            FFPuppet.create_profile(extension="bad_legacy")

        # create a profile with a good legacy ext
        os.mkdir("good_legacy")
        self.addCleanup(shutil.rmtree, "good_legacy")
        with open(os.path.join("good_legacy", "install.rdf"), "w") as manifest:
            manifest.write("""<?xml version="1.0"?>
                              <RDF xmlns="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                                   xmlns:em="http://www.mozilla.org/2004/em-rdf#">
                                <Description about="urn:mozilla:install-manifest">
                                  <em:id>good-ext-id</em:id>
                                </Description>
                              </RDF>""")
        with open(os.path.join("good_legacy", "example.js"), "w"):
            pass
        prof = FFPuppet.create_profile(extension="good_legacy")
        self.addCleanup(shutil.rmtree, prof)
        self.assertEqual(os.listdir(prof), ["extensions"])
        self.assertEqual(os.listdir(os.path.join(prof, "extensions")), ["good-ext-id"])
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions", "good-ext-id"))),
                         {"install.rdf", "example.js"})

        # create a profile with a bad webext
        os.mkdir("bad_webext")
        self.addCleanup(shutil.rmtree, "bad_webext")
        with open(os.path.join("bad_webext", "manifest.json"), "w"):
            pass
        with self.assertRaisesRegex(RuntimeError, "Failed to find extension id in manifest: 'bad_webext'"):
            FFPuppet.create_profile(extension="bad_webext")

        # create a profile with a good webext
        os.mkdir("good_webext")
        self.addCleanup(shutil.rmtree, "good_webext")
        with open(os.path.join("good_webext", "manifest.json"), "w") as manifest:
            manifest.write("""{"applications": {"gecko": {"id": "good-webext-id"}}}""")
        with open(os.path.join("good_webext", "example.js"), "w"):
            pass
        prof = FFPuppet.create_profile(extension="good_webext")
        self.addCleanup(shutil.rmtree, prof)
        self.assertEqual(os.listdir(prof), ["extensions"])
        self.assertEqual(os.listdir(os.path.join(prof, "extensions")), ["good-webext-id"])
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions", "good-webext-id"))),
                         {"manifest.json", "example.js"})

        # create a profile with multiple extensions
        prof = FFPuppet.create_profile(extension=["good_webext", "good_legacy"])
        self.addCleanup(shutil.rmtree, prof)
        self.assertEqual(os.listdir(prof), ["extensions"])
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions"))), {"good-ext-id", "good-webext-id"})
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions", "good-webext-id"))),
                         {"manifest.json", "example.js"})
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions", "good-ext-id"))),
                         {"install.rdf", "example.js"})

    def test_32(self):
        "test empty minidump log"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        md_dir = os.path.join(ffp.profile, "minidumps")
        if not os.path.isdir(md_dir):
            os.mkdir(md_dir)
        ffp._last_bin_path = ffp.profile # pylint: disable=protected-access
        sym_dir = os.path.join(ffp.profile, "symbols") # needs to exist to satisfy a check
        if not os.path.isdir(sym_dir):
            os.mkdir(sym_dir)
        # create empty "test.dmp" file
        with open(os.path.join(md_dir, "test.dmp"), "w") as _:
            pass
        # process .dmp file
        ffp.close()
        ffp.save_logs(self.logs)
        self.assertIn("log_minidump_01.txt", os.listdir(self.logs))
        with open(os.path.join(self.logs, "log_minidump_01.txt"), "r") as in_fp:
            md_lines = in_fp.read()
        self.assertTrue(md_lines.startswith("WARNING: minidump_stackwalk log was empty"))
        self.assertEqual(len(md_lines.splitlines()), 1)

    def test_33(self):
        "test multiple minidumps"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
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


    def test_34(self):
        "test minidump register processing"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        # create "test.dmp" file
        out_dmp = [
            "Crash reason:  SIGSEGV", "Crash address: 0x0", "Process uptime: not available", "",
            "Thread 0 (crashed)", " 0  libxul.so + 0x123456788",
            "    rax = 0xe5423423423fffe8   rdx = 0x0000000000000000",
            "    rcx = 0x0000000000000000   rbx = 0xe54234234233e5e5",
            "    rsi = 0x0000000000000000   rdi = 0x00007fedc31fe308",
            "    rbp = 0x00007fffca0dab00   rsp = 0x00007fffca0daad0",
            "     r8 = 0x0000000000000000    r9 = 0x0000000000000008",
            "    r10 = 0xffff00ffffffffff   r11 = 0xffffff00ffffffff",
            "    r12 = 0x0000743564566308   r13 = 0x00007fedce9d8000",
            "    r14 = 0x0000000000000001   r15 = 0x0000000000000000", "    rip = 0x0000745666666ac",
            "    Found by: given as instruction pointer in context", " 1  libxul.so + 0x1f4361c]", ""]
        md_dir = os.path.join(ffp.profile, "minidumps")
        if not os.path.isdir(md_dir):
            os.mkdir(md_dir)
        ffp._last_bin_path = ffp.profile # pylint: disable=protected-access
        sym_dir = os.path.join(ffp.profile, "symbols") # needs to exist to satisfy a check
        if not os.path.isdir(sym_dir):
            os.mkdir(sym_dir)
        with open(os.path.join(md_dir, "test.dmp"), "w") as out_fp:
            out_fp.write("\n".join(out_dmp))
        # process .dmp file
        ffp.close()
        ffp.save_logs(self.logs)
        self.assertIn("log_minidump_01.txt", os.listdir(self.logs))
        with open(os.path.join(self.logs, "log_minidump_01.txt"), "r") as in_fp:
            md_lines = list()
            for line in in_fp:
                if "=" not in line:
                    break
                md_lines.append(line)
        self.assertEqual(len(md_lines), 9) # only register info should be in here


class ScriptTests(TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform.startswith('win') and not os.path.isfile(TESTFF_BIN):
            raise EnvironmentError("testff.exe is missing see testff.py for build instructions") # pragma: no cover

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
