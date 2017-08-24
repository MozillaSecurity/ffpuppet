import errno
import logging
try: # py 2-3 compatibility
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
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

from ffpuppet import FFPuppet, LaunchError, main


logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")

CWD = os.path.realpath(os.path.dirname(__file__))
TESTFF_BIN = os.path.join(CWD, os.pardir, "testff", "testff.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testff.py")

FFPuppet.LOG_POLL_RATE = 0.01 # reduce this for testing

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


class PuppetTests(TestCase):

    @classmethod
    def setUpClass(cls):
        if sys.platform.startswith('win') and not os.path.isfile(os.path.join("testff", "testff.exe")):
            raise EnvironmentError("testff.exe is missing see testff.py for build instructions") # pragma: no cover

    def setUp(self):

        fd, self.tmpfn = tempfile.mkstemp()
        os.close(fd)

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.unlink(self.tmpfn)

    if not sys.platform.startswith('win'):
        def test_0(self):
            "test that invalid executables raise the right exception"
            ffp = FFPuppet()
            self.addCleanup(ffp.clean_up)
            with self.assertRaisesRegex(IOError, "is not an executable"):
                ffp.launch(self.tmpfn)

    def test_1(self):
        "test basic launch and close"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertEqual(ffp.get_launch_count(), 0)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        self.assertEqual(len(ffp._workers), 0)
        self.assertEqual(ffp.get_launch_count(), 1)
        self.assertIsNone(ffp.wait(0))
        ffp.close()
        self.assertIsNone(ffp._proc)
        self.assertFalse(ffp.is_running())
        self.assertIsNone(ffp.wait(10))

    def test_2(self):
        "test crash on start"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_startup_crash\n')
        with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
            ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
        self.assertEqual(ffp.wait(10), 1) # test crash returns 1
        ffp.close()
        ffp.save_log(self.tmpfn)

    def test_3(self):
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
            ffp.save_log(self.tmpfn)
            self.assertGreater(duration, ffp.LAUNCH_TIMEOUT_MIN)
            self.assertLess(duration, 30)
        finally:
            ffp.LAUNCH_TIMEOUT_MIN = default_timeout

    def test_4(self):
        "test logging"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        ffp.wait(0.25) # wait for log prints
        ffp.close()
        log_dir = tempfile.mkdtemp()
        log_file = os.path.join(log_dir, "some_dir", "test_log.txt") # nonexistent directory
        ffp.save_log(log_file)
        self.assertTrue(os.path.isfile(log_file))
        with open(log_file) as log_fp:
            out_log = log_fp.read().splitlines()
        self.assertEqual(len(out_log), 5)
        self.assertTrue(out_log[0].startswith('[ffpuppet] Launch command'))
        self.assertEqual(out_log[2:4], ["hello world", "[ffpuppet] Process was closed by ffpuppet"])
        self.assertTrue(out_log[-1].startswith('[ffpuppet] Exit code:')) # exit code differs between platforms
        log_file = "rel_test_path.txt" # save to cwd
        ffp.save_log(log_file)
        self.assertTrue(os.path.isfile(log_file))
        os.remove(log_file)
        if os.path.isdir(log_dir):
            shutil.rmtree(log_dir)
        self.assertIsNotNone(ffp._log.name)
        tmp_log_file = ffp._log.name
        self.assertTrue(os.path.isfile(tmp_log_file))
        ffp.clean_up()
        self.assertFalse(os.path.isfile(tmp_log_file))
        self.assertIsNone(ffp._log)

    def test_5(self):
        "test get_pid()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.get_pid())
        ffp.launch(TESTFF_BIN)
        self.assertGreater(ffp.get_pid(), 0)
        ffp.close()
        self.assertIsNone(ffp.get_pid())

    def test_6(self):
        "test is_running()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertFalse(ffp.is_running())
        ffp.launch(TESTFF_BIN)
        self.assertTrue(ffp.is_running())
        ffp.close()
        self.assertFalse(ffp.is_running())
        self.assertFalse(ffp.is_running())

    def test_7(self):
        "test wait()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.wait())
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        self.assertIsNone(ffp.wait(0))
        ffp._terminate()
        self.assertFalse(ffp.is_running())
        self.assertIsNotNone(ffp.wait())
        self.assertNotEqual(ffp.wait(), 0)
        ffp.close()
        ffp._terminate() # should not raise
        self.assertIsNone(ffp.wait(None))

    def test_8(self):
        "test clone_log()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        self.assertIsNone(ffp.clone_log(target_file=self.tmpfn))
        ffp.launch(TESTFF_BIN)
        # make sure logs are available
        self.assertEqual(ffp.clone_log(target_file=self.tmpfn), self.tmpfn)
        with open(self.tmpfn, "rb") as tmpfp:
            orig = tmpfp.read()
        self.assertEqual(ffp.clone_log(target_file=self.tmpfn, offset=10), self.tmpfn)
        self.assertGreater(len(orig), 10)
        with open(self.tmpfn, "rb") as tmpfp:
            self.assertEqual(tmpfp.read(), orig[10:])
        # grab log without giving a target file name
        rnd_log = ffp.clone_log()
        self.assertIsNotNone(rnd_log)
        ffp.close()
        # make sure logs are available
        self.assertEqual(ffp.clone_log(target_file=self.tmpfn), self.tmpfn)
        with open(self.tmpfn, "rb") as tmpfp:
            self.assertTrue(tmpfp.read().startswith(orig))
            self.assertGreater(tmpfp.tell(), len(orig))
        ffp.clean_up()
        if os.path.isfile(rnd_log):
            os.remove(rnd_log)
        # verify clean_up() removed the logs
        self.assertIsNone(ffp.clone_log(target_file=self.tmpfn))

    def test_9(self):
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
        ffp.save_log(self.tmpfn)
        with open(self.tmpfn, "rb") as fp:
            self.assertRegex(fp.read(), b"MEMORY_LIMIT_EXCEEDED")

    def test_10(self):
        "test calling launch() multiple times"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        prev_log = None
        for _ in range(10):
            ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
            if prev_log is not None:
                self.assertFalse(os.path.isfile(prev_log))
            prev_log = ffp._log.name
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
        ffp.save_log(self.tmpfn)
        with open(self.tmpfn, "rb") as fp:
            self.assertRegex(fp.read(), b"TOKEN_LOCATED")

    def test_12(self):
        "test using an existing profile directory"
        prf_dir = tempfile.mkdtemp()
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
        with open(os.path.join(test_dir, test_bin), "w") as fp:
            fp.write("test")
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
            ffp.launch(TESTFF_BIN, location=test_fp.name)

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
            bin_path = subprocess.check_output(["which", "echo"]).strip()
            if not isinstance(bin_path, str):
                bin_path = bin_path.decode() # python 3 compatibility
            # launch will fail b/c 'echo' will exit right away but that's fine
            with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
                self.assertEqual(ffp.launch(bin_path), 0)
            ffp.close()
            ffp.save_log(self.tmpfn)
            with open(self.tmpfn, "rb") as log_fp:
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

        # only the fuzzPriv ext is supported atm and support will be removed in the future
        with self.assertRaisesRegex(RuntimeError, "Unknown extension: 'fake_ext'"):
            FFPuppet.create_profile(extension="fake_ext")

        # try creating a profile from scratch, does nothing but create a directory to be populated
        prof = FFPuppet.create_profile()
        self.assertTrue(os.path.isdir(prof))
        contents = os.listdir(prof)
        shutil.rmtree(prof)
        self.assertEqual(len(contents), 0)

        # create dummy profile
        prf_dir = tempfile.mkdtemp()
        invalid_js = os.path.join(prf_dir, "Invalidprefs.js")
        with open(invalid_js, "w") as fp:
            fp.write("blah!")
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
        "test calling save_log() before close()"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        tsrv = HTTPTestServer()
        self.addCleanup(tsrv.shutdown)
        ffp.launch(TESTFF_BIN, location=tsrv.get_addr())
        with self.assertRaisesRegex(RuntimeError, "Log is still in use.+"):
            ffp.save_log(self.tmpfn)
        ffp.close()

    def test_22(self):
        "test launching with Valgrind"
        if not sys.platform.startswith("linux"):
            with self.assertRaisesRegex(EnvironmentError, "Valgrind is only supported on Linux"):
                FFPuppet(use_valgrind=True)
        else:
            ffp = FFPuppet(use_valgrind=True)
            self.addCleanup(ffp.clean_up)
            bin_path = subprocess.check_output(["which", "echo"]).strip()
            if not isinstance(bin_path, str):
                bin_path = bin_path.decode() # python 3 compatibility
            # launch will fail b/c 'echo' will exit right away but that's fine
            with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
                self.assertEqual(ffp.launch(bin_path), 0)
            ffp.close()
            ffp.save_log(self.tmpfn)
            with open(self.tmpfn, "rb") as log_fp:
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
        self.assertFalse(ffp.check_prefs(self.tmpfn)) # test with profile == None
        try:
            fd, custom_prefs = tempfile.mkstemp()
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
            ffp.clean_up()
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
        self.assertEqual(ffp.log_length(), 0)
        ffp.launch(TESTFF_BIN)
        self.assertGreater(ffp.log_length(), 0)
        ffp.close()
        self.assertGreater(ffp.log_length(), 0)
        ffp.clean_up()
        # verify clean_up() removed the logs
        self.assertEqual(ffp.log_length(), 0)

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
        "test collecting log data that is dumped after parent process is closed"
        FFPuppet.LOG_POLL_RATE = 0.2
        FFPuppet.LOG_CLOSE_TIMEOUT = 1
        try:
            ffp = FFPuppet()
            self.addCleanup(ffp.clean_up)
            ffp.launch(TESTFF_BIN)
            ffp._log.write("blah\n")
            def _spam_thread():
                while not ffp._log.closed:
                    ffp._log.write("blah\n")
                    time.sleep(0.1)
            spam_thread = threading.Thread(target=_spam_thread)
            try:
                spam_thread.start()
                ffp.close()
            finally:
                spam_thread.join()
            self.assertFalse(ffp.is_running())
            self.assertIsNone(ffp.wait())
            ffp.save_log(self.tmpfn)
            with open(self.tmpfn, "rb") as log_fp:
                self.assertIn(b"[ffpuppet] WARNING! Log may be incomplete!", log_fp.read())
        finally:
            FFPuppet.LOG_POLL_RATE = 0.001
            FFPuppet.LOG_CLOSE_TIMEOUT = 10

    def test_28(self):
        "test worker log clean up"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.add_abort_token("test_blah")
        ffp.launch(TESTFF_BIN)
        self.assertEqual(len(ffp._workers), 1)
        w_logs = list()
        for worker in ffp._workers:
            w_logs.append(worker._log)
            self.assertTrue(os.path.isfile(w_logs[-1]))
        ffp.close()
        self.assertEqual(len(ffp._workers), 0)
        self.assertEqual(len(w_logs), 1)
        for log in w_logs:
            self.assertFalse(os.path.isfile(log))

    def test_29(self):
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
        ffp.save_log(self.tmpfn)
        self.assertLess(limit, os.stat(self.tmpfn).st_size)
        with open(self.tmpfn, "rb") as fp:
            self.assertRegex(fp.read(), b"LOG_SIZE_LIMIT_EXCEEDED")

    def test_30(self):
        "test merging and cleaning up ASan logs"
        ffp = FFPuppet()
        self.addCleanup(ffp.clean_up)
        ffp.launch(TESTFF_BIN)
        asan_log_botton = ".".join([ffp._asan_log, str(random.randint(1000, 4000))]) # add a PID
        with open(asan_log_botton, "w") as fp:
            fp.write("BOTTOM LOG\n")
            fp.write("2 middle test line\n")
            fp.write("2 final line!")
        asan_log_top = ".".join([ffp._asan_log, str(random.randint(1000, 4000))]) # add a PID
        with open(asan_log_top, "w") as fp:
            fp.write("TOP LOG\n")
            for _ in range(6):
                fp.write("1 middle test line\n")
            fp.write("1 final line!")
        self.assertTrue(ffp.is_running())
        ffp.close()
        ffp.save_log(self.tmpfn)
        with open(self.tmpfn, "r") as fp:
            log_data = fp.read()
        self.assertIn("BOTTOM LOG\n", log_data)
        self.assertIn("TOP LOG\n", log_data)
        self.assertIn("1 final line!", log_data)
        self.assertIn("2 final line!", log_data)
        self.assertLess(log_data.find("TOP LOG"), log_data.find("BOTTOM LOG"))
        ffp.clean_up()
        self.assertFalse(os.path.isfile(asan_log_botton))
        self.assertFalse(os.path.isfile(asan_log_top))


class ScriptTests(TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform.startswith('win') and not os.path.isfile(os.path.join("testff", "testff.exe")):
            raise EnvironmentError("testff.exe is missing see testff.py for build instructions") # pragma: no cover

    def test_01(self):
        "test calling main with '-h'"
        with self.assertRaisesRegex(SystemExit, "0"):
            main(["-h"])

    def test_02(self):
        "test calling main with test binary/script"
        fd, out_log = tempfile.mkstemp()
        os.close(fd)
        os.remove(out_log)
        fd, prefs = tempfile.mkstemp()
        os.close(fd)
        with open(prefs, "w") as prefs_fp:
            prefs_fp.write("//fftest_exit_code_0\n")
        try:
            main([TESTFF_BIN, "-d", "-l", out_log, "-p", prefs])
            self.assertTrue(os.path.isfile(out_log))
        finally:
            if os.path.isfile(out_log):
                os.remove(out_log)
            if os.path.isfile(prefs):
                os.remove(prefs)

    def test_03(self):
        "test calling main with test binary/script"
        fd, prefs = tempfile.mkstemp()
        os.close(fd)
        with open(prefs, "w") as prefs_fp:
            prefs_fp.write("//fftest_big_log\n")
        try:
            main([TESTFF_BIN, "-v", "-d", "-p", prefs, "--log-limit", "1", "-a", "blah_test"])
        finally:
            if os.path.isfile(prefs):
                os.remove(prefs)
