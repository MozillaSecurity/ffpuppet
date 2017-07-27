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

from .ffpuppet import FFPuppet, LaunchError, main


logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")

TESTFF_BIN = os.path.join("testff", "testff.exe") if sys.platform.startswith('win') else "testff.py"

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


def create_server(handler):
    "returns a server object, call shutdown when done"
    while True:
        try:
            httpd = HTTPServer(('127.0.0.1', random.randint(0x800, 0xFFFF)), handler)
        except socket.error as soc_e:
            if soc_e.errno == errno.EADDRINUSE: # Address already in use
                continue
            raise
        break
    def _srv_thread():
        try:
            httpd.serve_forever()
        finally:
            httpd.socket.close()
    thread = threading.Thread(target=_srv_thread)
    thread.start()
    # XXX: join the thread on shutdown() .. somehow
    return httpd


class PuppetTests(TestCase):

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
            try:
                with self.assertRaisesRegex(IOError, "is not an executable"):
                    ffp.launch(self.tmpfn)
            finally:
                ffp.clean_up()

    def test_1(self):
        "test basic launch and close"
        ffp = FFPuppet()
        self.assertEqual(ffp.get_launch_count(), 0)
        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"test")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch(TESTFF_BIN, location=location)
            self.assertEqual(ffp.get_launch_count(), 1)
            self.assertEqual(ffp.wait(1), 0) # will close automatically
            ffp.close()
        finally:
            ffp.clean_up()
            httpd.shutdown()
        self.assertFalse(ffp.is_running())
        self.assertIsNone(ffp.wait())

    def test_2(self):
        "test crash on start"
        ffp = FFPuppet()
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_startup_crash\n')
        try:
            with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
                ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn)
            self.assertEqual(ffp.wait(1), 1) # test crash returns 1
            ffp.close()
            ffp.save_log(self.tmpfn)
        finally:
            ffp.clean_up()

    def test_3(self):
        "test hang on start"
        ffp = FFPuppet()
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_hang\n')
        try:
            start = time.time()
            with self.assertRaisesRegex(LaunchError, "Launching browser timed out"):
                ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, launch_timeout=1)
            duration = time.time() - start
            ffp.close()
            ffp.save_log(self.tmpfn)
        finally:
            ffp.clean_up()
        self.assertGreater(duration, 9) # min launch_timeout is 10
        self.assertLess(duration, 60)

    def test_4(self):
        "test logging"
        ffp = FFPuppet()

        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hello world")

        httpd = create_server(_req_handler)
        log_dir = tempfile.mkdtemp()
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch(TESTFF_BIN, location=location)
            ffp.wait()
            ffp.close()
            log_file = os.path.join(log_dir, "some_dir", "test_log.txt") # nonexistent directory
            ffp.save_log(log_file)
            self.assertTrue(os.path.isfile(log_file))
            with open(log_file) as log_fp:
                log = log_fp.read().splitlines()
            self.assertTrue(log[0].startswith('Launch command'))
            self.assertEqual(log[1:], ['', "hello world", "[Exit code: 0]"])
            log_file = "rel_test_path.txt" # save to cwd
            ffp.save_log(log_file)
            self.assertTrue(os.path.isfile(log_file))
            os.remove(log_file)
        finally:
            ffp.clean_up()
            httpd.shutdown()
            if os.path.isdir(log_dir):
                shutil.rmtree(log_dir)

    def test_5(self):
        "test get_pid()"
        ffp = FFPuppet()
        self.assertIsNone(ffp.get_pid())
        try:
            ffp.launch(TESTFF_BIN)
            self.assertGreater(ffp.get_pid(), 0)
            ffp.close()
        finally:
            ffp.clean_up()
        self.assertIsNone(ffp.get_pid())

    def test_6(self):
        "test is_running()"
        ffp = FFPuppet()
        self.assertFalse(ffp.is_running())
        try:
            ffp.launch(TESTFF_BIN)
            self.assertTrue(ffp.is_running())
            ffp.close()
            self.assertFalse(ffp.is_running())
        finally:
            ffp.clean_up()
        self.assertFalse(ffp.is_running())

    def test_7(self):
        "test wait()"
        ffp = FFPuppet()
        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"test")

        self.assertIsNone(ffp.wait())
        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch(TESTFF_BIN, location=location)
            self.assertEqual(ffp.wait(5), 0)
            ffp.close()
        finally:
            ffp.clean_up()
            httpd.shutdown()
        self.assertIsNone(ffp.wait())


    def test_8(self):
        "test clone_log()"
        rnd_log = None
        ffp = FFPuppet()
        self.assertIsNone(ffp.clone_log(target_file=self.tmpfn))
        try:
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
        finally:
            ffp.clean_up()
            if rnd_log is not None and os.path.isfile(rnd_log):
                os.remove(rnd_log)
        # verify clean_up() removed the logs
        self.assertIsNone(ffp.clone_log(target_file=self.tmpfn))

    def test_9(self):
        "test hitting memory limit"
        ffp = FFPuppet()
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_memory\n')

        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hello world")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch(TESTFF_BIN, location=location, prefs_js=self.tmpfn, memory_limit=100)
            self.assertIsNotNone(ffp.wait(60))
        finally:
            ffp.close()
            ffp.save_log(self.tmpfn)
            ffp.clean_up()
            httpd.shutdown()
        with open(self.tmpfn, "rb") as fp:
            self.assertRegex(fp.read(), b"MEMORY_LIMIT_EXCEEDED")

    def test_10(self):
        "test calling launch() multiple times"
        ffp = FFPuppet()
        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hello world")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            for _ in range(10):
                ffp.launch(TESTFF_BIN, location=location)
                ffp.close()
            # call 2x without calling launch
            ffp.launch(TESTFF_BIN, location=location)
            with self.assertRaisesRegex(LaunchError, "Process is already running"):
                ffp.launch(TESTFF_BIN, location=location)
        finally:
            ffp.close()
            ffp.clean_up()
            httpd.shutdown()

    def test_11(self):
        "test abort tokens"
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('//fftest_soft_assert\n')
        ffp = FFPuppet()
        ffp.add_abort_token(re.compile(r"TEST\dREGEX\.+"))
        with self.assertRaisesRegex(TypeError, "Expecting 'str' or 're._pattern_type' got: 'NoneType'"):
            ffp.add_abort_token(None)
        ffp.add_abort_token("###!!! ASSERTION:")
        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hello world")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch(TESTFF_BIN, location=location, prefs_js=self.tmpfn)
            self.assertIsNotNone(ffp.wait(5))
            ffp.close()
            ffp.save_log(self.tmpfn)
        finally:
            ffp.clean_up()
            httpd.shutdown()
        with open(self.tmpfn, "rb") as fp:
            self.assertRegex(fp.read(), b"TOKEN_LOCATED")

    def test_12(self):
        "test using an existing profile directory"
        prf_dir = tempfile.mkdtemp()
        ffp = FFPuppet(use_profile=prf_dir)
        try:
            ffp.launch(TESTFF_BIN)
            ffp.close()
        finally:
            ffp.clean_up()
            self.assertTrue(os.path.isdir(prf_dir))
            shutil.rmtree(prf_dir)

    def test_13(self):
        "test calling close() and clean_up() in mutliple states"
        ffp = FFPuppet()
        ffp.close()
        try:
            ffp.launch(TESTFF_BIN)
            ffp.close()
            ffp.clean_up()
            ffp.close()
        finally:
            ffp.clean_up()

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
        try:
            with self.assertRaisesRegex(IOError, "Cannot find"):
                ffp.launch(TESTFF_BIN, location="fake_file.none")
            ffp.close()
            with tempfile.NamedTemporaryFile() as test_fp:
                test_fp.write(b"test")
                test_fp.seek(0)
                ffp.launch(TESTFF_BIN, location=test_fp.name)
        finally:
            ffp.clean_up()

    def test_18(self):
        "test passing nonexistent file to launch() via prefs_js"
        ffp = FFPuppet()
        try:
            with self.assertRaisesRegex(IOError, "prefs.js file does not exist"):
                ffp.launch(TESTFF_BIN, prefs_js="fake_file.js")
        finally:
            ffp.clean_up()

    if not sys.platform.startswith('win'): # GDB work untested on windows
        def test_19(self):
            "test launching with gdb"
            ffp = FFPuppet(use_gdb=True)
            try:
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
            finally:
                ffp.clean_up()

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

        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hello world")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch(TESTFF_BIN, location=location)
            with self.assertRaisesRegex(RuntimeError, "Log is still in use.+"):
                ffp.save_log(self.tmpfn)
        finally:
            ffp.clean_up()
            httpd.shutdown()

    def test_22(self):
        "test launching with Valgrind"
        if sys.platform.startswith('win'):
            with self.assertRaisesRegex(EnvironmentError, "Valgrind is not supported on Windows"):
                FFPuppet(use_valgrind=True)
        else:
            ffp = FFPuppet(use_valgrind=True)
            try:
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
                self.assertRegex(log_data, br"\[Exit code: 0\]")
            finally:
                ffp.clean_up()

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
        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"test")
        with open(self.tmpfn, 'w') as prefs_fp:
            prefs_fp.write('//fftest_invalid_js\n')
        httpd = create_server(_req_handler)
        ffp = FFPuppet()
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            with self.assertRaisesRegex(LaunchError, "'.+?' is invalid"):
                ffp.launch(TESTFF_BIN, prefs_js=self.tmpfn, location=location)
        finally:
            ffp.clean_up()
            httpd.shutdown()

    def test_25(self):
        "test log_length()"
        ffp = FFPuppet()
        self.assertEqual(ffp.log_length(), 0)
        try:
            ffp.launch(TESTFF_BIN)
            self.assertGreater(ffp.log_length(), 0)
            ffp.close()
            self.assertGreater(ffp.log_length(), 0)
        finally:
            ffp.clean_up()
        # verify clean_up() removed the logs
        self.assertEqual(ffp.log_length(), 0)


class ScriptTests(TestCase):
    def test_01(self):
        "test calling main with '-h'"
        with self.assertRaisesRegex(SystemExit, "0"):
            main(["-h"])

    def test_02(self):
        "test calling main with test binary/script"
        fd, log = tempfile.mkstemp()
        os.close(fd)
        os.remove(log)
        fd, prefs = tempfile.mkstemp()
        os.close(fd)
        try:
            main([TESTFF_BIN, "-l", log, "-d", "-p", prefs])
            self.assertTrue(os.path.isfile(log))
        finally:
            if os.path.isfile(log):
                os.remove(log)
            if os.path.isfile(prefs):
                os.remove(prefs)
