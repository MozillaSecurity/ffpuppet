import errno
import logging
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import os
import platform
import random
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

from ffpuppet import FFPuppet, LaunchError


logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("ffp_test")


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
            httpd = HTTPServer(('127.0.0.1', random.randint(0x2000, 0xFFFF)), handler)
        except socket.error as soc_e:
            if soc_e.errno == errno.EADDRINUSE: # Address already in use
                continue
            raise
        break
    def _srv_thread():
        httpd.serve_forever()
    thread = threading.Thread(target=_srv_thread)
    thread.start()
    # XXX: join the thread on shutdown() .. somehow
    return httpd


class PuppetTests(TestCase):

    def setUp(self):
        fd, self.tmpfn = tempfile.mkstemp()
        os.close(fd)

    def tearDown(self):
        os.unlink(self.tmpfn)

    if sys.platform != 'win32':
        def test_0(self):
            "test that invalid executables raise the right exception"
            ffp = FFPuppet()
            with self.assertRaisesRegex(IOError, "is not an executable"):
                try:
                    ffp.launch(self.tmpfn)
                finally:
                    ffp.close()
                    ffp.save_log(self.tmpfn)
                    ffp.clean_up()

    def test_1(self):
        "test basic launch and close"
        ffp = FFPuppet()

        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write("test")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch('testff.py', location=location)
            self.assertEqual(ffp.wait(1), 0) # will close automatically
        finally:
            ffp.close()
            ffp.clean_up()
            httpd.shutdown()
        self.assertFalse(ffp.is_running())
        self.assertIsNone(ffp.wait())

    def test_2(self):
        "test crash on start"
        ffp = FFPuppet()
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('#fftest_startup_crash\n')
        try:
            with self.assertRaisesRegex(LaunchError, "Failure during browser startup"):
                ffp.launch('testff.py', prefs_js=self.tmpfn)
        finally:
            self.assertEqual(ffp.wait(1), 1) # test crash returns 1
            ffp.close()
            ffp.save_log(self.tmpfn)
            ffp.clean_up()

    def test_3(self):
        "test hang on start"
        ffp = FFPuppet()
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('#fftest_hang\n')
        try:
            start = time.time()
            with self.assertRaisesRegex(LaunchError, "Launching browser timed out"):
                ffp.launch('testff.py', prefs_js=self.tmpfn, launch_timeout=1)
            duration = time.time() - start
        finally:
            ffp.close()
            ffp.save_log(self.tmpfn)
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
                self.wfile.write("hello world")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch('testff.py', location=location)
            ffp.wait()
        finally:
            ffp.close()
            ffp.save_log(self.tmpfn)
            ffp.clean_up()
            httpd.shutdown()
        with open(self.tmpfn) as log_fp:
            log = log_fp.read().splitlines()
        self.assertTrue(log[0].startswith('Launch command'))
        self.assertEqual(log[1:], ['', "hello world", "[Exit code: 0]"])

    def test_5(self):
        "test get_pid()"
        ffp = FFPuppet()
        self.assertIsNone(ffp.get_pid())
        try:
            ffp.launch('testff.py')
            self.assertGreater(ffp.get_pid(), 0)
        finally:
            ffp.close()
            ffp.clean_up()
            self.assertIsNone(ffp.get_pid())

    def test_6(self):
        "test is_running()"
        ffp = FFPuppet()
        self.assertFalse(ffp.is_running())
        try:
            ffp.launch('testff.py')
            self.assertTrue(ffp.is_running())
        finally:
            ffp.close()
            self.assertFalse(ffp.is_running())
            ffp.clean_up()
            self.assertFalse(ffp.is_running())

    def test_7(self):
        "test wait()"
        ffp = FFPuppet()
        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write("test")

        self.assertIsNone(ffp.wait())
        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch('testff.py', location=location)
            self.assertEqual(ffp.wait(5), 0)
        finally:
            ffp.close()
            ffp.clean_up()
            httpd.shutdown()
        self.assertIsNone(ffp.wait())


    def test_8(self):
        "test clone_log()"
        ffp = FFPuppet()
        self.assertIsNone(ffp.clone_log(target_file=self.tmpfn))
        try:
            ffp.launch('testff.py')
            # make sure logs are available
            self.assertEqual(ffp.clone_log(target_file=self.tmpfn), self.tmpfn)
            with open(self.tmpfn, "rb") as tmpfp:
                orig = tmpfp.read()
            self.assertEqual(ffp.clone_log(target_file=self.tmpfn, offset=10), self.tmpfn)
            self.assertGreater(len(orig), 10)
            with open(self.tmpfn, "rb") as tmpfp:
                self.assertEqual(tmpfp.read(), orig[10:])
            ffp.close()
            # make sure logs are available
            self.assertEqual(ffp.clone_log(target_file=self.tmpfn), self.tmpfn)
            with open(self.tmpfn, "rb") as tmpfp:
                self.assertTrue(tmpfp.read().startswith(orig))
                self.assertGreater(tmpfp.tell(), len(orig))
        finally:
            ffp.clean_up()
        # verify clean_up() removed the logs
        self.assertIsNone(ffp.clone_log(target_file=self.tmpfn))

    def test_9(self):
        "test hitting memory limit"
        ffp = FFPuppet()
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('#fftest_memory\n')

        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write("hello world")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch('testff.py', location=location, prefs_js=self.tmpfn, memory_limit=100)
            self.assertIsNotNone(ffp.wait(60))
        finally:
            ffp.close()
            ffp.save_log(self.tmpfn)
            ffp.clean_up()
            httpd.shutdown()
        with open(self.tmpfn, "r") as fp:
            self.assertRegex(fp.read(), "MEMORY_LIMIT_EXCEEDED")

    def test_10(self):
        "test calling launch() multiple times"
        ffp = FFPuppet()
        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write("hello world")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            for _ in range(10):
                ffp.launch('testff.py', location=location)
                ffp.close()
            # call 2x without calling launch
            ffp.launch('testff.py', location=location)
            with self.assertRaisesRegex(LaunchError, "Process is already running"):
                ffp.launch('testff.py', location=location)
        finally:
            ffp.close()
            ffp.clean_up()
            httpd.shutdown()

    def test_11(self):
        "test abort tokens via detect_soft_assertions"
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('#fftest_soft_assert\n')
        ffp = FFPuppet(detect_soft_assertions=True)

        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write("hello world")

        httpd = create_server(_req_handler)
        try:
            location = "http://127.0.0.1:%d" % httpd.server_address[1]
            ffp.launch('testff.py', location=location, prefs_js=self.tmpfn)
            self.assertIsNotNone(ffp.wait(5))
        finally:
            ffp.close()
            ffp.save_log(self.tmpfn)
            ffp.clean_up()
            httpd.shutdown()
        with open(self.tmpfn, "r") as fp:
            self.assertRegex(fp.read(), "TOKEN_LOCATED")

    def test_12(self):
        "test using an existing profile directory"
        prf_dir = tempfile.mkdtemp()
        ffp = FFPuppet(use_profile=prf_dir)
        try:
            ffp.launch('testff.py')
        finally:
            ffp.close()
            ffp.clean_up()
            self.assertTrue(os.path.isdir(prf_dir))
            shutil.rmtree(prf_dir)

    def test_13(self):
        "test calling close() and clean_up() in mutliple states"
        prf_dir = tempfile.mkdtemp()
        ffp = FFPuppet(use_profile=prf_dir)
        ffp.close()
        try:
            ffp.launch('testff.py')
        finally:
            ffp.close()
            ffp.clean_up()
            ffp.close()
            ffp.clean_up()
        shutil.rmtree(prf_dir)

    def test_14(self):
        "test manually setting ASAN_SYMBOLIZER_PATH"
        os.environ["ASAN_SYMBOLIZER_PATH"] = "foo/bar"
        ffp = FFPuppet()
        env = ffp.get_environ("fake/bin/path")
        ffp.close()
        ffp.clean_up()
        os.environ.pop("ASAN_SYMBOLIZER_PATH", None)
        self.assertEqual(env["ASAN_SYMBOLIZER_PATH"], "foo/bar")

    def test_15(self):
        "test automatically using bundled llvm-symbolizer"
        test_dir = tempfile.mkdtemp()
        with open(os.path.join(test_dir, "llvm-symbolizer"), "w") as fp:
            fp.write("test")
        ffp = FFPuppet()
        env = ffp.get_environ(os.path.join(test_dir, "fake_bin"))
        ffp.close()
        ffp.clean_up()
        shutil.rmtree(test_dir)
        self.assertEqual(env["ASAN_SYMBOLIZER_PATH"], os.path.join(test_dir, "llvm-symbolizer"))

    def test_16(self):
        "test launching under Xvfb"
        if platform.system().lower() != "linux":
            with self.assertRaisesRegex(EnvironmentError, "Xvfb is only supported on Linux"):
                ffp = FFPuppet(use_xvfb=True)
        else:
            ffp = FFPuppet(use_xvfb=True)
        ffp.close()
        ffp.clean_up()

# TODO: open file url, open missing file url
