import errno
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import os
import random
import socket
import sys
import tempfile
import threading
import time
import unittest

from ffpuppet import FFPuppet, LaunchError


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
        "test hang on start"
        ffp = FFPuppet()
        with open(self.tmpfn, 'w') as prefs:
            prefs.write('#fftest_hang\n')
        try:
            start = time.time()
            with self.assertRaisesRegex(LaunchError, "Launching browser timed out"):
                ffp.launch('testff.py', prefs_js=self.tmpfn, launch_timeout=10)
            duration = time.time() - start
        finally:
            ffp.close()
            ffp.save_log(self.tmpfn)
            ffp.clean_up()
        self.assertGreater(duration, 10)
        self.assertLess(duration, 60)

    def test_2(self):
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

    def test_3(self):
        "test log trimming"
        ffp = FFPuppet()

        class _req_handler(BaseHTTPRequestHandler):
            def do_GET(self):
                ffp.trim_log()
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
            log = log_fp.read()
        self.assertEqual(log.splitlines(), ["hello world", "[Exit code: 0]"])

