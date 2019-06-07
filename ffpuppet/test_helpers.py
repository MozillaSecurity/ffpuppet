# coding=utf-8
"""ffpuppet helpers tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import multiprocessing
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest

from .exceptions import BrowserTerminatedError, BrowserTimeoutError, LaunchError
from .helpers import (
    append_prefs, Bootstrapper, create_profile, check_prefs, configure_sanitizers,
    get_processes, prepare_environment, SanitizerConfig, wait_on_files)

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("helpers_test")  # pylint: disable=invalid-name


# this needs to be here in order to work correctly on Windows
def dummy_process(is_alive, is_done):
    is_alive.set()
    sys.stdout.write("I'm process %d\n" % os.getpid())
    is_done.wait(5)


class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:
        def assertRaisesRegex(self, *args, **kwds):  # pylint: disable=arguments-differ,invalid-name
            return self.assertRaisesRegexp(*args, **kwds)  # pylint: disable=deprecated-method


class HelperTests(TestCase):  # pylint: disable=too-many-public-methods

    def setUp(self):
        _fd, self.tmpfn = tempfile.mkstemp(prefix="helper_test_")
        os.close(_fd)
        self.tmpdir = tempfile.mkdtemp(prefix="helper_test_")

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.unlink(self.tmpfn)
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_01(self):
        "test create_profile()"
        with self.assertRaisesRegex(IOError, "Cannot find template profile: 'fake_dir'"):
            create_profile(template="fake_dir")

        with self.assertRaisesRegex(IOError, "prefs.js file does not exist: 'fake_prefs'"):
            create_profile(prefs_js="fake_prefs")

        # try creating a profile from scratch, does nothing but create a directory to be populated
        prof = create_profile()
        self.assertTrue(os.path.isdir(prof))
        contents = os.listdir(prof)
        shutil.rmtree(prof)
        self.assertEqual(len(contents), 0)

        # create dummy profile
        invalid_js = os.path.join(self.tmpdir, "Invalidprefs.js")
        with open(invalid_js, "w") as log_fp:
            log_fp.write("blah!")
        # try creating a profile from a template
        prof = create_profile(prefs_js=self.tmpfn, template=self.tmpdir)
        self.assertTrue(os.path.isdir(prof))
        contents = os.listdir(prof)
        shutil.rmtree(prof)
        self.assertIn("prefs.js", contents)
        self.assertIn("times.json", contents)
        self.assertNotIn("Invalidprefs.js", contents)

    def test_02(self):
        "test check_prefs()"
        with self.assertRaises(IOError):
            check_prefs(self.tmpfn, "/missing/file")
        with self.assertRaises(IOError):
            check_prefs("/missing/file", self.tmpfn)
        with open(self.tmpfn, 'w') as prefs_fp:  # browser prefs.js dummy
            prefs_fp.write('// comment line\n')
            prefs_fp.write('# comment line\n')
            prefs_fp.write(' \n\n')
            prefs_fp.write('user_pref("a.a", 0);\n')
            prefs_fp.write('user_pref("a.b", "test");\n')
            prefs_fp.write('user_pref("a.c", true);\n')
        tmpfd, custom_prefs = tempfile.mkstemp(dir=self.tmpdir)
        os.close(tmpfd)
        with open(custom_prefs, "w") as prefs_fp:
            prefs_fp.write('// comment line\n')
            prefs_fp.write('# comment line\n')
            prefs_fp.write('/* comment block.\n')
            prefs_fp.write('*\n')
            prefs_fp.write(' \n\n')
            prefs_fp.write('user_pref("a.a", 0); // test comment\n')
            prefs_fp.write('user_pref("a.c", true);\n')
        self.assertTrue(check_prefs(self.tmpfn, prefs_fp.name))
        with open(custom_prefs, "w") as prefs_fp:
            prefs_fp.write('user_pref("a.a", 0);\n')
            prefs_fp.write('user_pref("b.a", false);\n')
        # test detecting missing prefs
        self.assertFalse(check_prefs(self.tmpfn, prefs_fp.name))

    def test_03(self):
        "test create_profile() extension support"

        # create a profile with a non-existent ext
        with self.assertRaisesRegex(RuntimeError, "Unknown extension: 'fake_ext'"):
            create_profile(extension="fake_ext")

        # create a profile with an xpi ext
        with open("xpi-ext.xpi", "w"):
            pass
        self.addCleanup(os.unlink, "xpi-ext.xpi")
        prof = create_profile(extension="xpi-ext.xpi")
        self.addCleanup(shutil.rmtree, prof)
        self.assertEqual(os.listdir(prof), ["extensions"])
        self.assertEqual(os.listdir(os.path.join(prof, "extensions")), ["xpi-ext.xpi"])

        # create a profile with an unknown ext
        os.mkdir("dummy_ext")
        self.addCleanup(os.rmdir, "dummy_ext")
        with self.assertRaisesRegex(RuntimeError, "Failed to find extension id in manifest: 'dummy_ext'"):
            create_profile(extension="dummy_ext")

        # create a profile with a bad legacy ext
        os.mkdir("bad_legacy")
        self.addCleanup(shutil.rmtree, "bad_legacy")
        with open(os.path.join("bad_legacy", "install.rdf"), "w"):
            pass
        with self.assertRaisesRegex(RuntimeError, "Failed to find extension id in manifest: 'bad_legacy'"):
            create_profile(extension="bad_legacy")

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
        prof = create_profile(extension="good_legacy")
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
            create_profile(extension="bad_webext")

        # create a profile with a good webext
        os.mkdir("good_webext")
        self.addCleanup(shutil.rmtree, "good_webext")
        with open(os.path.join("good_webext", "manifest.json"), "w") as manifest:
            manifest.write("""{"applications": {"gecko": {"id": "good-webext-id"}}}""")
        with open(os.path.join("good_webext", "example.js"), "w"):
            pass
        prof = create_profile(extension="good_webext")
        self.addCleanup(shutil.rmtree, prof)
        self.assertEqual(os.listdir(prof), ["extensions"])
        self.assertEqual(os.listdir(os.path.join(prof, "extensions")), ["good-webext-id"])
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions", "good-webext-id"))),
                         {"manifest.json", "example.js"})

        # create a profile with multiple extensions
        prof = create_profile(extension=["good_webext", "good_legacy"])
        self.addCleanup(shutil.rmtree, prof)
        self.assertEqual(os.listdir(prof), ["extensions"])
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions"))), {"good-ext-id", "good-webext-id"})
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions", "good-webext-id"))),
                         {"manifest.json", "example.js"})
        self.assertEqual(set(os.listdir(os.path.join(prof, "extensions", "good-ext-id"))),
                         {"install.rdf", "example.js"})

    def test_04(self):
        "test configure_sanitizers()"
        is_windows = sys.platform.startswith("win")
        def parse(opt_str):
            opts = dict()
            for entry in SanitizerConfig.re_delim.split(opt_str):
                key, value = entry.split("=")
                opts[key] = value
            return opts

        # create dummy llvm-symbolizer
        dummy_symb = os.path.join(self.tmpdir, "llvm-symbolizer%s" % (".exe" if is_windows else ""))
        with open(dummy_symb, "w") as out_fp:
            out_fp.write("blah")

        # test with empty environment
        env = {}
        configure_sanitizers(env, self.tmpdir, "blah")
        self.assertIn("ASAN_OPTIONS", env)
        asan_opts = parse(env["ASAN_OPTIONS"])
        self.assertIn("detect_leaks", asan_opts)
        self.assertEqual(asan_opts["detect_leaks"], "false")
        self.assertEqual(asan_opts["log_path"], "'blah'")
        self.assertIn("LSAN_OPTIONS", env)
        self.assertIn("UBSAN_OPTIONS", env)
        if not is_windows:
            self.assertIn("llvm-symbolizer", env["ASAN_SYMBOLIZER_PATH"])
        else:
            self.assertNotIn("ASAN_SYMBOLIZER_PATH", env)

        # test with presets environment
        env = {"ASAN_OPTIONS":"detect_leaks=true", "LSAN_OPTIONS":"a=1=2", "UBSAN_OPTIONS":""}
        configure_sanitizers(env, self.tmpdir, "blah")
        self.assertIn("ASAN_OPTIONS", env)
        asan_opts = parse(env["ASAN_OPTIONS"])
        self.assertIn("detect_leaks", asan_opts)
        self.assertEqual(asan_opts["detect_leaks"], "true")
        self.assertIn("LSAN_OPTIONS", env)
        self.assertIn("UBSAN_OPTIONS", env)
        ubsan_opts = parse(env["UBSAN_OPTIONS"])
        self.assertIn("print_stacktrace", ubsan_opts)

        # test previously set ASAN_SYMBOLIZER_PATH
        env = {"ASAN_SYMBOLIZER_PATH":"blah"}
        configure_sanitizers(env, "target_dir", "blah")
        self.assertIn("ASAN_SYMBOLIZER_PATH", env)
        self.assertEqual(env["ASAN_SYMBOLIZER_PATH"], "blah")

        # test suppression file
        env = {"ASAN_OPTIONS":"suppressions='%s'" % self.tmpfn}
        configure_sanitizers(env, self.tmpdir, "blah")
        asan_opts = parse(env["ASAN_OPTIONS"])
        self.assertIn("suppressions", asan_opts)

        # test overwrite log_path
        env = {"ASAN_OPTIONS":"log_path='overwrite'", "UBSAN_OPTIONS":"log_path='overwrite'"}
        configure_sanitizers(env, self.tmpdir, "blah")
        self.assertIn("ASAN_OPTIONS", env)
        asan_opts = parse(env["ASAN_OPTIONS"])
        self.assertEqual(asan_opts["log_path"], "'blah'")
        self.assertIn("UBSAN_OPTIONS", env)
        ubsan_opts = parse(env["UBSAN_OPTIONS"])
        self.assertEqual(ubsan_opts["log_path"], "'blah'")

        # test missing suppression file
        env = {"ASAN_OPTIONS":"suppressions=no_a_file"}
        with self.assertRaisesRegex(IOError, r"Suppressions file '.+?' does not exist"):
            configure_sanitizers(env, self.tmpdir, "blah")

        # unquoted path containing ':'
        env = {"ASAN_OPTIONS":"strip_path_prefix=x:\\foo\\bar"}
        with self.assertRaises(AssertionError):
            configure_sanitizers(env, self.tmpdir, "blah")

        # multiple options
        env = {"ASAN_OPTIONS":"opt1=1:opt2=:opt3=test:opt4='x:\\foo':opt5=\"z:/bar\":opt6=''"}
        configure_sanitizers(env, self.tmpdir, "blah")
        asan_opts = parse(env["ASAN_OPTIONS"])
        self.assertEqual(asan_opts["opt1"], "1")
        self.assertEqual(asan_opts["opt2"], "")
        self.assertEqual(asan_opts["opt3"], "test")
        self.assertEqual(asan_opts["opt4"], "'x:\\foo'")
        self.assertEqual(asan_opts["opt5"], "\"z:/bar\"")
        self.assertEqual(asan_opts["opt6"], "''")

    def test_05(self):
        "test prepare_environment()"
        env = prepare_environment("", "blah")
        self.assertIn("ASAN_OPTIONS", env)
        self.assertIn("LSAN_OPTIONS", env)
        self.assertIn("UBSAN_OPTIONS", env)
        self.assertIn("RUST_BACKTRACE", env)
        self.assertIn("MOZ_CRASHREPORTER", env)

    def test_06(self):
        "test prepare_environment() using some predefined environment variables"
        pre = {
            "LSAN_OPTIONS": "lopt=newopt",
            "MOZ_GDB_SLEEP":"2",  # update default
            "MOZ_SKIA_DISABLE_ASSERTS": "1",  # existing optional
            "RUST_BACKTRACE":None,  # remove default
            "TEST_FAKE":None,  # remove non existing entry
            "TEST_VAR":"123",  # add non existing entry
            "TEST_EXISTING_OVERWRITE":"1",
            "TEST_EXISTING_REMOVE":None}
        try:
            os.environ["MOZ_SKIA_DISABLE_ASSERTS"] = "0"
            os.environ["TEST_EXISTING_OVERWRITE"] = "0"
            os.environ["TEST_EXISTING_REMOVE"] = "1"
            env = prepare_environment("", "blah", pre)
        finally:
            os.environ.pop("MOZ_SKIA_DISABLE_ASSERTS")
            os.environ.pop("TEST_EXISTING_OVERWRITE")
            os.environ.pop("TEST_EXISTING_REMOVE")
        self.assertIn("ASAN_OPTIONS", env)
        self.assertIn("LSAN_OPTIONS", env)
        self.assertIn("lopt=newopt", env["LSAN_OPTIONS"].split(":"))
        self.assertIn("max_leaks=1", env["LSAN_OPTIONS"].split(":"))
        self.assertIn("UBSAN_OPTIONS", env)
        self.assertIn("TEST_VAR", env)
        self.assertEqual(env["TEST_VAR"], "123")
        self.assertIn("MOZ_CRASHREPORTER", env)
        self.assertIn("MOZ_GDB_SLEEP", env)
        self.assertEqual(env["MOZ_GDB_SLEEP"], "2")
        self.assertNotIn("RUST_BACKTRACE", env)
        self.assertNotIn("TEST_FAKE", env)
        self.assertNotIn("TEST_EXISTING_REMOVE", env)
        self.assertEqual(env["MOZ_SKIA_DISABLE_ASSERTS"], "0")
        self.assertEqual(env["TEST_EXISTING_OVERWRITE"], "1")
        # MOZ_CRASHREPORTER should not be added if MOZ_CRASHREPORTER_DISABLE is set
        pre = {"MOZ_CRASHREPORTER_DISABLE": "1"}
        env = prepare_environment("", "blah", pre)
        self.assertNotIn("MOZ_CRASHREPORTER", env)

    def test_07(self):
        "test wait_on_files()"
        with tempfile.NamedTemporaryFile() as wait_fp:
            self.assertFalse(wait_on_files((wait_fp.name, self.tmpfn), timeout=0.1))
        # existing but closed file
        self.assertTrue(wait_on_files([self.tmpfn], timeout=0.1))
        # file that does not exist
        self.assertTrue(wait_on_files(["no_file"], timeout=0.1))
        # empty file list
        self.assertTrue(wait_on_files([]))

    def test_08(self):
        "test bootstrapper"
        bts = Bootstrapper()
        self.addCleanup(bts.close)
        self.assertTrue(bts.location.startswith("http://127.0.0.1:"))
        self.assertGreater(int(bts.location.split(":")[-1]), 1024)

        with self.assertRaises(BrowserTimeoutError):
            bts.wait(lambda: True, timeout=0.1)

        with self.assertRaises(BrowserTerminatedError):
            bts.wait(lambda: False)

        def _fake_browser(port, error=False, timeout=False, payload_size=5120):
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 50 x 0.1 = 5 seconds
            conn.settimeout(0.1)
            attempts = 50
            # open connection
            while True:
                try:
                    conn.connect(("127.0.0.1", port))
                    conn.settimeout(10)
                except socket.timeout:
                    attempts -= 1
                    if attempts > 0:
                        continue
                    conn.close()
                    raise
                break
            # send request and receive response
            try:
                if timeout:
                    return
                conn.sendall(b"A" * payload_size)
                # don't send sentinel when multiple of 'buf_size' (test hang code)
                if payload_size % 4096 != 0:
                    conn.send(b"")
                if error:
                    conn.shutdown(socket.SHUT_RDWR)
                    return
                conn.recv(8192)
            finally:
                conn.close()

        # without redirect
        browser_thread = threading.Thread(target=_fake_browser, args=(bts.port,))
        try:
            browser_thread.start()
            bts.wait(browser_thread.is_alive, timeout=10)
        finally:
            browser_thread.join()

        # with redirect
        browser_thread = threading.Thread(target=_fake_browser, args=(bts.port,))
        try:
            browser_thread.start()
            bts.wait(browser_thread.is_alive, timeout=10, url="http://localhost/")
        finally:
            browser_thread.join()

        # test filling buffer
        browser_thread = threading.Thread(
            target=_fake_browser,
            args=(bts.port,),
            kwargs={'payload_size': 8192})
        try:
            browser_thread.start()
            bts.wait(lambda: True, timeout=10)
        finally:
            browser_thread.join()

        # callback failure
        browser_thread = threading.Thread(
            target=_fake_browser,
            args=(bts.port,),
            kwargs={'timeout': True})
        try:
            browser_thread.start()
            with self.assertRaises(BrowserTerminatedError):
                bts.wait(lambda: False, timeout=10)
        finally:
            browser_thread.join()

        # timeout waiting for connection data
        browser_thread = threading.Thread(
            target=_fake_browser,
            args=(bts.port,),
            kwargs={'timeout': True})
        try:
            browser_thread.start()
            with self.assertRaises(BrowserTimeoutError):
                bts.wait(lambda: True, timeout=0.25)
        finally:
            browser_thread.join()

        init_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(init_soc.close)
        # exhaust port range
        if sys.platform.startswith("win"):
            init_soc.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)  # pylint: disable=no-member
        init_soc.bind(("127.0.0.1", 0))  # bind to a random free port
        try:
            Bootstrapper.PORT_MAX = init_soc.getsockname()[1]
            Bootstrapper.PORT_MIN = Bootstrapper.PORT_MAX
            with self.assertRaisesRegex(LaunchError, "Could not find available port"):
                Bootstrapper()
        finally:
            Bootstrapper.PORT_MAX = 0xFFFF
            Bootstrapper.PORT_MIN = 0x4000

    def test_09(self):
        "test append_prefs()"
        pref_fname = os.path.join(self.tmpdir, "prefs.js")
        with open(pref_fname, "w") as out_fp:
            out_fp.write("user_pref('pre.existing', 1);\n")
        append_prefs(self.tmpdir, {"test.enabled": "True", "foo": "'a1b2c3'"})
        self.assertTrue(os.path.isfile(pref_fname))
        with open(pref_fname, "r") as in_fp:
            data = in_fp.read()
        self.assertIn("user_pref('pre.existing', 1);\n", data)
        self.assertIn("user_pref('test.enabled', True);\n", data)
        self.assertIn("user_pref('foo', 'a1b2c3');\n", data)

    def test_10(self):
        "test get_processes()"
        self.assertEqual(len(get_processes(os.getpid(), recursive=False)), 1)
        self.assertFalse(get_processes(0xFFFFFF))
        is_alive = multiprocessing.Event()
        is_done = multiprocessing.Event()
        self.addCleanup(is_done.set)
        proc = multiprocessing.Process(target=dummy_process, args=(is_alive, is_done))
        proc.start()
        is_alive.wait(5)
        self.assertGreater(len(get_processes(os.getpid())), 1)
        is_done.set()
        proc.join()
