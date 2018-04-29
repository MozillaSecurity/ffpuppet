# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import platform
import shutil
import sys
import tempfile
import threading
import time
import unittest

from .helpers import create_profile, check_prefs, poll_file, configure_sanitizers, \
                     prepare_environment, wait_on_files

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("helpers_test")

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class HelperTests(TestCase):  # pylint: disable=too-many-public-methods

    def setUp(self):
        fd, self.tmpfn = tempfile.mkstemp(prefix="helper_test_")
        os.close(fd)
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
        self.assertIsNone(poll_file("invalid_file"))
        # wait for a file to finish being written
        t_size = 10
        w_thread = threading.Thread(
            target=populate_file,
            args=(self.tmpfn, t_size, e_token, 0.1, abort_evt))
        w_thread.start()
        try:
            poll_file(self.tmpfn)
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
            result = poll_file(self.tmpfn, idle_wait=1.99, timeout=2)
        finally:
            abort_evt.set()
            w_thread.join()
            abort_evt.clear()
        with open(self.tmpfn, "rb") as in_fp:
            data = in_fp.read()
        self.assertIsNone(result)
        self.assertLess(len(data), t_size + len(e_token))
        self.assertFalse(data.endswith(e_token))

    def test_04(self):
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

    def test_05(self):
        "test configure_sanitizers()"
        is_windows = platform.system().lower().startswith("windows")
        def parse(opt_str):
            opts = dict()
            for entry in opt_str.split(":"):
                k, v = entry.split("=")
                opts[k] = v
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

        # test bad env
        with self.assertRaisesRegex(AssertionError, ""):
            configure_sanitizers({"ASAN_OPTIONS":1}, self.tmpdir, "blah")

        # test previously set ASAN_SYMBOLIZER_PATH
        env = {"ASAN_SYMBOLIZER_PATH":"blah"}
        configure_sanitizers(env, "target_dir", "blah")
        self.assertIn("ASAN_SYMBOLIZER_PATH", env)
        self.assertEqual(env["ASAN_SYMBOLIZER_PATH"], "blah")

    def test_06(self):
        "test prepare_environment()"
        env = prepare_environment("", "blah")
        self.assertIn("ASAN_OPTIONS", env)
        self.assertIn("LSAN_OPTIONS", env)
        self.assertIn("UBSAN_OPTIONS", env)
        self.assertIn("RUST_BACKTRACE", env)

    def test_07(self):
        "test prepare_environment() using some predefined environment variables"
        pre = {
            "RUST_BACKTRACE":None,  # remove
            "TEST_FAKE":None,  # remove non existing entry
            "TEST_VAR":"123",  # add
            "MOZ_GDB_SLEEP":"2"}  # update
        env = prepare_environment("", "blah", pre)
        self.assertIn("ASAN_OPTIONS", env)
        self.assertIn("LSAN_OPTIONS", env)
        self.assertIn("UBSAN_OPTIONS", env)
        self.assertIn("TEST_VAR", env)
        self.assertEqual(env["TEST_VAR"], "123")
        self.assertIn("MOZ_GDB_SLEEP", env)
        self.assertEqual(env["MOZ_GDB_SLEEP"], "2")
        self.assertNotIn("RUST_BACKTRACE", env)
        self.assertNotIn("TEST_FAKE", env)

    def test_08(self):
        "test wait_on_files()"
        with tempfile.NamedTemporaryFile() as wait_fp:
            self.assertFalse(wait_on_files(os.getpid(), [wait_fp.name, self.tmpfn], timeout=0.1))
        # existing but closed file
        self.assertTrue(wait_on_files(os.getpid(), [self.tmpfn], timeout=0.1))
        # file that does not exist
        self.assertTrue(wait_on_files(os.getpid(), ["no_file"], timeout=0.1))
        # empty file list
        self.assertTrue(wait_on_files(os.getpid(), [], timeout=0.1))
