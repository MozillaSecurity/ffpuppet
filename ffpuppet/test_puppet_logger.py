# coding=utf-8
"""ffpuppet puppet logger tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import logging
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest

from .puppet_logger import PuppetLogger

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("pl_test")  # pylint: disable=invalid-name


class PuppetLoggerTests(unittest.TestCase):
    def setUp(self):
        tmpfd, self.tmpfn = tempfile.mkstemp(prefix="plog_test_")
        os.close(tmpfd)
        self.tmpdir = tempfile.mkdtemp(prefix="plog_test")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        if os.path.isfile(self.tmpfn):
            os.remove(self.tmpfn)

    def test_01(self):
        "test clean_up(), close() and reset()"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        self.assertFalse(plog.closed)
        self.assertTrue(os.path.isdir(plog.working_path))
        old_working_path = plog.working_path
        plog.close()
        self.assertTrue(plog.closed)
        with self.assertRaises(AssertionError):
            plog.add_log("test")
        plog.clean_up()
        self.assertFalse(os.path.isdir(old_working_path))
        self.assertIsNone(plog.working_path)
        self.assertTrue(plog.closed)
        plog.reset()
        self.assertTrue(os.path.isdir(plog.working_path))
        self.assertFalse(plog.closed)
        plog.add_log("test_new")
        fname = plog.get_fp("test_new").name
        self.assertTrue(os.path.isfile(fname))
        self.assertEqual(len(list(plog.files)), 1)
        self.assertEqual(len(plog.available_logs()), 1)
        plog.close()
        self.assertEqual(len(list(plog.files)), 1)
        self.assertEqual(len(plog.available_logs()), 1)
        self.assertTrue(plog.closed)
        plog.clean_up()
        self.assertFalse(any(plog.files))
        self.assertFalse(plog.available_logs())
        self.assertFalse(os.path.isfile(fname))
        plog.reset()
        self.assertFalse(plog.available_logs())
        self.assertFalse(plog.closed)

    def test_02(self):
        "test adding logs"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        self.assertFalse(plog._logs)  # pylint: disable=protected-access
        self.assertFalse(plog.available_logs())
        plog.add_log("test_new")  # non-existing log
        self.assertIn("test_new", plog.available_logs())
        fname_new = plog.get_fp("test_new").name
        self.assertTrue(os.path.isfile(fname_new))
        with open(os.path.join(self.tmpdir, "test_existing.txt"), "w+b") as in_fp:
            in_fp.write(b"blah")
            plog.add_log("test_existing", logfp=in_fp)
        self.assertEqual(len(plog._logs), 2)  # pylint: disable=protected-access
        self.assertEqual(len(plog.available_logs()), 2)
        fname_exist = plog.get_fp("test_existing").name
        self.assertTrue(os.path.isfile(fname_exist))
        self.assertEqual(plog.log_length("test_new"), 0)
        self.assertEqual(plog.log_length("test_existing"), 4)

    def test_03(self):
        "test cloning logs"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        plog.add_log("test_empty")
        plog.add_log("test_extra")
        plog.get_fp("test_extra").write(b"stuff")
        plog.get_fp("test_extra").flush()
        # test clone
        plog.add_log("test_new")
        pl_fp = plog.get_fp("test_new")
        pl_fp.write(b"test1")
        cloned = plog.clone_log("test_new")
        self.assertTrue(os.path.isfile(cloned))
        with open(cloned, "rb") as log_fp:
            self.assertEqual(log_fp.read(), b"test1")
        # test target exists
        self.assertTrue(os.path.isfile(self.tmpfn))
        pl_fp.write(b"test2")
        pl_fp.flush()
        cloned = plog.clone_log("test_new", target_file=self.tmpfn)
        self.assertTrue(os.path.isfile(cloned))
        with open(cloned, "rb") as log_fp:
            self.assertEqual(log_fp.read(), b"test1test2")
        os.remove(cloned)
        # test target does not exist with offset
        self.assertFalse(os.path.isfile(self.tmpfn))
        pl_fp.write(b"test3")
        pl_fp.flush()
        cloned = plog.clone_log("test_new", target_file=self.tmpfn, offset=4)
        self.assertTrue(os.path.isfile(cloned))
        with open(cloned, "rb") as log_fp:
            self.assertEqual(log_fp.read(), b"1test2test3")
        self.assertEqual(plog.log_length("test_new"), 15)
        # test non existent log
        self.assertIsNone(plog.clone_log("no_log"))
        # test empty log
        self.assertEqual(plog.log_length("test_empty"), 0)
        cloned = plog.clone_log("test_empty")
        self.assertTrue(os.path.isfile(cloned))
        self.assertFalse(os.stat(cloned).st_size)

    def test_04(self):
        "test saving logs"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        plog.close()
        # save when there are no logs
        plog.save_logs(self.tmpdir)
        self.assertFalse(os.listdir(self.tmpdir))
        plog.reset()
        # add small log
        plog.add_log("test_1")
        plog.get_fp("test_1").write(b"test1\ntest1\n")
        # add binary data in log
        plog.add_log("test_2")
        plog.get_fp("test_2").write(b"\x00TEST\xFF\xEF")
        # add empty log
        plog.add_log("test_empty")
        # add larger log (not a power of 2 to help catch buffer issues)
        plog.add_log("test_3")
        data = b"A" * 1234
        for _ in range(500):
            plog.get_fp("test_3").write(data)
        meta_test = os.path.join(self.tmpdir, "test_meta.txt")
        with open(meta_test, "w+b") as meta_fp:
            meta_fp.write(b"blah")
            plog.add_log("test_meta", logfp=meta_fp)
        # delay to check if creation time was copied when save_logs is called
        time.sleep(0.1)
        plog.close()
        plog.save_logs(self.tmpdir, meta=True)
        # grab meta data and remove test file
        meta_ctime = os.stat(meta_test).st_ctime
        os.remove(meta_test)
        # check saved file count
        self.assertEqual(len(plog.available_logs()), 5)
        self.assertEqual(len(os.listdir(self.tmpdir)), 6)
        # verify meta data was copied
        meta_file = os.path.join(self.tmpdir, PuppetLogger.META_FILE)
        self.assertTrue(os.path.isfile(meta_file))
        with open(meta_file, "r") as json_fp:
            meta_map = json.load(json_fp)
        self.assertEqual(len(meta_map.keys()), 5)
        self.assertEqual(meta_ctime, meta_map["log_test_meta.txt"]["st_ctime"])
        # verify all data was copied
        self.assertEqual(os.stat(plog.get_fp("test_1").name).st_size, 12)
        self.assertEqual(os.stat(plog.get_fp("test_2").name).st_size, 7)
        self.assertEqual(os.stat(plog.get_fp("test_3").name).st_size, 500 * 1234)

    def test_05(self):
        "test saving logs with empty rr trace directory"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        os.makedirs(os.path.join(plog.working_path, plog.PATH_RR))
        plog.close()
        plog.save_logs(self.tmpdir)

    def test_06(self):
        "test log that does not have a file on disk"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        with tempfile.SpooledTemporaryFile(max_size=2048) as log_fp:
            plog.add_log("test", logfp=log_fp)
            with self.assertRaises(IOError):
                plog.get_fp("test")

    def test_07(self):
        "test clean_up() with inaccessible directory"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up, ignore_errors=True)
        plog.add_log("test")
        os.chmod(plog.working_path, stat.S_IRUSR)
        plog.close()
        old_working_path = plog.working_path
        try:
            self.assertTrue(os.path.isdir(plog.working_path))
            with self.assertRaises(OSError):
                plog.clean_up()
            self.assertIsNotNone(plog.working_path)
            plog.clean_up(ignore_errors=True)
            self.assertIsNone(plog.working_path)
            self.assertTrue(os.path.isdir(old_working_path))
        finally:
            os.chmod(old_working_path, stat.S_IRWXU)
            shutil.rmtree(old_working_path)

    @unittest.skipIf(not sys.platform.startswith("win"), "Only supported on Windows")
    def test_08(self):
        "test clean_up() with in-use file"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up, ignore_errors=True)
        plog.add_log("test")
        fname = plog.get_fp("test").name
        plog.close()
        with open(fname, "r") as _:
            with self.assertRaises(OSError):
                plog.clean_up(wait_delay=0)
            self.assertTrue(os.path.isfile(fname))
            self.assertIsNotNone(plog.working_path)
        plog.clean_up()
        self.assertFalse(os.path.isfile(fname))

    def test_09(self):
        "test add_path()"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        path = plog.add_path("test")
        self.assertTrue(os.path.isdir(path))
        simple_file = os.path.join(path, "simple.txt")
        with open(simple_file, "w") as o_fp:
            o_fp.write("test")
        plog.close()
        plog.save_logs(self.tmpdir)
        self.assertIn("test", os.listdir(self.tmpdir))
        self.assertIn("simple.txt", os.listdir(os.path.join(self.tmpdir, "test")))
