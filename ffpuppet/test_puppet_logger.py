import logging
import os
import shutil
import sys
import tempfile
import unittest

from .puppet_logger import PuppetLogger

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("pl_test")

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class PuppetLoggerTests(TestCase):
    def setUp(self):
        fd, self.tmpfn = tempfile.mkstemp(prefix="plog_test_")
        os.close(fd)
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
        plog.close()
        self.assertTrue(plog.closed)
        plog.clean_up()
        self.assertTrue(plog.closed)
        plog.reset()
        self.assertFalse(plog.closed)
        plog.add_log("test_new")
        fname = plog.get_fp("test_new").name
        self.assertTrue(os.path.isfile(fname))
        self.assertEqual(len(plog.available_logs()), 1)
        plog.close()
        self.assertEqual(len(plog.available_logs()), 1)
        self.assertTrue(plog.closed)
        plog.clean_up()
        self.assertEqual(len(plog.available_logs()), 0)
        self.assertFalse(os.path.isfile(fname))
        plog.reset()
        self.assertEqual(len(plog.available_logs()), 0)
        self.assertFalse(plog.closed)

    def test_02(self):
        "test adding logs"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        self.assertEqual(len(plog._logs), 0) # pylint: disable=protected-access
        self.assertEqual(len(plog.available_logs()), 0)
        plog.add_log("test_new") # non-existing log
        self.assertIn("test_new", plog.available_logs())
        fname_new = plog.get_fp("test_new").name
        self.assertTrue(os.path.isfile(fname_new))
        existing_fp = open(os.path.join(self.tmpdir, "test_existing.txt"), "w+b")
        try:
            existing_fp.write(b"blah")
            plog.add_log("test_existing", logfp=existing_fp)
        finally:
            existing_fp.close()
        self.assertEqual(len(plog._logs), 2) # pylint: disable=protected-access
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
        plog.add_log("test_new")
        pl_fp = plog.get_fp("test_new")
        pl_fp.write(b"test1")
        pl_fp.flush()
        with open(pl_fp.name, "rb") as log_fp:
            self.assertEqual(log_fp.read(), b"test1")
        cloned = plog.clone_log("test_new")
        try:
            with open(cloned, "rb") as log_fp:
                self.assertEqual(log_fp.read(), b"test1")
        finally:
            if os.path.isfile(cloned):
                os.remove(cloned)
        # test target exists
        self.assertTrue(os.path.isfile(self.tmpfn))
        pl_fp.write(b"test2")
        pl_fp.flush()
        cloned = plog.clone_log("test_new", target_file=self.tmpfn)
        try:
            with open(cloned, "rb") as log_fp:
                self.assertEqual(log_fp.read(), b"test1test2")
        finally:
            if os.path.isfile(cloned):
                os.remove(cloned)
        # test target does not exist with offset
        self.assertFalse(os.path.isfile(self.tmpfn))
        pl_fp.write(b"test3")
        pl_fp.flush()
        cloned = plog.clone_log("test_new", target_file=self.tmpfn, offset=4)
        try:
            with open(cloned, "rb") as log_fp:
                self.assertEqual(log_fp.read(), b"1test2test3")
        finally:
            if os.path.isfile(cloned):
                os.remove(cloned)
        self.assertEqual(plog.log_length("test_new"), 15)
        # test non existent log
        self.assertIsNone(plog.clone_log("no_log"))
        # test empty log
        self.assertEqual(plog.log_length("test_empty"), 0)
        cloned = plog.clone_log("test_empty")
        try:
            with open(cloned, "rb") as log_fp:
                log_fp.seek(0, os.SEEK_END)
                self.assertEqual(log_fp.tell(), 0)
        finally:
            if os.path.isfile(cloned):
                os.remove(cloned)

    def test_04(self):
        "test saving logs"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        # save when there are no logs
        plog.save_logs(self.tmpdir)
        self.assertEqual(len(os.listdir(self.tmpdir)), 0)
        # add small log
        plog.add_log("test_1")
        plog.get_fp("test_1").write(b"test1\ntest1\n")
        plog.get_fp("test_1").flush()
        # add binary data in log
        plog.add_log("test_2")
        plog.get_fp("test_2").write(b"\x00TEST\xFF\xEF")
        plog.get_fp("test_2").flush()
        # add empty log
        plog.add_log("test_empty")
        # add larger log ~512KB log
        plog.add_log("test_3")
        data = b"A" * 1024
        for _ in range(512):
            plog.get_fp("test_3").write(data)
        plog.get_fp("test_3").flush()
        plog.save_logs(self.tmpdir)
        self.assertEqual(len(plog.available_logs()), 4)
        dir_list = os.listdir(self.tmpdir)
        self.assertEqual(len(dir_list), 4)

    def test_05(self):
        "test log that does not have a file on disk"
        plog = PuppetLogger()
        self.addCleanup(plog.clean_up)
        with tempfile.SpooledTemporaryFile(max_size=2048) as log_fp:
            plog.add_log("test", logfp=log_fp)
            with self.assertRaisesRegex(IOError, r"log file\s.+?\sdoes not exist"):
                plog.get_fp("test")
