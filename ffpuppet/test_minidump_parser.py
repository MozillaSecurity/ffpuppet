# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import shutil
import sys
import tempfile
import time
import unittest

from .minidump_parser import MinidumpParser, process_minidumps

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("minidump_test")

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


CWD = os.path.realpath(os.path.dirname(__file__))
TESTMDSW_BIN = os.path.join(CWD, "testmdsw", "testmdsw.exe") if sys.platform.startswith('win') else os.path.join(CWD, "testmdsw.py")

MinidumpParser.MDSW_BIN = TESTMDSW_BIN
MinidumpParser.MDSW_MAX_STACK = 8
MinidumpParser.POLL_RATE = 0.01
MinidumpParser.POLL_WAIT = 0.1


class DummyLogger(object):
    def __init__(self):
        self._files = dict()
        self._working_path = None

    @property
    def count(self):
        return len(self._files)

    def create(self, file_name):
        if self._working_path is None:
            self._working_path = tempfile.mkdtemp()
        tmp_fd, log_file = tempfile.mkstemp(
            dir=self._working_path,
            prefix=time.strftime("ffp_%Y-%m-%d_%H-%M-%S_"))
        os.close(tmp_fd)

        # open with 'open' so the file object 'name' attribute is correct
        self._files[file_name] = open(log_file, mode="wb")

        return self._files[file_name]

    def close(self):
        for fp in self._files.values():
            fp.close()
        if self._working_path is not None and os.path.isdir(self._working_path):
            shutil.rmtree(self._working_path)


class MinidumpParserTests(TestCase):  # pylint: disable=too-many-public-methods

    @classmethod
    def setUpClass(cls):
        if sys.platform.startswith('win') and not os.path.isfile(TESTMDSW_BIN):
            raise EnvironmentError("testmdsw.exe is missing see testmdsw.py for build instructions") # pragma: no cover

    def setUp(self):
        self.lgr = DummyLogger()
        fd, self.tmpfn = tempfile.mkstemp(prefix="helper_test_")
        os.close(fd)
        self.tmpdir = tempfile.mkdtemp(prefix="helper_test_")

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.unlink(self.tmpfn)
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        self.lgr.close()

    def test_01(self):
        "test MinidumpParser() with empty scan path"
        mdp = MinidumpParser(self.tmpdir)
        self.assertFalse(mdp.dump_files)
        mdp.collect_logs(self.lgr.create, self.tmpdir)

    def test_02(self):
        "test MinidumpParser() with empty minidumps"
        md_path = os.path.join(self.tmpdir, "minidumps")
        os.mkdir(md_path)
        with open(os.path.join(md_path, "not_a_dmp.txt"), "w") as _:
            pass
        with open(os.path.join(md_path, "test.dmp"), "w") as _:
            pass
        mdp = MinidumpParser(md_path)
        self.assertEqual(len(mdp.dump_files), 1)
        mdp.collect_logs(self.lgr.create, self.tmpdir)
        internal_fp = [fp for fp in self.lgr._files.values()][0]  # pylint: disable=protected-access
        internal_fp.flush()
        with open(internal_fp.name, "r") as log_fp:
            self.assertTrue(log_fp.read().startswith("WARNING: minidump_stackwalk log was empty"))

    def test_03(self):
        "test _read_registers()"
        with open(self.tmpfn, "w") as out_fp:
            out_fp.write("Crash reason:  SIGSEGV\n")
            out_fp.write("Crash address: 0x0\n")
            out_fp.write("Process uptime: not available\n\n")
            out_fp.write("Thread 0 (crashed)\n")
            out_fp.write(" 0  libxul.so + 0x123456788\n")
            out_fp.write("    rax = 0xe5423423423fffe8   rdx = 0x0000000000000000\n")
            out_fp.write("    rcx = 0x0000000000000000   rbx = 0xe54234234233e5e5\n")
            out_fp.write("    rsi = 0x0000000000000000   rdi = 0x00007fedc31fe308\n")
            out_fp.write("    rbp = 0x00007fffca0dab00   rsp = 0x00007fffca0daad0\n")
            out_fp.write("     r8 = 0x0000000000000000    r9 = 0x0000000000000008\n")
            out_fp.write("    r10 = 0xffff00ffffffffff   r11 = 0xffffff00ffffffff\n")
            out_fp.write("    r12 = 0x0000743564566308   r13 = 0x00007fedce9d8000\n")
            out_fp.write("    r14 = 0x0000000000000001   r15 = 0x0000000000000000\n")
            out_fp.write("    rip = 0x0000745666666ac\n")
            out_fp.write("    Found by: given as instruction pointer in context\n")
            out_fp.write(" 1  libxul.so + 0x1f4361c]\n\n")

        mdp = MinidumpParser(self.tmpdir)
        mdp.symbols_path = self.tmpdir  # usually set internally
        md_lines = list()
        with tempfile.TemporaryFile() as log_fp:
            mdp._read_registers(self.tmpfn, log_fp)  # pylint: disable=protected-access
            log_fp.seek(0)
            for line in log_fp:  # pylint: disable=not-an-iterable
                if b"=" not in line:
                    break
                md_lines.append(line)
        self.assertEqual(len(md_lines), 9)   # only register info should be in here

    def test_04(self):
        "test _read_stacktrace()"
        with open(self.tmpfn, "w") as out_fp:
            out_fp.write("OS|Linux|0.0.0 sys info...\n")
            out_fp.write("CPU|amd64|more info|8\n")
            out_fp.write("GPU|||\n")
            out_fp.write("Crash|SIGSEGV|0x7fff27aaeff8|0\n")
            out_fp.write("Module|firefox||firefox|a|0x1|0x1|1\n")
            out_fp.write("Module|firefox||firefox|a|0x1|0x2|1\n")
            out_fp.write("Module|firefox||firefox|a|0x1|0x3|1\n")
            out_fp.write("  \n")
            out_fp.write("\n")
            out_fp.write("0|0|blah|foo|a/bar.c|123|0x0\n")
            out_fp.write("0|1|blat|foo|a/bar.c|223|0x0\n")
            out_fp.write("0|2|blas|foo|a/bar.c|423|0x0\n")
            out_fp.write("0|3|blas|foo|a/bar.c|423|0x0\n")
            out_fp.write("1|0|libpthread-2.23.so||||0xd360\n")
            out_fp.write("1|1|swrast_dri.so||||0x7237f3\n")
            out_fp.write("1|2|libplds4.so|_fini|||0x163\n")
            out_fp.write("2|0|swrast_dri.so||||0x723657\n")
            out_fp.write("2|1|libpthread-2.23.so||||0x76ba\n")
            out_fp.write("2|3|libc-2.23.so||||0x1073dd\n\n")

        mdp = MinidumpParser(self.tmpdir)
        mdp.symbols_path = self.tmpdir  # usually set internally
        md_lines = list()
        with tempfile.TemporaryFile() as log_fp:
            mdp._read_stacktrace(self.tmpfn, log_fp)  # pylint: disable=protected-access
            log_fp.seek(0)
            md_lines = log_fp.readlines()
        self.assertEqual(len(md_lines), 9)  # only the interesting stack info should be in here
        self.assertTrue(md_lines[-1].startswith(b"WARNING: Hit line output limit!"))
        self.assertTrue(md_lines[-2].startswith(b"0|3|"))

    def test_05(self):
        "test process_minidumps() scan_path does not exist"
        process_minidumps("blah", "symbols_path", self.lgr.create)
        self.assertEqual(self.lgr.count, 0)

    def test_06(self):
        "test process_minidumps() empty scan_path (no dmps)"
        process_minidumps(self.tmpdir, "symbols_path", self.lgr.create)
        self.assertEqual(self.lgr.count, 0)

    def test_07(self):
        "test process_minidumps() symbols_path does not exist"
        with open(os.path.join(self.tmpdir, "dummy.dmp"), "w"):
            pass
        process_minidumps(self.tmpdir, "symbols_path", self.lgr.create)
        self.assertEqual(self.lgr.count, 0)

    def test_08(self):
        "test process_minidumps() with missing mdsw"
        test_bin = MinidumpParser.MDSW_BIN
        try:
            MinidumpParser.MDSW_BIN = "fake_bin"
            with open(os.path.join(self.tmpdir, "dummy.dmp"), "w"):
                pass
            process_minidumps(self.tmpdir, self.tmpdir, self.lgr.create)
            self.assertEqual(self.lgr.count, 0)
        finally:
            MinidumpParser.MDSW_BIN = test_bin

    def test_09(self):
        "test process_minidumps() with dmp files"
        with open(os.path.join(self.tmpdir, "dummy.dmp"), "w") as _:
            pass
        with open(os.path.join(self.tmpdir, "dummy.txt"), "w") as _:
            pass
        with open(os.path.join(self.tmpdir, "test.dmp"), "w") as out_fp:
            out_fp.write("Crash reason:  SIGSEGV\n")
            out_fp.write("Crash address: 0x0\n")
            out_fp.write("Thread 0 (crashed)\n")
            out_fp.write(" 0  libxul.so + 0x123456788\n")
            out_fp.write("    rax = 0xe5423423423fffe8   rdx = 0x0000000000000000\n")
            out_fp.write("OS|Linux|0.0.0 sys info...\n")
            out_fp.write("Crash|SIGSEGV|0x7fff27aaeff8|0\n")
            out_fp.write("0|0|blah|foo|a/bar.c|123|0x0\n")
        process_minidumps(self.tmpdir, self.tmpdir, self.lgr.create)
        self.assertEqual(self.lgr.count, 2)
