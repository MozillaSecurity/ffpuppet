# coding=utf-8
"""ffpuppet minidump parser tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

import os
import tempfile

import pytest

from .minidump_parser import MinidumpParser, process_minidumps


def test_minidump_parser_01(mocker, tmp_path):
    """test MinidumpParser() with missing and empty scan path"""
    with pytest.raises(IOError):
        MinidumpParser("/path/does/not/exist/")
    mdp = MinidumpParser(str(tmp_path))
    assert not mdp.dump_files
    callback = mocker.Mock()
    with pytest.raises(IOError):
        mdp.collect_logs(callback, "/path/does/not/exist/")
    assert callback.call_count == 0
    mdp.collect_logs(callback, str(tmp_path))
    assert callback.call_count == 0

def test_minidump_parser_02(mocker, tmp_path):
    """test MinidumpParser() with empty minidumps (ignore mdsw failures)"""
    md_path = tmp_path / "minidumps"
    md_path.mkdir()
    (md_path / "not_a_dmp.txt").touch()
    (md_path / "test.dmp").touch()
    callback = mocker.mock_open()
    callback.return_value.tell.return_value = 0
    log_path = tmp_path / "logs"
    log_path.mkdir()
    mdp = MinidumpParser(str(md_path), record_failures=False)
    assert len(mdp.dump_files) == 1
    mdp.collect_logs(callback, str(log_path))
    assert callback.return_value.tell.call_count == 1
    assert callback.return_value.write.call_count == 1

def test_minidump_parser_03(mocker, tmp_path):
    """test MinidumpParser._read_registers()"""
    def fake_call_mdsw(_, out_fp):
        out_fp.write(b"Crash reason:  SIGSEGV\n")
        out_fp.write(b"Crash address: 0x0\n")
        out_fp.write(b"Process uptime: not available\n\n")
        out_fp.write(b"Thread 0 (crashed)\n")
        out_fp.write(b" 0  libxul.so + 0x123456788\n")
        out_fp.write(b"    rax = 0xe5423423423fffe8   rdx = 0x0000000000000000\n")
        out_fp.write(b"    rcx = 0x0000000000000000   rbx = 0xe54234234233e5e5\n")
        out_fp.write(b"    rsi = 0x0000000000000000   rdi = 0x00007fedc31fe308\n")
        out_fp.write(b"    rbp = 0x00007fffca0dab00   rsp = 0x00007fffca0daad0\n")
        out_fp.write(b"     r8 = 0x0000000000000000    r9 = 0x0000000000000008\n")
        out_fp.write(b"    r10 = 0xffff00ffffffffff   r11 = 0xffffff00ffffffff\n")
        out_fp.write(b"    r12 = 0x0000743564566308   r13 = 0x00007fedce9d8000\n")
        out_fp.write(b"    r14 = 0x0000000000000001   r15 = 0x0000000000000000\n")
        out_fp.write(b"    rip = 0x0000745666666ac\n")
        out_fp.write(b"    Found by: given as instruction pointer in context\n")
        out_fp.write(b" 1  libxul.so + 0x1f4361c]\n\n")
        out_fp.seek(0)
    mocker.patch.object(MinidumpParser, '_call_mdsw', side_effect=fake_call_mdsw)
    mdp = MinidumpParser(str(tmp_path))
    md_lines = list()
    with tempfile.TemporaryFile() as log_fp:
        mdp._read_registers("fake.dmp", log_fp)
        log_fp.seek(0)
        for line in log_fp:  # pylint: disable=not-an-iterable
            if b"=" not in line:
                break
            md_lines.append(line)
    assert len(md_lines) == 9   # only register info should be in here

def test_minidump_parser_04(mocker, tmp_path):
    """test MinidumpParser._read_stacktrace()"""
    def fake_call_mdsw(_, out_fp, extra_flags=None):  # pylint: disable=unused-argument
        out_fp.write(b"OS|Linux|0.0.0 sys info...\n")
        out_fp.write(b"CPU|amd64|more info|8\n")
        out_fp.write(b"GPU|||\n")
        out_fp.write(b"Crash|SIGSEGV|0x7fff27aaeff8|0\n")
        out_fp.write(b"Module|firefox||firefox|a|0x1|0x1|1\n")
        out_fp.write(b"Module|firefox||firefox|a|0x1|0x2|1\n")
        out_fp.write(b"Module|firefox||firefox|a|0x1|0x3|1\n")
        out_fp.write(b"  \n\n")
        out_fp.write(b"0|0|blah|foo|a/bar.c|123|0x0\n")
        out_fp.write(b"0|1|blat|foo|a/bar.c|223|0x0\n")
        out_fp.write(b"junk\n")
        out_fp.write(b"0|2|blas|foo|a/bar.c|423|0x0\n")
        out_fp.write(b"0|3|blas|foo|a/bar.c|423|0x0\n")
        out_fp.write(b"1|0|libpthread-2.23.so||||0xd360\n")
        out_fp.write(b"junk\n")
        out_fp.write(b"1|1|swrast_dri.so||||0x7237f3\n")
        out_fp.write(b"1|2|libplds4.so|_fini|||0x163\n")
        out_fp.write(b"2|0|swrast_dri.so||||0x723657\n")
        out_fp.write(b"junk\n")
        out_fp.write(b"2|1|libpthread-2.23.so||||0x76ba\n")
        out_fp.write(b"2|3|libc-2.23.so||||0x1073dd\n\n")
        out_fp.seek(0)
    mocker.patch.object(MinidumpParser, '_call_mdsw', side_effect=fake_call_mdsw)
    mdp = MinidumpParser(str(tmp_path))
    MinidumpParser.MDSW_MAX_STACK = 7
    with tempfile.TemporaryFile() as log_fp:
        mdp._read_stacktrace("fake.dmp", log_fp)
        log_fp.seek(0)
        md_lines = log_fp.readlines()
    assert len(md_lines) == 8  # only the interesting stack info should be in here
    assert md_lines[-1].startswith(b"WARNING: Hit line output limit!")
    assert md_lines[-2].startswith(b"0|2|")
    # test raw_fp set
    MinidumpParser.MDSW_MAX_STACK = 150
    with tempfile.TemporaryFile() as log_fp, tempfile.TemporaryFile() as raw_fp:
        mdp._read_stacktrace("fake.dmp", log_fp, raw_fp=raw_fp)
        raw_size = raw_fp.tell()
        log_fp.seek(0)
        md_lines = log_fp.readlines()
    with tempfile.TemporaryFile() as log_fp:
        fake_call_mdsw("x", log_fp)
        log_fp.seek(0, os.SEEK_END)
        assert raw_size == log_fp.tell()
    assert len(md_lines) == 8
    assert md_lines[-1].startswith(b"0|3|")

def test_minidump_parser_05(mocker, tmp_path):
    """test MinidumpParser.collect_logs()"""
    (tmp_path / "dummy.dmp").touch()
    (tmp_path / "dummy.txt").touch()
    with (tmp_path / "test.dmp").open("wb") as out_fp:
        out_fp.write(b"Crash reason:  SIGSEGV\n")
        out_fp.write(b"Crash address: 0x0\n")
        out_fp.write(b"Thread 0 (crashed)\n")
        out_fp.write(b" 0  libxul.so + 0x123456788\n")
        out_fp.write(b"    rax = 0xe5423423423fffe8   rdx = 0x0000000000000000\n")
        out_fp.write(b"OS|Linux|0.0.0 sys info...\n")
        out_fp.write(b"Crash|SIGSEGV|0x7fff27aaeff8|0\n")
        out_fp.write(b"0|0|blah|foo|a/bar.c|123|0x0\n")
    fake_subproc = mocker.patch("ffpuppet.minidump_parser.subprocess", autospec=True)
    fake_subproc.call.return_value = 0
    mdp = MinidumpParser(str(tmp_path))
    callback = mocker.mock_open()
    callback.return_value.tell.return_value = 0
    mdp.collect_logs(callback, str(tmp_path))
    assert callback.call_count == 2

def test_minidump_parser_06(mocker, tmp_path):
    """test MinidumpParser._call_mdsw()"""
    fake_subproc = mocker.patch("ffpuppet.minidump_parser.subprocess", autospec=True)
    fake_subproc.call.return_value = 0
    working = (tmp_path / "fake_tmpd")
    working.mkdir()
    mocker.patch("ffpuppet.minidump_parser.tempfile.mkdtemp", return_value=str(working))
    dmp_path = (tmp_path / "dmps")
    dmp_path.mkdir()
    mdp = MinidumpParser(str(dmp_path))
    fake_file = mocker.mock_open()
    dmp_file = dmp_path / "test.dmp"
    dmp_file.touch()
    mdp._call_mdsw(str(dmp_file), fake_file())
    # test minidump_stackwalk failures
    fake_subproc.call.call_count = 0
    fake_file.return_value.seek.call_count = 0
    mdp._record_failures = True
    mdp.symbols_path = "sympath"
    fake_subproc.call.return_value = 1
    with pytest.raises(RuntimeError, match="MDSW Error"):
        mdp._call_mdsw(str(dmp_file), fake_file())
    assert fake_subproc.call.call_count == 1
    assert len(tuple(working.glob("**/mdsw_*.txt"))) == 3
    assert any(working.glob("**/test.dmp"))

def test_minidump_parser_07(mocker):
    """test MinidumpParser.mdsw_available()"""
    fake_subproc = mocker.patch("ffpuppet.minidump_parser.subprocess", autospec=True)
    fake_subproc.call.return_value = 0
    assert MinidumpParser.mdsw_available()
    fake_subproc.call.side_effect = OSError
    assert not MinidumpParser.mdsw_available()

def test_process_minidumps_01(mocker, tmp_path):
    """test process_minidumps()"""
    fake_mdp = mocker.patch("ffpuppet.minidump_parser.MinidumpParser", autospec=True)
    fake_mdp.return_value.mdsw_available.return_value = False
    # test scan_path does not exist
    process_minidumps("/missing/path/", "symbols_path", mocker.Mock())
    # test empty scan_path (no .dmp files)
    fake_mdp.return_value.dump_files = []
    process_minidumps(str(tmp_path), "symbols_path", mocker.Mock())
    # test symbols_path does not exist
    fake_mdp.return_value.dump_files = [mocker.Mock()]
    process_minidumps(str(tmp_path), "symbols_path", mocker.Mock())
    assert fake_mdp.return_value.mdsw_available.call_count == 0
    assert not fake_mdp.return_value.mdsw_available.return_value
    # test minidump_stackwalk not available
    process_minidumps(str(tmp_path), str(tmp_path), mocker.Mock())
    assert fake_mdp.return_value.mdsw_available.call_count == 1
    assert fake_mdp.return_value.collect_logs.call_count == 0
    # test success
    fake_mdp.return_value.mdsw_available.return_value = True
    process_minidumps(str(tmp_path), str(tmp_path), mocker.Mock())
    assert fake_mdp.return_value.collect_logs.call_count == 1
