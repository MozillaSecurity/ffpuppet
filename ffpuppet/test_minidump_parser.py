# coding=utf-8
"""ffpuppet minidump parser tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

from os import SEEK_END

from pytest import mark, raises

from .minidump_parser import MinidumpParser, process_minidumps


def test_minidump_parser_01(mocker, tmp_path):
    """test MinidumpParser() with missing and empty scan path"""
    with raises(IOError):
        MinidumpParser("/path/does/not/exist/")
    mdp = MinidumpParser(str(tmp_path))
    assert not mdp.md_files
    callback = mocker.Mock()
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
    working = tmp_path / "working"
    working.mkdir()
    mocker.patch("ffpuppet.minidump_parser.call", autospec=True, return_value=0)
    mdp = MinidumpParser(str(md_path), record_failures=False, working_path=str(working))
    assert len(mdp.md_files) == 1
    mdp.collect_logs(callback, str(log_path))
    assert callback.return_value.tell.call_count == 1
    assert callback.return_value.write.call_count == 1
    assert not any(working.iterdir())


def test_minidump_parser_03(mocker, tmp_path):
    """test MinidumpParser._read_registers()"""

    def fake_call_mdsw(_, out_fp):
        out_fp.write(
            b"Crash reason:  SIGSEGV\n"
            b"Crash address: 0x0\n"
            b"Process uptime: not available\n\n"
            b"Thread 0 (crashed)\n"
            b" 0  libxul.so + 0x123456788\n"
            b"    rax = 0xe5423423423fffe8   rdx = 0x0000000000000000\n"
            b"    rcx = 0x0000000000000000   rbx = 0xe54234234233e5e5\n"
            b"    rsi = 0x0000000000000000   rdi = 0x00007fedc31fe308\n"
            b"    rbp = 0x00007fffca0dab00   rsp = 0x00007fffca0daad0\n"
            b"     r8 = 0x0000000000000000    r9 = 0x0000000000000008\n"
            b"    r10 = 0xffff00ffffffffff   r11 = 0xffffff00ffffffff\n"
            b"    r12 = 0x0000743564566308   r13 = 0x00007fedce9d8000\n"
            b"    r14 = 0x0000000000000001   r15 = 0x0000000000000000\n"
            b"    rip = 0x0000745666666ac\n"
            b"    Found by: given as instruction pointer in context\n"
            b" 1  libxul.so + 0x1f4361c]\n\n"
        )
        out_fp.seek(0)

    mocker.patch.object(MinidumpParser, "_call_mdsw", side_effect=fake_call_mdsw)
    mdp = MinidumpParser(str(tmp_path))
    md_lines = list()
    with (tmp_path / "md_out").open("w+b") as log_fp:
        mdp._read_registers("fake.dmp", log_fp)
        log_fp.seek(0)
        for line in log_fp:
            if b"=" not in line:
                break
            md_lines.append(line)
    assert len(md_lines) == 9  # only register info should be in here


def test_minidump_parser_04(mocker, tmp_path):
    """test MinidumpParser._read_stacktrace()"""

    def fake_call_mdsw(_, out_fp, extra_flags=None):  # pylint: disable=unused-argument
        out_fp.write(
            b"OS|Linux|0.0.0 sys info...\n"
            b"CPU|amd64|more info|8\n"
            b"GPU|||\n"
            b"Crash|SIGSEGV|0x7fff27aaeff8|0\n"
            b"Module|firefox||firefox|a|0x1|0x1|1\n"
            b"Module|firefox||firefox|a|0x1|0x2|1\n"
            b"Module|firefox||firefox|a|0x1|0x3|1\n"
            b"  \n\n"
            b"0|0|blah|foo|a/bar.c|123|0x0\n"
            b"0|1|blat|foo|a/bar.c|223|0x0\n"
            b"junk\n"
            b"0|2|blas|foo|a/bar.c|423|0x0\n"
            b"0|3|blas|foo|a/bar.c|423|0x0\n"
            b"1|0|libpthread-2.23.so||||0xd360\n"
            b"junk\n"
            b"1|1|swrast_dri.so||||0x7237f3\n"
            b"1|2|libplds4.so|_fini|||0x163\n"
            b"2|0|swrast_dri.so||||0x723657\n"
            b"junk\n"
            b"2|1|libpthread-2.23.so||||0x76ba\n"
            b"2|3|libc-2.23.so||||0x1073dd\n\n"
        )
        out_fp.seek(0)

    mocker.patch.object(MinidumpParser, "_call_mdsw", side_effect=fake_call_mdsw)
    mdp = MinidumpParser(str(tmp_path))
    with (tmp_path / "md_out").open("w+b") as log_fp:
        mdp._read_stacktrace("fake.dmp", log_fp, limit=7)
        log_fp.seek(0)
        md_lines = log_fp.readlines()
    assert len(md_lines) == 8  # only the interesting stack info should be in here
    assert md_lines[-1].startswith(b"WARNING: Hit stack size output limit!")
    assert md_lines[-2].startswith(b"0|2|")
    # test raw_fp set
    with (tmp_path / "md_out").open("w+b") as log_fp:
        with (tmp_path / "md_raw").open("w+b") as raw_fp:
            mdp._read_stacktrace("fake.dmp", log_fp, raw_fp=raw_fp)
            raw_size = raw_fp.tell()
        log_fp.seek(0)
        md_lines = log_fp.readlines()
    with (tmp_path / "md_out").open("w+b") as log_fp:
        fake_call_mdsw("x", log_fp)
        log_fp.seek(0, SEEK_END)
        assert raw_size == log_fp.tell()
    assert len(md_lines) == 8
    assert md_lines[-1].startswith(b"0|3|")


def test_minidump_parser_05(mocker, tmp_path):
    """test MinidumpParser.collect_logs()"""
    (tmp_path / "dummy.dmp").touch()
    (tmp_path / "dummy.txt").touch()
    (tmp_path / "test.dmp").write_text(
        "Crash reason:  SIGSEGV\n"
        "Crash address: 0x0\n"
        "Thread 0 (crashed)\n"
        " 0  libxul.so + 0x123456788\n"
        "    rax = 0xe5423423423fffe8   rdx = 0x0000000000000000\n"
        "OS|Linux|0.0.0 sys info...\n"
        "Crash|SIGSEGV|0x7fff27aaeff8|0\n"
        "0|0|blah|foo|a/bar.c|123|0x0\n"
    )
    mocker.patch("ffpuppet.minidump_parser.call", autospec=True, return_value=0)
    mdp = MinidumpParser(str(tmp_path))
    callback = mocker.mock_open()
    callback.return_value.tell.return_value = 0
    mdp.collect_logs(callback, str(tmp_path))
    assert callback.call_count == 2


@mark.parametrize(
    "call_result, record, stat_result, log_count, dmp_exists",
    [
        # minidump_stackwalk succeeded - no failures
        (0, False, None, 0, False),
        # minidump_stackwalk failed - don't record mdsw error
        (1, False, 123, 0, False),
        # minidump_stackwalk failed - record mdsw error results
        (1, True, 123, 3, True),
        # minidump_stackwalk failed - stat raises
        (1, False, OSError, 0, False),
    ],
)
def test_minidump_parser_06(
    mocker, tmp_path, call_result, record, stat_result, log_count, dmp_exists
):
    """test MinidumpParser._call_mdsw()"""
    fake_call = mocker.patch(
        "ffpuppet.minidump_parser.call", autospec=True, return_value=call_result
    )
    # create path for error reports
    working = tmp_path / "fake_tmpd"
    working.mkdir()
    mocker.patch(
        "ffpuppet.minidump_parser.mkdtemp", autospec=True, return_value=str(working)
    )
    fake_stat = mocker.patch("ffpuppet.minidump_parser.stat", autospec=True)
    if isinstance(stat_result, int):
        fake_stat.return_value.st_size.return_value = stat_result
    else:
        fake_stat.side_effect = stat_result
    # create dmp file
    dmp_path = tmp_path / "dmps"
    dmp_path.mkdir()
    dmp_file = dmp_path / "test.dmp"
    dmp_file.write_text("fakedmp")
    # create MinidumpParser
    mdp = MinidumpParser(str(dmp_path), record_failures=record)
    mdp.symbols_path = "sympath"
    if call_result != 0:
        with raises(RuntimeError, match="MDSW Error"):
            mdp._call_mdsw(str(dmp_file), mocker.mock_open()())
    else:
        mdp._call_mdsw(str(dmp_file), mocker.mock_open()())
    assert fake_call.call_count == 1
    assert len(tuple(working.glob("**/mdsw_*.txt"))) == log_count
    assert any(working.glob("**/test.dmp")) == dmp_exists


def test_minidump_parser_07(mocker):
    """test MinidumpParser.mdsw_available()"""
    fake_call = mocker.patch(
        "ffpuppet.minidump_parser.call", autospec=True, return_value=0
    )
    assert MinidumpParser.mdsw_available()
    fake_call.side_effect = OSError
    assert not MinidumpParser.mdsw_available()


def test_process_minidumps_01(mocker, tmp_path):
    """test process_minidumps()"""
    fake_mdp = mocker.patch("ffpuppet.minidump_parser.MinidumpParser", autospec=True)
    fake_mdp.return_value.mdsw_available.return_value = True
    callback = mocker.Mock()
    # test scan_path does not exist
    process_minidumps("/missing/path/", "symbols_path", callback)
    assert fake_mdp.call_count == 0
    assert fake_mdp.return_value.mdsw_available.call_count == 0
    assert fake_mdp.return_value.collect_logs.call_count == 0
    # test empty scan_path (no .dmp files)
    fake_mdp.return_value.md_files = []
    process_minidumps(str(tmp_path), "symbols_path", callback)
    assert fake_mdp.call_count == 1
    assert fake_mdp.call_args[0][0] == str(tmp_path)
    assert fake_mdp.return_value.mdsw_available.call_count == 0
    assert fake_mdp.return_value.collect_logs.call_count == 0
    fake_mdp.reset_mock()
    # test symbols_path does not exist
    fake_mdp.return_value.md_files = [mocker.Mock()]
    process_minidumps(str(tmp_path), "symbols_path", callback)
    assert fake_mdp.return_value.mdsw_available.call_count == 1
    assert fake_mdp.return_value.collect_logs.call_count == 1
    assert fake_mdp.return_value.collect_logs.call_args[0][-1] is None
    fake_mdp.reset_mock()
    # test minidump_stackwalk not available
    fake_mdp.return_value.mdsw_available.return_value = False
    process_minidumps(str(tmp_path), str(tmp_path), callback)
    assert fake_mdp.return_value.mdsw_available.call_count == 1
    assert fake_mdp.return_value.collect_logs.call_count == 0
    fake_mdp.reset_mock()
    # test success
    fake_mdp.return_value.mdsw_available.return_value = True
    process_minidumps(str(tmp_path), str(tmp_path), callback)
    assert fake_mdp.return_value.collect_logs.call_count == 1
    assert fake_mdp.return_value.collect_logs.call_args[0][0] == callback
    assert fake_mdp.return_value.collect_logs.call_args[0][-1] == str(tmp_path)
