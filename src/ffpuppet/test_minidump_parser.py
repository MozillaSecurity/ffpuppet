# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet minidump parser tests"""

from json import dumps
from pathlib import Path
from subprocess import CompletedProcess
from sys import executable

from pytest import mark

from .minidump_parser import MinidumpParser, process_minidumps

MD_UNSYMBOLIZED = {
    "crash_info": {
        "address": "0x00007ffe4e09af8d",
        "crashing_thread": 0,
        "type": "EXCEPTION_BREAKPOINT",
    },
    "crashing_thread": {
        "frame_count": 49,
        "frames": [
            {
                "file": None,
                "frame": 0,
                "function": None,
                "function_offset": None,
                "line": None,
                "module": "xul.dll",
                "registers": {"r10": "0x0"},
            },
        ],
    },
    "system_info": {
        "cpu_arch": "amd64",
        "cpu_count": 8,
        "cpu_info": "family 6 model 70 stepping 1",
        "os": "Windows NT",
        "os_ver": "10.0.19044",
    },
}


@mark.parametrize(
    "symbols",
    [
        # use local path
        True,
        # use url
        False,
    ],
)
def test_minidump_parser_01(mocker, tmp_path, symbols):
    """test MinidumpParser._cmd()"""
    mocker.patch.object(MinidumpParser, "MDSW_BIN", "minidump-stackwalk")
    with MinidumpParser(symbols=tmp_path if symbols else None) as parser:
        assert parser
        # pylint: disable=protected-access
        cmd = parser._cmd(tmp_path)
        assert cmd
        assert "minidump-stackwalk" in cmd
        if symbols:
            assert "--symbols-path" in cmd
        else:
            assert "--symbols-url" in cmd


@mark.parametrize(
    "code, token, timeout",
    [
        # success
        (f"print('{dumps(MD_UNSYMBOLIZED)}')", "xul.dll", 60),
        # mdsw failed
        ("exit(1)", "minidump-stackwalk failed", 60),
        # invalid json
        ("print('bad,json')", "json decode error", 60),
        # mdsw hang
        ("import time;time.sleep(10)", "minidump-stackwalk timeout", 0),
    ],
)
def test_minidump_parser_02(mocker, code, token, timeout):
    """test MinidumpParser.create_log()"""
    mocker.patch.object(MinidumpParser, "_cmd", return_value=[executable, "-c", code])
    with MinidumpParser() as parser:
        # pylint: disable=protected-access
        assert parser._storage.is_dir()
        output = parser.create_log(Path("foo.dmp"), "minidump_00.txt", timeout=timeout)
        assert output
        assert output.name == "minidump_00.txt"
        assert output.is_file()
        assert token in output.read_text()
    assert not output.is_file()


def test_minidump_parser_03(tmp_path):
    """test MinidumpParser._fmt_output() - un-symbolized"""
    with (tmp_path / "out.txt").open("w+b") as ofp:
        # pylint: disable=protected-access
        MinidumpParser._fmt_output(MD_UNSYMBOLIZED, ofp, limit=2)
        ofp.seek(0)
        formatted = ofp.read().strip().decode().split("\n")
    assert len(formatted) == 5
    assert formatted[0] == "r10 = 0x0"
    assert formatted[1] == "OS|Windows NT|10.0.19044"
    assert formatted[2] == "CPU|amd64|family 6 model 70 stepping 1|8"
    assert formatted[3] == "Crash|EXCEPTION_BREAKPOINT|0x00007ffe4e09af8d|0"
    assert formatted[4] == "0|0|xul.dll||||"


def test_minidump_parser_04(tmp_path):
    """test MinidumpParser._fmt_output() - symbolized"""
    data = {
        "crash_info": {
            "address": "0x00007ffe4e09af8d",
            "crashing_thread": 0,
            "type": "EXCEPTION_BREAKPOINT",
        },
        "crashing_thread": {
            "frames": [
                {
                    "file": "file0.cpp",
                    "frame": 0,
                    "function": "function00()",
                    "function_offset": "0x00000000000001ed",
                    "line": 47,
                    "module": "xul.dll",
                    "registers": {
                        "r10": "0x12345678",
                        "r11": "0x0badf00d",
                        "r12": "0x00000000",
                        "r13": "0x000000dceebfc2e8",
                    },
                },
                {
                    "file": "file1.cpp",
                    "frame": 1,
                    "function": "function01()",
                    "function_offset": "0x00000000000001bb",
                    "line": 210,
                    "module": "xul.dll",
                },
                {
                    "file": "file2.cpp",
                    "frame": 2,
                    "function": "function02()",
                    "function_offset": "0x0000000000000123",
                    "line": 123,
                    "module": "xul.dll",
                },
            ],
        },
        "system_info": {
            "cpu_arch": "amd64",
            "cpu_count": 8,
            "cpu_info": "family 6 model 70 stepping 1",
            "os": "Windows NT",
            "os_ver": "10.0.19044",
        },
    }
    with (tmp_path / "out.txt").open("w+b") as ofp:
        # pylint: disable=protected-access
        MinidumpParser._fmt_output(data, ofp, limit=2)
        ofp.seek(0)
        formatted = ofp.read().strip().decode().split("\n")
    assert len(formatted) == 8
    assert formatted[0] == "r10 = 0x12345678\tr11 = 0x0badf00d\tr12 = 0x00000000"
    assert formatted[1] == "r13 = 0x000000dceebfc2e8"
    assert formatted[2] == "OS|Windows NT|10.0.19044"
    assert formatted[3] == "CPU|amd64|family 6 model 70 stepping 1|8"
    assert formatted[4] == "Crash|EXCEPTION_BREAKPOINT|0x00007ffe4e09af8d|0"
    assert formatted[5] == "0|0|xul.dll|function00()|file0.cpp|47|0x1ed"
    assert formatted[6] == "0|1|xul.dll|function01()|file1.cpp|210|0x1bb"
    assert formatted[7] == "WARNING: Hit stack size output limit!"


@mark.parametrize(
    "call_result, mdsw_bin, result",
    [
        # minidump-stackwalk is available
        (
            (CompletedProcess([], 0, stdout=b"minidump-stackwalk 0.17.0\n"),),
            "minidump-stackwalk",
            True,
        ),
        # minidump-stackwalk is matches minimum version
        (
            (CompletedProcess([], 0, stdout=b"minidump-stackwalk 0.15.2\n"),),
            "minidump-stackwalk",
            True,
        ),
        # minidump-stackwalk is out-of-date
        (
            (CompletedProcess([], 0, stdout=b"minidump-stackwalk 0.10.0\n"),),
            "minidump-stackwalk",
            False,
        ),
        # minidump-stackwalk is out-of-date
        (
            (CompletedProcess([], 0, stdout=b"minidump-stackwalk 0.15.1\n"),),
            "minidump-stackwalk",
            False,
        ),
        # minidump-stackwalk is bad version
        (
            (CompletedProcess([], 0, stdout=b"minidump-stackwalk badversion\n"),),
            "minidump-stackwalk",
            False,
        ),
        # minidump-stackwalk is not available
        (OSError("test"), "minidump-stackwalk", False),
        # minidump-stackwalk not installed
        (None, None, False),
    ],
)
def test_minidump_parser_05(mocker, call_result, mdsw_bin, result):
    """test MinidumpParser.mdsw_available()"""
    mocker.patch("ffpuppet.minidump_parser.run", side_effect=call_result)
    mocker.patch.object(MinidumpParser, "MDSW_BIN", mdsw_bin)
    assert (
        MinidumpParser.mdsw_available(force_check=True, min_version="0.15.2") == result
    )


def test_process_minidumps_01(mocker, tmp_path):
    """test process_minidumps()"""
    fake_mdp = mocker.patch("ffpuppet.minidump_parser.MinidumpParser", autospec=True)
    fake_mdp.mdsw_available.return_value = False
    assert not any(process_minidumps(tmp_path, tmp_path))


def test_process_minidumps_02(mocker, tmp_path):
    """test process_minidumps()"""
    mocker.patch(
        "ffpuppet.minidump_parser.MinidumpParser.mdsw_available", autospec=True
    )
    mocker.patch(
        "ffpuppet.minidump_parser.MinidumpParser.create_log",
        autospec=True,
        return_value=tmp_path / "minidump_00.txt",
    )
    (tmp_path / "foo.dmp").touch()
    logs = list(process_minidumps(tmp_path, tmp_path / "syms"))
    assert logs
    assert logs[0].name == "minidump_00.txt"
