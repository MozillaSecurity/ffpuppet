# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""ffpuppet minidump parser tests"""

from copy import deepcopy
from json import dumps
from pathlib import Path
from subprocess import CompletedProcess
from sys import executable

from pytest import mark

from .minidump_parser import MinidumpParser

MD_BASE_AMD64_WIN = {
    "crash_info": {
        "address": "0x00007ffe4e09af8d",
        "type": "EXCEPTION_BREAKPOINT",
    },
    "system_info": {
        "cpu_arch": "amd64",
        "cpu_count": 8,
        "cpu_info": "family 6 model 70 stepping 1",
        "os": "Windows NT",
        "os_ver": "10.0.19044",
    },
}

MD_UNSYMBOLIZED_AMD64_WIN = deepcopy(MD_BASE_AMD64_WIN)
MD_UNSYMBOLIZED_AMD64_WIN["crash_info"]["crashing_thread"] = 0
MD_UNSYMBOLIZED_AMD64_WIN["crashing_thread"] = {
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
}

MD_UNSYMBOLIZED_ARM64_MAC = {
    "crash_info": {
        "address": "0x0000000000000000",
        "crashing_thread": 0,
        "type": "EXC_BAD_ACCESS / KERN_INVALID_ADDRESS",
    },
    "crashing_thread": {
        "frame_count": 32,
        "frames": [
            {
                "file": None,
                "frame": 0,
                "function": None,
                "function_offset": None,
                "line": None,
                "module": "XUL",
                "registers": {
                    "x1": "0x0000000000000001",
                    "x2": "0x0000000000000002",
                },
            },
        ],
    },
    "system_info": {
        "cpu_arch": "arm64",
        "cpu_count": 8,
        "cpu_info": None,
        "os": "Mac OS X",
        "os_ver": "13.0.1 22A400",
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
        (f"print('{dumps(MD_UNSYMBOLIZED_AMD64_WIN)}')", "xul.dll", 60),
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
        assert parser._storage.is_dir()
        output = parser.create_log(Path("foo.dmp"), "minidump_00.txt", timeout=timeout)
        assert output
        assert output.name == "minidump_00.txt"
        assert output.is_file()
        assert token in output.read_text()
    assert not output.is_file()


@mark.parametrize(
    "data, reg, operating_system, cpu, crash, frame",
    [
        # Windows - x86_64 / AMD64
        (
            MD_UNSYMBOLIZED_AMD64_WIN,
            "r10 = 0x0",
            "OS|Windows NT|10.0.19044",
            "CPU|amd64|family 6 model 70 stepping 1|8",
            "Crash|EXCEPTION_BREAKPOINT|0x00007ffe4e09af8d|0",
            "0|0|xul.dll||||",
        ),
        # MacOS - ARM64
        (
            MD_UNSYMBOLIZED_ARM64_MAC,
            " x1 = 0x0000000000000001\t x2 = 0x0000000000000002",
            "OS|Mac OS X|13.0.1 22A400",
            "CPU|arm64||8",
            "Crash|EXC_BAD_ACCESS / KERN_INVALID_ADDRESS|0x0000000000000000|0",
            "0|0|XUL||||",
        ),
    ],
)
def test_minidump_parser_03(tmp_path, data, reg, operating_system, cpu, crash, frame):
    """test MinidumpParser._fmt_output() - un-symbolized"""
    with (tmp_path / "out.txt").open("w+b") as ofp:
        MinidumpParser._fmt_output(data, ofp, {}, limit=2)
        ofp.seek(0)
        formatted = ofp.read().rstrip().decode().split("\n")
    assert len(formatted) == 5
    assert formatted[0] == reg
    assert formatted[1] == operating_system
    assert formatted[2] == cpu
    assert formatted[3] == crash
    assert formatted[4] == frame


def test_minidump_parser_04(tmp_path):
    """test MinidumpParser._fmt_output() - symbolized"""
    data = deepcopy(MD_BASE_AMD64_WIN)
    data["crash_info"]["crashing_thread"] = 0
    data["crashing_thread"] = {
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
    }

    with (tmp_path / "out.txt").open("w+b") as ofp:
        MinidumpParser._fmt_output(data, ofp, {"metadata": "foo"}, limit=2)
        ofp.seek(0)
        formatted = ofp.read().rstrip().decode().split("\n")
    assert len(formatted) == 9
    assert formatted[0] == "r10 = 0x12345678\tr11 = 0x0badf00d\tr12 = 0x00000000"
    assert formatted[1] == "r13 = 0x000000dceebfc2e8"
    assert formatted[2] == "metadata|foo"
    assert formatted[3] == "OS|Windows NT|10.0.19044"
    assert formatted[4] == "CPU|amd64|family 6 model 70 stepping 1|8"
    assert formatted[5] == "Crash|EXCEPTION_BREAKPOINT|0x00007ffe4e09af8d|0"
    assert formatted[6] == "0|0|xul.dll|function00()|file0.cpp|47|0x1ed"
    assert formatted[7] == "0|1|xul.dll|function01()|file1.cpp|210|0x1bb"
    assert formatted[8] == "WARNING: Hit stack size output limit!"


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
    assert MinidumpParser.mdsw_available(min_version="0.15.2") == result


def test_minidump_parser_06(tmp_path):
    """test MinidumpParser.dmp_files()"""
    # empty minidump path
    assert not MinidumpParser.dmp_files(tmp_path)
    # find single dump file
    (tmp_path / "a.dmp").write_text("a")
    assert tmp_path / "a.dmp" in MinidumpParser.dmp_files(tmp_path)
    # find multiple dump files
    (tmp_path / "b.dmp").write_text("b")
    (tmp_path / "c.dmp").write_text("c")
    assert len(MinidumpParser.dmp_files(tmp_path)) == 3
    # add .extra file to prioritize .dmp file
    (tmp_path / "b.extra").write_text('{"MozCrashReason":"foo"}')
    assert MinidumpParser.dmp_files(tmp_path)[0] == (tmp_path / "b.dmp")
    (tmp_path / "b.extra").unlink()
    # add .extra file to prioritize .dmp file
    (tmp_path / "c-browser.dmp").write_text("c-browser")
    (tmp_path / "c.extra").write_text('{"additional_minidumps":"browser"}')
    assert MinidumpParser.dmp_files(tmp_path)[0] == (tmp_path / "c-browser.dmp")
    # corrupt (bad json) .extra file
    (tmp_path / "c.extra").write_text("!")
    assert MinidumpParser.dmp_files(tmp_path)


def test_minidump_parser_missing_crashing_thread(tmp_path):
    """test MinidumpParser._fmt_output() - missing crashing thread"""
    with (tmp_path / "out.txt").open("w+b") as ofp:
        MinidumpParser._fmt_output(MD_BASE_AMD64_WIN, ofp, {})
        ofp.seek(0)
        formatted = ofp.read().rstrip().decode().split("\n")
    assert len(formatted) == 3
    assert formatted[0] == "OS|Windows NT|10.0.19044"
    assert formatted[1] == "CPU|amd64|family 6 model 70 stepping 1|8"
    assert formatted[2] == "Crash|EXCEPTION_BREAKPOINT|0x00007ffe4e09af8d|?"


def test_minidump_parser_metadata(tmp_path):
    """test MinidumpParser._metadata()"""
    # collect metadata from .extra file
    (tmp_path / "out.extra").write_text(dumps({"a": "1", "b": "2", "c": "3"}))
    result = MinidumpParser._metadata(tmp_path / "out.dmp", ("a", "c"))
    assert "a" in result
    assert "b" not in result
    assert "c" in result
    # invalid .extra file
    (tmp_path / "out.extra").write_text("!")
    assert not MinidumpParser._metadata(tmp_path / "out.dmp", ("a", "c"))
