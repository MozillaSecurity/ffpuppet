# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet minidump parser tests"""

from json import JSONDecodeError
from subprocess import CalledProcessError, TimeoutExpired

from pytest import mark, raises

from .minidump_parser import MinidumpParser, MinidumpStackwalkFailure, process_minidumps


@mark.parametrize(
    "run_return, symbols, result",
    [
        # succeeded - with symbols
        (None, True, True),
        # succeeded - without symbols
        (None, False, True),
        # failed - parse hung
        ((TimeoutExpired(["test"], 0.0),), True, False),
        # failed - json parse error
        ((CalledProcessError(1, ["test"]),), True, False),
    ],
)
def test_minidump_parser_01(mocker, tmp_path, run_return, symbols, result):
    """test MinidumpParser.to_json()"""
    mocker.patch("ffpuppet.minidump_parser.run", autospec=True, side_effect=run_return)
    parser = MinidumpParser(symbols_path=tmp_path if symbols else None)
    if result:
        assert parser.to_json(tmp_path, str(tmp_path)).is_file()
    else:
        with raises(MinidumpStackwalkFailure):
            parser.to_json(tmp_path, str(tmp_path))


def test_minidump_parser_02(tmp_path):
    """test MinidumpParser.format_output() - un-symbolized"""
    data = {
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
    with (tmp_path / "out.txt").open("w+b") as ofp:
        MinidumpParser.format_output(data, ofp, limit=2)
        ofp.seek(0)
        formatted = ofp.read().strip().decode().split("\n")
    assert len(formatted) == 5
    assert formatted[0] == "r10 = 0x0"
    assert formatted[1] == "OS|Windows NT|10.0.19044"
    assert formatted[2] == "CPU|amd64|family 6 model 70 stepping 1|8"
    assert formatted[3] == "Crash|EXCEPTION_BREAKPOINT|0x00007ffe4e09af8d|0"
    assert formatted[4] == "0|0|xul.dll||||"


def test_minidump_parser_03(tmp_path):
    """test MinidumpParser.format_output() - symbolized"""
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
        MinidumpParser.format_output(data, ofp, limit=2)
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
    "call_result, result",
    [
        # minidump-stackwalk is available
        ((0,), True),
        # minidump-stackwalk is not available
        (OSError("test"), False),
    ],
)
def test_minidump_parser_04(mocker, call_result, result):
    """test MinidumpParser.mdsw_available()"""
    mocker.patch("ffpuppet.minidump_parser.call", side_effect=call_result)
    assert MinidumpParser.mdsw_available(force_check=True) == result


@mark.parametrize(
    "mdsw, syms, md_json_data, raised",
    [
        # loading minidump files - success
        (True, True, ["{}"], False),
        # loading minidump files - JSONDecodeError
        (True, True, ["bad,json"], True),
        # loading minidump files - zero byte minidumps
        (True, True, ["", "{}", ""], False),
        # symbols_path does not exist
        (True, False, ["{}"], False),
        # test minidump-stackwalk not available
        (False, False, [], False),
    ],
)
def test_process_minidumps_01(mocker, tmp_path, mdsw, syms, md_json_data, raised):
    """test process_minidumps()"""
    fake_mdp = mocker.patch("ffpuppet.minidump_parser.MinidumpParser", autospec=True)
    fake_mdp.mdsw_available.return_value = mdsw

    to_json_results = []
    for count, md_data in enumerate(md_json_data):
        md_file = tmp_path / f"minidump{count:02d}.dmp"
        md_file.write_text(md_data)
        if md_data:
            to_json_results.append(md_file)
    fake_mdp.return_value.to_json.side_effect = to_json_results

    try:
        process_minidumps(
            tmp_path,
            tmp_path if syms else tmp_path / "missing",
            mocker.Mock(),
            working_path=str(tmp_path),
        )
    except JSONDecodeError:
        assert raised
    else:
        assert not raised

    assert fake_mdp.mdsw_available.call_count == 1
    if mdsw:
        assert fake_mdp.return_value.to_json.call_count == 1
        assert fake_mdp.return_value.format_output.call_count == (0 if raised else 1)
