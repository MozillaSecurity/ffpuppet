# coding=utf-8
"""ffpuppet main.py tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import pytest

from .main import dump_to_console, main, parse_args


def test_main_01(mocker, tmp_path):
    """test main() with FFPuppet exit"""
    fake_ffp = mocker.patch("ffpuppet.main.FFPuppet", autospec=True)
    fake_ffp.return_value.get_pid.return_value = 12345
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.profile = str(tmp_path)
    fake_ffp.return_value.reason = "EXITED"
    out_logs = tmp_path / "logs"
    out_logs.mkdir()
    prefs = tmp_path / "prefs.js"
    prefs.touch()
    main(["fake_bin", "-d", "-l", str(out_logs), "-p", str(prefs)])
    assert fake_ffp.return_value.add_abort_token.call_count == 0
    assert fake_ffp.return_value.get_pid.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1
    assert fake_ffp.return_value.save_logs.call_count == 1
    assert fake_ffp.return_value.clean_up.call_count == 1

def test_main_02(mocker, tmp_path):
    """test main() with user exit"""
    fake_ffp = mocker.patch("ffpuppet.main.FFPuppet", autospec=True)
    fake_ffp.return_value.get_pid.return_value = 12345
    fake_ffp.return_value.profile = str(tmp_path)
    fake_ffp.return_value.reason = "CLOSED"
    fake_time = mocker.patch("ffpuppet.main.time", autospec=True)
    fake_time.sleep.side_effect = KeyboardInterrupt
    out_logs = tmp_path / "logs"
    out_logs.mkdir()
    main(["fake_bin", "-d", "-a", "token", "-v"])
    assert fake_ffp.return_value.add_abort_token.call_count == 1
    assert fake_ffp.return_value.get_pid.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1
    assert fake_ffp.return_value.save_logs.call_count == 1
    assert fake_ffp.return_value.clean_up.call_count == 1

def test_parse_args_01(tmp_path):
    """test parse_args()"""
    with pytest.raises(SystemExit):
        parse_args(["-h"])
    with pytest.raises(SystemExit):
        parse_args(["fake_bin", "-p", str(tmp_path / "missing")])
    with pytest.raises(SystemExit):
        parse_args(["fake_bin", "-e", str(tmp_path / "missing")])
    with pytest.raises(SystemExit):
        parse_args(["fake_bin", "--gdb", "--valgrind"])
    with pytest.raises(SystemExit):
        parse_args(["fake_bin", "--rr"])
    (tmp_path / "junk.log").touch()
    with pytest.raises(SystemExit):
        parse_args(["fake_bin", "--log", str(tmp_path)])
    assert parse_args(["fake_bin"])

def test_dump_to_console_01(tmp_path):
    """test dump_to_console()"""
    # call with no logs
    assert not dump_to_console(str(tmp_path), False)
    # call with dummy logs
    (tmp_path / "log_stderr.txt").write_bytes(b"dummy-stderr")
    (tmp_path / "log_stdout.txt").write_bytes(b"dummy-stdout")
    output = dump_to_console(str(tmp_path), "/fake/save/path")
    assert "Full logs available here" not in output
    assert "Dumping 'log_stderr.txt'" in output
    assert "dummy-stderr" in output
    assert "Dumping 'log_stdout.txt'" in output
    assert "dummy-stdout" in output
    # truncate log
    with (tmp_path / "log_stdout.txt").open("wb") as log_fp:
        log_fp.write(b"dummy-stdout")
        for _ in range(1024):
            log_fp.write(b"test")
    output = dump_to_console(str(tmp_path), "/fake/save/path", log_quota=100)
    assert "Full logs available here" in output
    assert "Dumping 'log_stderr.txt'" in output
    assert "dummy-stderr" in output
    assert "Dumping 'log_stdout.txt'" in output
    assert "dummy-stdout" not in output
