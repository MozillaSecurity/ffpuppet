# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet debugger.py tests"""
from pytest import raises

from .debugger import (
    Debugger,
    DebuggerError,
    GdbDebugger,
    RrDebugger,
    ValgrindDebugger,
    load_debugger,
)


def test_gdb_debugger(mocker):
    """test GdbDebugger()"""
    check_output = mocker.patch("ffpuppet.debugger.check_output", autospec=True)
    debugger = GdbDebugger()
    assert debugger.args()
    assert not debugger.env()
    debugger.version_check()
    check_output.side_effect = OSError()
    with raises(DebuggerError, match="Please install GDB"):
        debugger.version_check()


def test_rr_debugger(mocker, tmp_path):
    """test RrDebugger()"""
    check_output = mocker.patch("ffpuppet.debugger.check_output", autospec=True)
    mocker.patch("ffpuppet.debugger.getenv", autospec=True, return_value="1")
    debugger = RrDebugger()
    debugger.log_path = tmp_path
    assert debugger.args()
    assert debugger.env()
    debugger.version_check()
    check_output.side_effect = OSError()
    with raises(DebuggerError, match="Please install rr"):
        debugger.version_check()


def test_valgrind_debugger(mocker, tmp_path):
    """test ValgrindDebugger()"""
    supp_file = tmp_path / "test.supp"
    mocker.patch("ffpuppet.debugger.getenv", autospec=True, return_value=str(supp_file))
    check_output = mocker.patch(
        "ffpuppet.debugger.check_output",
        autospec=True,
        return_value=b"valgrind-99.25.0",
    )
    debugger = ValgrindDebugger()
    debugger.log_path = tmp_path
    debugger.log_prefix = "foo"
    with raises(OSError, match="Missing Valgrind suppressions"):
        debugger.args()
    supp_file.touch()
    assert debugger.args()
    assert debugger.env()
    debugger.version_check()
    # git version
    check_output.return_value = b"valgrind-99.99.3-GIT"
    debugger.version_check()
    # unsupported version
    check_output.return_value = b"valgrind-1.99.3"
    with raises(DebuggerError, match="Valgrind >= 3.14 is required"):
        debugger.version_check()
    # not installed
    check_output.side_effect = OSError()
    with raises(DebuggerError, match="Please install Valgrind"):
        debugger.version_check()


def test_load_debugger(mocker):
    """test load_debugger()"""
    fake_debugger = mocker.Mock(spec_set=Debugger)
    mocker.patch("ffpuppet.debugger.DEBUGGERS", {"fake": fake_debugger})
    with raises(DebuggerError, match="Unsupported debugger"):
        load_debugger("missing")
    assert load_debugger("fake")
    assert fake_debugger.version_check.call_count == 1
