# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""display.py tests"""

import sys
from subprocess import TimeoutExpired

from pytest import mark, raises

from .display import (
    DISPLAYS,
    Display,
    DisplayMode,
    HeadlessDisplay,
)

if sys.platform == "linux":
    from .display import WestonDisplay, XvfbDisplay


@mark.parametrize("mode", tuple(x for x in DisplayMode))
def test_displays(mocker, mode):
    """test Displays()"""
    if sys.platform == "linux":
        mocker.patch("ffpuppet.display.Xvfb", autospec=True)
        mocker.patch("ffpuppet.display.which", return_value="/usr/bin/weston")
        mocker.patch("ffpuppet.display.Popen", autospec=True)
        mocker.patch("ffpuppet.display.Path.exists", return_value=True)
    display = DISPLAYS[mode]()
    assert display
    try:
        if mode.name == "DEFAULT":
            assert isinstance(display, Display)
        elif mode.name == "HEADLESS":
            assert isinstance(display, HeadlessDisplay)
        elif mode.name == "XVFB":
            # pylint: disable=possibly-used-before-assignment,used-before-assignment
            assert isinstance(display, XvfbDisplay)
        elif mode.name == "WESTON":
            # pylint: disable=possibly-used-before-assignment,used-before-assignment
            assert isinstance(display, WestonDisplay)
        else:
            raise AssertionError(f"Unknown DisplayMode: {mode.name}")
    finally:
        display.close()


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_missing_deps(mocker):
    """test XvfbDisplay() missing deps"""
    mocker.patch("ffpuppet.display.Xvfb", side_effect=NameError("test"))
    with raises(NameError):
        XvfbDisplay()


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
@mark.parametrize(
    "resolution, expected_width, expected_height",
    (
        (None, 1280, 1024),
        ("1920x1080", 1920, 1080),
        ("a", 1280, 1024),
    ),
)
def test_xvfb_resolution(mocker, resolution, expected_width, expected_height):
    """test XvfbDisplay() XVFB_RESOLUTION"""
    xvfb = mocker.patch("ffpuppet.display.Xvfb", autospec=True)
    mocker.patch.dict(
        "ffpuppet.display.environ",
        {} if resolution is None else {"XVFB_RESOLUTION": resolution},
    )
    XvfbDisplay()
    assert xvfb.return_value.start.call_count == 1
    xvfb.assert_called_with(width=expected_width, height=expected_height, timeout=60)


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_stop_hang(mocker):
    """test XvfbDisplay.stop hang"""
    xvfb = mocker.patch("ffpuppet.display.Xvfb")
    xvfb.return_value.stop.side_effect = TimeoutExpired(["foo"], 1)
    display = XvfbDisplay()
    display.close()
    assert xvfb.return_value.proc.kill.call_count == 1


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_weston_missing_binary(mocker):
    """test WestonDisplay() with missing weston binary"""
    mocker.patch("ffpuppet.display.which", return_value=None)
    with raises(RuntimeError, match="weston not found"):
        WestonDisplay()


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
@mark.parametrize(
    "resolution, expected_width, expected_height",
    (
        (None, 1280, 1024),
        ("1920x1080", 1920, 1080),
        ("a", 1280, 1024),
    ),
)
def test_weston_resolution(mocker, resolution, expected_width, expected_height):
    """test WestonDisplay() XVFB_RESOLUTION"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/weston")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    mocker.patch("ffpuppet.display.Path.exists", return_value=True)
    mocker.patch.dict(
        "ffpuppet.display.environ",
        {} if resolution is None else {"XVFB_RESOLUTION": resolution},
    )
    display = WestonDisplay()
    try:
        args = popen.call_args[0][0]
        assert f"--width={expected_width}" in args
        assert f"--height={expected_height}" in args
        assert "--backend=headless" in args
    finally:
        display.close()


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_weston_stop_hang(mocker):
    """test WestonDisplay.close() when process hangs"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/weston")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    mocker.patch("ffpuppet.display.Path.exists", return_value=True)
    proc = popen.return_value
    proc.wait.side_effect = [TimeoutExpired(["weston"], 10), None]
    display = WestonDisplay()
    display.close()
    assert proc.terminate.call_count == 1
    assert proc.kill.call_count == 1


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_weston_socket_timeout(mocker):
    """test WestonDisplay() when socket file never appears"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/weston")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    popen.return_value.poll.return_value = None
    mocker.patch("ffpuppet.display.Path.exists", return_value=False)
    mocker.patch("ffpuppet.display.perf_counter", side_effect=[0, 0, 11])
    mocker.patch("ffpuppet.display.sleep")
    with raises(RuntimeError, match="Timed out waiting for weston socket"):
        WestonDisplay()
    assert popen.return_value.terminate.call_count == 1


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_weston_early_exit(mocker):
    """test WestonDisplay() when weston process exits immediately"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/weston")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    popen.return_value.poll.return_value = 1
    mocker.patch("ffpuppet.display.Path.exists", return_value=False)
    with raises(RuntimeError, match="weston process exited early"):
        WestonDisplay()
    assert popen.return_value.terminate.call_count == 0
