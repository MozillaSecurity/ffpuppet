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
    XvfbLaunchError,
)

if sys.platform == "linux":
    from .display import WestonDisplay, XvfbDisplay


@mark.parametrize("mode", tuple(x for x in DisplayMode))
def test_displays(mocker, mode):
    """test Displays()"""
    if sys.platform == "linux":
        mocker.patch("ffpuppet.display.which", return_value="/usr/bin/foo")
        mocker.patch("ffpuppet.display.Popen", autospec=True)
        mocker.patch("ffpuppet.display.Path.exists", return_value=True)
        mocker.patch("ffpuppet.display.poll")
        mocker.patch("ffpuppet.display.os_read", return_value=b"5\n")
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
def test_xvfb_missing_binary(mocker):
    """test XvfbDisplay() with missing Xvfb binary"""
    mocker.patch("ffpuppet.display.which", return_value=None)
    with raises(RuntimeError, match="Xvfb not found"):
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
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/Xvfb")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    mocker.patch("ffpuppet.display.poll")
    mocker.patch("ffpuppet.display.os_read", return_value=b"1\n")
    mocker.patch.dict(
        "ffpuppet.display.environ",
        {} if resolution is None else {"XVFB_RESOLUTION": resolution},
    )
    display = XvfbDisplay()
    try:
        assert popen.call_count == 1
        args = popen.call_args[0][0]
        assert args[0] == "/usr/bin/Xvfb"
        assert "-displayfd" in args
        assert f"{expected_width}x{expected_height}x24" in args
        # Xvfb must share the caller's process group so killpg() cleans it up
        assert "start_new_session" not in popen.call_args.kwargs
        assert display.env["DISPLAY"] == ":1"
        assert display.env["MOZ_ENABLE_WAYLAND"] == "0"
    finally:
        display.close()
    assert popen.return_value.terminate.call_count == 1


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_partial_read(mocker):
    """test XvfbDisplay() display number split across multiple reads"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/Xvfb")
    mocker.patch("ffpuppet.display.Popen", autospec=True)
    mocker.patch("ffpuppet.display.poll")
    mocker.patch("ffpuppet.display.os_read", side_effect=(b"1", b"23\n"))
    display = XvfbDisplay()
    try:
        assert display.env["DISPLAY"] == ":123"
    finally:
        display.close()


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_early_exit(mocker):
    """test XvfbDisplay() when Xvfb exits before reporting a display"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/Xvfb")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    popen.return_value.poll.return_value = 1
    mocker.patch("ffpuppet.display.poll")
    mocker.patch("ffpuppet.display.os_read", return_value=b"")
    fake_sleep = mocker.patch("ffpuppet.display.sleep")
    with raises(RuntimeError, match=r"Xvfb exited early \(exit code: 1\)"):
        XvfbDisplay()
    assert popen.call_count == XvfbDisplay.LAUNCH_ATTEMPTS
    assert fake_sleep.call_count == XvfbDisplay.LAUNCH_ATTEMPTS - 1


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_retry_success(mocker):
    """test XvfbDisplay() succeeds after a failed launch attempt"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/Xvfb")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    mocker.patch("ffpuppet.display.poll")
    popen.return_value.poll.return_value = None
    # first attempt: Xvfb closes displayfd but does not exit
    popen.return_value.wait.side_effect = (TimeoutExpired(["Xvfb"], 5), None, None)
    mocker.patch("ffpuppet.display.os_read", side_effect=(b"", b"7\n"))
    mocker.patch("ffpuppet.display.sleep")
    display = XvfbDisplay()
    try:
        assert popen.call_count == 2
        assert display.env["DISPLAY"] == ":7"
    finally:
        display.close()


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_invalid_display(mocker):
    """test XvfbDisplay() when Xvfb reports an invalid display"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/Xvfb")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    mocker.patch("ffpuppet.display.poll")
    popen.return_value.poll.return_value = None
    mocker.patch("ffpuppet.display.os_read", return_value=b"foo\n")
    mocker.patch("ffpuppet.display.sleep")
    with raises(XvfbLaunchError, match="Xvfb reported invalid display") as exc:
        XvfbDisplay()
    assert "exit code" not in str(exc.value)
    assert popen.return_value.terminate.call_count == XvfbDisplay.LAUNCH_ATTEMPTS


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_timeout(mocker):
    """test XvfbDisplay() when Xvfb never reports a display"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/Xvfb")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    popen.return_value.poll.return_value = None
    mocker.patch("ffpuppet.display.poll").return_value.poll.return_value = []
    # deadline calc, not expired (poll times out), expired
    mocker.patch("ffpuppet.display.perf_counter", side_effect=(0, 1, 61))
    with raises(RuntimeError, match="Timed out waiting for Xvfb") as exc:
        XvfbDisplay()
    assert "exit code" not in str(exc.value)
    assert not isinstance(exc.value, XvfbLaunchError)
    # timeouts are not retried
    assert popen.call_count == 1
    assert popen.return_value.terminate.call_count == 1


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_interrupted(mocker):
    """test XvfbDisplay() stops Xvfb when launch is interrupted"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/Xvfb")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    mocker.patch(
        "ffpuppet.display.poll"
    ).return_value.poll.side_effect = KeyboardInterrupt
    with raises(KeyboardInterrupt):
        XvfbDisplay()
    assert popen.call_count == 1
    assert popen.return_value.terminate.call_count == 1


@mark.skipif(sys.platform != "linux", reason="Only supported on Linux")
def test_xvfb_stop_hang(mocker):
    """test XvfbDisplay.close() when process hangs"""
    mocker.patch("ffpuppet.display.which", return_value="/usr/bin/Xvfb")
    popen = mocker.patch("ffpuppet.display.Popen", autospec=True)
    mocker.patch("ffpuppet.display.poll")
    mocker.patch("ffpuppet.display.os_read", return_value=b"1\n")
    proc = popen.return_value
    proc.wait.side_effect = [TimeoutExpired(["Xvfb"], 10), None]
    display = XvfbDisplay()
    display.close()
    assert proc.terminate.call_count == 1
    assert proc.kill.call_count == 1


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
