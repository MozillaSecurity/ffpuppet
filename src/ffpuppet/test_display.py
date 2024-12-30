# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""display.py tests"""
from platform import system

from pytest import mark, raises

from .display import DISPLAYS, Display, DisplayMode, HeadlessDisplay, XvfbDisplay


@mark.parametrize("mode", tuple(x for x in DisplayMode))
def test_displays(mocker, mode):
    """test Displays()"""
    if system() == "Linux":
        mocker.patch("ffpuppet.display.Xvfb", autospec=True)
    display = DISPLAYS[mode]()
    assert display
    try:
        if mode.name == "DEFAULT":
            assert isinstance(display, Display)
        elif mode.name == "HEADLESS":
            assert isinstance(display, HeadlessDisplay)
        elif mode.name == "XVFB":
            assert isinstance(display, XvfbDisplay)
        else:
            raise AssertionError(f"Unknown DisplayMode: {mode.name}")
    finally:
        display.close()


@mark.skipif(system() != "Linux", reason="Only supported on Linux")
def test_xvfb_missing_deps(mocker):
    """test XvfbDisplay() missing deps"""
    mocker.patch("ffpuppet.display.Xvfb", side_effect=NameError("test"))
    with raises(NameError):
        XvfbDisplay()
