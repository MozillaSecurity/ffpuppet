# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet display module"""

from __future__ import annotations

from contextlib import suppress
from enum import Enum, auto, unique
from logging import getLogger
from platform import system
from types import MappingProxyType

with suppress(ImportError):
    from xvfbwrapper import Xvfb

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


LOG = getLogger(__name__)


@unique
class DisplayMode(Enum):
    """Supported display modes."""

    DEFAULT = auto()
    HEADLESS = auto()
    if system() == "Linux":
        XVFB = auto()


class Display:
    """Default display mode.

    Attributes:
        args: Extra Firefox command line arguments to use.
        env: Extra environment variables to use.
        mode: DisplayMode enum name.
    """

    __slots__ = ("args", "env", "mode")

    def __init__(self) -> None:
        self.args: Iterable[str] = ()
        self.env: Mapping[str, str] = MappingProxyType({})
        self.mode: str = DisplayMode.DEFAULT.name

    def close(self) -> None:
        """Perform any required operations to shutdown and cleanup.

        Args:
            None

        Returns:
            None
        """


class HeadlessDisplay(Display):
    """Headless display mode."""

    def __init__(self) -> None:
        super().__init__()
        self.args = ("-headless",)
        self.mode = DisplayMode.HEADLESS.name


class XvfbDisplay(Display):
    """Xvfb display mode."""

    __slots__ = ("_xvfb",)

    def __init__(self) -> None:
        super().__init__()
        self.env = MappingProxyType({"MOZ_ENABLE_WAYLAND": "0"})
        self.mode = DisplayMode.XVFB.name
        try:
            self._xvfb: Xvfb | None = Xvfb(width=1280, height=1024)
        except NameError:
            LOG.error("Missing xvfbwrapper")
            raise
        self._xvfb.start()

    def close(self) -> None:
        if self._xvfb is not None:
            self._xvfb.stop()
            self._xvfb = None


_displays: dict[DisplayMode, type[Display]] = {
    DisplayMode.DEFAULT: Display,
    DisplayMode.HEADLESS: HeadlessDisplay,
}
if system() == "Linux":
    _displays[DisplayMode.XVFB] = XvfbDisplay

DISPLAYS = MappingProxyType(_displays)
