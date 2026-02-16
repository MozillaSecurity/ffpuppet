# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet display module"""

from __future__ import annotations

# use sys.platform for mypy
import sys
from enum import Enum, auto, unique
from logging import getLogger
from os import environ, getpid
from pathlib import Path
from shutil import which
from subprocess import DEVNULL, Popen, TimeoutExpired
from time import perf_counter, sleep
from types import MappingProxyType
from typing import TYPE_CHECKING

if sys.platform != "win32":
    # pylint: disable=ungrouped-imports,no-name-in-module
    from os import getuid


if sys.platform == "linux":
    # pylint: disable=import-error
    from xvfbwrapper import Xvfb


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


LOG = getLogger(__name__)


@unique
class DisplayMode(Enum):
    """Supported display modes."""

    DEFAULT = auto()
    HEADLESS = auto()
    if sys.platform == "linux":
        WESTON = auto()
        XVFB = auto()


def _parse_resolution(width: int = 1280, height: int = 1024) -> tuple[int, int]:
    """Parse display resolution from XVFB_RESOLUTION env var.

    Returns:
        Tuple of (width, height).
    """
    resolution = environ.get("XVFB_RESOLUTION")
    if resolution is not None:
        try:
            w_str, h_str = resolution.lower().split("x")
            width, height = int(w_str), int(h_str)
        except ValueError:
            LOG.warning("Invalid XVFB_RESOLUTION '%s'", resolution)
    return width, height


class Display:
    """Default display mode.

    Attributes:
        args: Extra command line arguments to pass to Firefox.
        env: Extra environment variables to set.
        mode: DisplayMode enum name.
    """

    __slots__ = ("args", "env")

    def __init__(self) -> None:
        self.args: Sequence[str] = ()
        self.env: Mapping[str, str] = MappingProxyType({})

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


if sys.platform == "linux":

    class WestonDisplay(Display):
        """Weston (Wayland) headless display mode."""

        __slots__ = ("_weston",)

        def __init__(self) -> None:
            super().__init__()
            weston_bin = which("weston")
            if weston_bin is None:
                raise RuntimeError("weston not found")
            width, height = _parse_resolution()
            LOG.debug("weston resolution: %dx%d", width, height)
            socket_name = f"wayland-ffpuppet-{getpid()}"
            self.env = MappingProxyType(
                {"WAYLAND_DISPLAY": socket_name, "MOZ_ENABLE_WAYLAND": "1"}
            )
            # pylint: disable=consider-using-with
            self._weston: Popen[bytes] | None = Popen(
                [
                    weston_bin,
                    "--backend=headless",
                    f"--socket={socket_name}",
                    f"--width={width}",
                    f"--height={height}",
                ],
                start_new_session=True,
                stderr=DEVNULL,
                stdout=DEVNULL,
            )
            # wait for the socket file to appear
            # pylint: disable=possibly-used-before-assignment
            runtime_dir = Path(environ.get("XDG_RUNTIME_DIR", f"/run/user/{getuid()}"))
            socket_path = runtime_dir / socket_name
            deadline = perf_counter() + 10
            while not socket_path.exists():
                if self._weston.poll() is not None:
                    self._weston = None
                    raise RuntimeError("weston process exited early")
                if perf_counter() >= deadline:
                    self.close()
                    raise RuntimeError(
                        f"Timed out waiting for weston socket: {socket_path}"
                    )
                sleep(0.1)

        def close(self) -> None:
            if self._weston is not None:
                self._weston.terminate()
                try:
                    self._weston.wait(timeout=10)
                except TimeoutExpired:
                    self._weston.kill()
                    self._weston.wait()
                self._weston = None

    class XvfbDisplay(Display):
        """Xvfb headless display mode."""

        __slots__ = ("_xvfb",)

        def __init__(self) -> None:
            super().__init__()
            self.env = MappingProxyType({"MOZ_ENABLE_WAYLAND": "0"})
            width, height = _parse_resolution()
            LOG.debug("xvfb resolution: %dx%d", width, height)
            try:
                self._xvfb: Xvfb | None = Xvfb(width=width, height=height, timeout=60)
            except NameError:
                LOG.error("Missing xvfbwrapper")
                raise
            self._xvfb.start()

        def close(self) -> None:
            if self._xvfb is not None:
                try:
                    self._xvfb.stop()
                except TimeoutExpired:
                    if self._xvfb.proc is not None:
                        self._xvfb.proc.kill()
                self._xvfb = None


_displays: dict[DisplayMode, type[Display]] = {
    DisplayMode.DEFAULT: Display,
    DisplayMode.HEADLESS: HeadlessDisplay,
}
if sys.platform == "linux":
    _displays[DisplayMode.WESTON] = WestonDisplay
    _displays[DisplayMode.XVFB] = XvfbDisplay

DISPLAYS = MappingProxyType(_displays)
