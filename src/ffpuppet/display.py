# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet display module"""

from __future__ import annotations

# use sys.platform for mypy
import sys
from contextlib import suppress
from enum import Enum, auto, unique
from logging import getLogger
from os import close as os_close
from os import environ, getpid, pipe
from os import read as os_read
from pathlib import Path
from shutil import which
from subprocess import DEVNULL, Popen, TimeoutExpired
from tempfile import TemporaryFile
from time import perf_counter, sleep
from types import MappingProxyType
from typing import TYPE_CHECKING

if sys.platform != "win32":
    # pylint: disable=ungrouped-imports,no-name-in-module
    from os import getuid
    from select import POLLIN, poll


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


def _stop_process(proc: Popen[bytes], timeout: float = 10) -> None:
    """Terminate a process, kill it if it does not exit in time.

    Args:
        proc: Process to stop.
        timeout: Seconds to wait for the process to exit after terminate().

    Returns:
        None
    """
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except TimeoutExpired:
        proc.kill()
        proc.wait()


class XvfbLaunchError(RuntimeError):
    """Xvfb failed during launch, another attempt may succeed."""


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
                _stop_process(self._weston)
                self._weston = None

    class XvfbDisplay(Display):
        """Xvfb headless display mode."""

        __slots__ = ("_proc",)

        LAUNCH_ATTEMPTS = 3
        LAUNCH_TIMEOUT = 60

        def __init__(self) -> None:
            super().__init__()
            self._proc: Popen[bytes] | None = None
            xvfb_bin = which("Xvfb")
            if xvfb_bin is None:
                raise RuntimeError("Xvfb not found")
            width, height = _parse_resolution()
            LOG.debug("xvfb resolution: %dx%d", width, height)
            try:
                attempt = 0
                while True:
                    attempt += 1
                    try:
                        display = self._launch(xvfb_bin, width, height)
                        break
                    except XvfbLaunchError as exc:
                        if attempt >= self.LAUNCH_ATTEMPTS:
                            raise
                        LOG.warning(
                            "Xvfb launch failed (attempt %d/%d): %s",
                            attempt,
                            self.LAUNCH_ATTEMPTS,
                            exc,
                        )
                        sleep(1)
            except BaseException:
                # the caller never receives this object if __init__ raises
                # so close() must be called here to avoid leaking Xvfb
                self.close()
                raise
            LOG.debug("xvfb display: %s", display)
            self.env = MappingProxyType({"DISPLAY": display, "MOZ_ENABLE_WAYLAND": "0"})

        def _launch(self, xvfb_bin: str, width: int, height: int) -> str:
            """Launch Xvfb and wait for it to report the display it is using.

            Xvfb selects an available display number and writes it to the
            file descriptor passed via '-displayfd' once it is ready to
            accept connections.

            Args:
                xvfb_bin: Xvfb binary.
                width: Screen width.
                height: Screen height.

            Returns:
                X display name (e.g. ':1').

            Raises:
                XvfbLaunchError: Xvfb exited or reported an invalid display.
                RuntimeError: Timed out waiting for Xvfb.
            """
            with TemporaryFile() as stderr:
                fd_r, fd_w = pipe()
                error: str | None = None
                # failures are retryable unless they are not expected to recover
                error_cls: type[RuntimeError] = XvfbLaunchError
                try:
                    try:
                        # pylint: disable=consider-using-with
                        self._proc = Popen(
                            [
                                xvfb_bin,
                                "-displayfd",
                                str(fd_w),
                                "-screen",
                                "0",
                                f"{width}x{height}x24",
                                "-nolisten",
                                "tcp",
                            ],
                            pass_fds=(fd_w,),
                            stderr=stderr,
                            stdout=DEVNULL,
                        )
                    finally:
                        os_close(fd_w)
                    # use poll() instead of select() which can't handle fd >= 1024
                    # pylint: disable=possibly-used-before-assignment
                    poller = poll()
                    poller.register(fd_r, POLLIN)
                    data = b""
                    deadline = perf_counter() + self.LAUNCH_TIMEOUT
                    while b"\n" not in data:
                        remaining = deadline - perf_counter()
                        if remaining <= 0:
                            # a hung Xvfb is not expected to recover, don't retry
                            error = "Timed out waiting for Xvfb"
                            error_cls = RuntimeError
                            break
                        if not poller.poll(remaining * 1000):
                            continue
                        chunk = os_read(fd_r, 64)
                        if not chunk:
                            error = "Xvfb exited early"
                            # give the process a moment to exit and report
                            # its real exit code before it is terminated
                            with suppress(TimeoutExpired):
                                self._proc.wait(timeout=5)
                            break
                        data += chunk
                finally:
                    os_close(fd_r)
                if error is None:
                    try:
                        return f":{int(data)}"
                    except ValueError:
                        error = f"Xvfb reported invalid display {data!r}"
                assert self._proc is not None
                # check before close() so a terminated process is not reported
                exit_code = self._proc.poll()
                self.close()
                if exit_code is not None:
                    error = f"{error} (exit code: {exit_code})"
                stderr.seek(0)
                # the cause of a failure is reported at the end of the output
                output = stderr.read().decode("utf-8", errors="replace").strip()
                tail = "\n".join(output.splitlines()[-10:])
            message = f"{error}\n{tail}".rstrip()
            raise error_cls(message)

        def close(self) -> None:
            if self._proc is not None:
                _stop_process(self._proc)
                self._proc = None


_displays: dict[DisplayMode, type[Display]] = {
    DisplayMode.DEFAULT: Display,
    DisplayMode.HEADLESS: HeadlessDisplay,
}
if sys.platform == "linux":
    _displays[DisplayMode.WESTON] = WestonDisplay
    _displays[DisplayMode.XVFB] = XvfbDisplay

DISPLAYS = MappingProxyType(_displays)
