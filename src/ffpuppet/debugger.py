# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet debugger module"""
from __future__ import annotations

from abc import ABCMeta, abstractmethod
from logging import getLogger
from os import getenv
from pathlib import Path
from platform import system
from re import match as re_match
from subprocess import check_output
from types import MappingProxyType

LOG = getLogger(__name__)


class DebuggerError(Exception):
    """
    Raised when a debugger related error occurs.
    """


class Debugger(metaclass=ABCMeta):
    """Debugger wrapper base class."""

    def __init__(self) -> None:
        self.log_path: Path | None = None
        self.log_prefix: str | None = None

    @abstractmethod
    def args(self) -> list[str]:
        """Arguments to prepend to the browser launch command.

        Args:
            None

        Returns:
            A list of arguments.
        """

    @abstractmethod
    def env(self) -> dict[str, str]:
        """Environment modification.

        Args:
            None

        Returns:
            Mapping of environment variables to change and values.
        """

    @classmethod
    @abstractmethod
    def version_check(cls) -> None:
        """Perform debugger version check. DebuggerError is raised if any issues are
        encounter.

        Args:
            None

        Returns:
            None.
        """


class GdbDebugger(Debugger):
    """GDB debugger wrapper."""

    def args(self) -> list[str]:
        return [
            "gdb",
            "-nx",
            "-x",
            str((Path(__file__).parent / "cmds.gdb").resolve()),
            "-ex",
            "run",
            "-ex",
            "print $_siginfo",
            "-ex",
            "info locals",
            "-ex",
            "info registers",
            "-ex",
            "backtrace full",
            "-ex",
            "disassemble",
            "-ex",
            "symbol-file",
            # "-ex", "symbol-file %s",
            "-ex",
            "sharedlibrary",
            "-ex",
            "info proc mappings",
            "-ex",
            "info threads",
            "-ex",
            "shared",
            "-ex",
            "info sharedlibrary",
            # "-ex", "init-if-undefined $_exitcode = -1", # windows
            # "-ex", "quit $_exitcode", # windows
            "-ex",
            "quit_with_code",
            "-return-child-result",
            "-batch",
            "--args",
        ]

    def env(self) -> dict[str, str]:
        return {}

    @classmethod
    def version_check(cls) -> None:
        try:
            check_output(("gdb", "--version"))
        except OSError:
            raise DebuggerError("Please install GDB") from None


class RrDebugger(Debugger):
    """rr debugger wrapper."""

    def args(self) -> list[str]:
        args = [
            "rr",
            "record",
            # disable AVX512 for compatibility (required for Pernosco)
            "--disable-cpuid-features-ext",
            "0xdc230000,0x2c42,0xc",
        ]
        if getenv("RR_CHAOS") == "1":
            args.append("--chaos")
        return args

    def env(self) -> dict[str, str]:
        assert self.log_path
        return {"_RR_TRACE_DIR": str(self.log_path.resolve())}

    @classmethod
    def version_check(cls) -> None:
        try:
            check_output(("rr", "--version"))
        except OSError:
            raise DebuggerError("Please install rr") from None


class ValgrindDebugger(Debugger):
    """Valgrind debugger wrapper."""

    # minimum allowed version of Valgrind
    MIN_VERSION = 3.14

    def args(self) -> list[str]:
        assert self.log_path is not None
        assert self.log_prefix is not None

        args = [
            "valgrind",
            "-q",
            "--error-exitcode=99",
            "--exit-on-first-error=yes",
            "--expensive-definedness-checks=yes",
            "--fair-sched=yes",
            "--gen-suppressions=all",
            "--leak-check=no",
            f"--log-file={self.log_path / self.log_prefix}.%p",
            "--num-transtab-sectors=48",
            "--read-inline-info=yes",
            "--show-mismatched-frees=no",
            "--show-possibly-lost=no",
            "--smc-check=all-non-file",
            "--trace-children=yes",
            "--trace-children-skip=python*,*/lsb_release",
            # track-origins=no is much faster and best used to discover issues
            (
                "--track-origins=yes"
                if getenv("VALGRIND_TRACK_ORIGINS") == "1"
                else "--track-origins=no"
            ),
            "--vex-iropt-register-updates=allregs-at-mem-access",
            "--vgdb=no",
        ]

        sup_file = Path(getenv("VALGRIND_SUP_PATH", ""))
        if sup_file.name:
            if not sup_file.is_file():
                raise OSError(f"Missing Valgrind suppressions '{sup_file.resolve()}'")
            LOG.debug("using Valgrind suppressions '%s'", sup_file.resolve())
            args.append(f"--suppressions={sup_file.resolve()}")
        return args

    def env(self) -> dict[str, str]:
        return {
            # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_DEBUG
            "G_DEBUG": "gc-friendly",
            "MOZ_CRASHREPORTER_DISABLE": "1",
        }

    @classmethod
    def version_check(cls) -> None:
        try:
            match = re_match(
                b"valgrind-(?P<ver>\\d+\\.\\d+)",
                check_output(("valgrind", "--version")),
            )
        except OSError:
            raise DebuggerError("Please install Valgrind") from None
        if not match or float(match.group("ver")) < cls.MIN_VERSION:
            raise DebuggerError(f"Valgrind >= {cls.MIN_VERSION:.2f} is required")


_available_debuggers: dict[str, type[Debugger]] = {}
if system() == "Linux":
    _available_debuggers["gdb"] = GdbDebugger
    _available_debuggers["rr"] = RrDebugger
    _available_debuggers["valgrind"] = ValgrindDebugger
DEBUGGERS = MappingProxyType(_available_debuggers)


def load_debugger(name: str) -> Debugger:
    """Load a debugger wrapper by name.

    Args:
        None

    Returns:
        None.
    """
    try:
        selected = DEBUGGERS[name.lower()]
    except KeyError:
        raise DebuggerError(f"Unsupported debugger '{name}'") from None
    # version_check() raises DebuggerError on failure
    selected.version_check()
    return selected()
