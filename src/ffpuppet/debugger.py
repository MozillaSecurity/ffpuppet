# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet debugger module"""

from abc import ABCMeta, abstractmethod
from logging import getLogger
from os import getenv
from pathlib import Path
from platform import system
from re import match as re_match
from subprocess import check_output
from typing import Dict, List, Optional, Union

LOG = getLogger(__name__)


class DebuggerError(Exception):
    """"""


class Debugger(metaclass=ABCMeta):
    SUPPORTED_OS = {"Linux"}

    def __init__(self) -> None:
        self.log_path: Optional[Path] = None
        self.log_prefix: Optional[str] = None

    @abstractmethod
    def args(self) -> List[str]:
        pass

    @abstractmethod
    def env(self) -> Dict[str, str]:
        pass

    @classmethod
    def os_supported(cls) -> bool:
        return system() in cls.SUPPORTED_OS

    @abstractmethod
    @classmethod
    def version_check(cls) -> None:
        pass


class GdbDebugger(Debugger):
    def args(self) -> List[str]:
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

    def env(self) -> Dict[str, str]:
        return {}

    @classmethod
    def version_check(cls) -> None:
        try:
            check_output(["gdb", "--version"])
        except OSError:
            raise DebuggerError("Please install GDB") from None


class RrDebugger(Debugger):
    def args(self) -> List[str]:
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

    def env(self) -> Dict[str, str]:
        assert self.log_path
        return {"_RR_TRACE_DIR": str(self.log_path.resolve())}

    @classmethod
    def version_check(cls) -> None:
        try:
            check_output(["rr", "--version"])
        except OSError:
            raise DebuggerError("Please install rr") from None


class ValgrindDebugger(Debugger):
    # minimum allowed version of Valgrind
    MIN_VERSION = 3.14

    def args(self) -> List[str]:
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
            "--track-origins=no",
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

    def env(self) -> Dict[str, str]:
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
                check_output(["valgrind", "--version"]),
            )
        except OSError:
            raise DebuggerError("Please install Valgrind") from None
        if not match or float(match.group("ver")) < cls.MIN_VERSION:
            raise DebuggerError(f"Valgrind >= {cls.MIN_VERSION:.2f} is required")


def load_debugger(name: str) -> Union[GdbDebugger, RrDebugger, ValgrindDebugger]:
    debuggers: Dict[
        str,
        Union[type[GdbDebugger], type[RrDebugger], type[ValgrindDebugger]],
    ] = {
        "gdb": GdbDebugger,
        "rr": RrDebugger,
        "valgrind": ValgrindDebugger,
    }
    try:
        selected = debuggers[name.lower()]
    except KeyError:
        raise DebuggerError(f"Unsupported debugger '{name}'") from None
    if not selected.os_supported():
        raise DebuggerError(f"{name} not supported on {system()}")
    # raises DebuggerError on failure
    selected.version_check()
    return selected()
