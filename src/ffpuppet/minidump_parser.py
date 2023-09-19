# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet minidump parsing module"""
from json import JSONDecodeError, load
from logging import getLogger
from pathlib import Path
from shutil import rmtree, which
from subprocess import CalledProcessError, TimeoutExpired, run
from tempfile import TemporaryFile, mkdtemp
from typing import IO, Any, Dict, Iterator, List, Optional

LOG = getLogger(__name__)

MDSW_AVAILABLE = False

__author__ = "Tyson Smith"
__all__ = ("process_minidumps",)


class MinidumpParser:
    """Parse minidump files via minidump-stackwalk.
    https://lib.rs/crates/minidump-stackwalk

    Attributes:
        symbols: Path containing debug symbols.
    """

    MDSW_BIN = which("minidump-stackwalk")

    __slots__ = ("_storage", "_symbols")

    def __init__(self, symbols: Optional[Path] = None):
        self._storage = Path(mkdtemp(prefix="md-parser-"))
        self._symbols = symbols

    def __enter__(self) -> "MinidumpParser":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _cmd(self, src: Path) -> List[str]:
        """Generate minidump-stackwalk command line.

        Args:
            src: minidump to load.

        Returns:
            Command line.
        """
        assert self.MDSW_BIN
        cmd = [self.MDSW_BIN, "--no-color", "--json"]
        if self._symbols:
            cmd.extend(["--symbols-path", str(self._symbols)])
        else:
            cmd.extend(["--symbols-url", "https://symbols.mozilla.org/"])
        cmd.append(str(src))
        return cmd

    @staticmethod
    def _fmt_output(data: Dict[str, Any], out_fp: IO[bytes], limit: int = 150) -> None:
        """Write summarized contents of a minidump to a file in a format that is
        consumable by FuzzManager.

        Args:
            md_data: Minidump contents.
            out_fp: Formatted content destination.
            limit: Maximum number of stack frames to include.

        Returns:
            None
        """
        assert limit > 0
        # generate register information lines
        frames = data["crashing_thread"]["frames"]
        reg_lines: List[str] = []
        for reg, value in frames[0]["registers"].items():
            # display three registers per line
            sep = "\t" if (len(reg_lines) + 1) % 3 else "\n"
            reg_lines.append(f"{reg:>3} = {value}{sep}")
        out_fp.write("".join(reg_lines).strip().encode())
        out_fp.write(b"\n")

        # generate OS information line
        line = "|".join(
            ("OS", data["system_info"]["os"], data["system_info"]["os_ver"])
        )
        out_fp.write(line.encode())
        out_fp.write(b"\n")

        # generate CPU information line
        line = "|".join(
            (
                "CPU",
                data["system_info"]["cpu_arch"],
                data["system_info"]["cpu_info"],
                str(data["system_info"]["cpu_count"]),
            )
        )
        out_fp.write(line.encode())
        out_fp.write(b"\n")

        # generate Crash information line
        crashing_thread = str(data["crash_info"]["crashing_thread"])
        line = "|".join(
            (
                "Crash",
                data["crash_info"]["type"],
                data["crash_info"]["address"],
                crashing_thread,
            )
        )
        out_fp.write(line.encode())
        out_fp.write(b"\n")

        # generate Frame information lines
        for frame in frames[:limit]:
            if frame["function_offset"]:
                # remove the padding zeros
                func_offset = str(hex(int(frame["function_offset"], 16)))
            else:
                func_offset = ""
            line = "|".join(
                (
                    crashing_thread,
                    str(frame["frame"]),
                    frame["module"] or "",
                    frame["function"] or "",
                    frame["file"] or "",
                    str(frame["line"] or ""),
                    func_offset,
                )
            )
            out_fp.write(line.encode())
            out_fp.write(b"\n")

        if limit < len(frames):
            out_fp.write(b"WARNING: Hit stack size output limit!\n")

    def close(self) -> None:
        """Remove working data.

        Args:
            None

        Returns:
            None
        """
        if self._storage.is_dir():
            rmtree(self._storage)

    def create_log(self, src: Path, filename: str, timeout: int = 60) -> Path:
        """Create a human readable log from a minidump file.

        Args:
            src:
            filename:
            timeout:

        Returns:
            Log file.
        """
        assert filename
        assert timeout >= 0
        cmd = self._cmd(src)
        dst = self._storage / filename
        # using nested with statements for python 3.8 support
        with TemporaryFile(dir=self._storage, prefix="mdsw_out_") as out_fp:
            with TemporaryFile(dir=self._storage, prefix="mdsw_err_") as err_fp:
                LOG.debug("running %r", " ".join(cmd))
                try:
                    run(cmd, check=True, stderr=err_fp, stdout=out_fp, timeout=timeout)
                    out_fp.seek(0)
                    # load json, format data and write log
                    with dst.open("wb") as log_fp:
                        self._fmt_output(load(out_fp), log_fp)
                except (CalledProcessError, JSONDecodeError, TimeoutExpired) as exc:
                    if isinstance(exc, CalledProcessError):
                        msg = f"minidump-stackwalk failed ({exc.returncode})"
                    elif isinstance(exc, JSONDecodeError):
                        msg = "json decode error"
                    else:
                        msg = "minidump-stackwalk timeout"
                    LOG.warning("Failed to parse minidump: %s", msg)
                    err_fp.seek(0)
                    out_fp.seek(0)
                    # write log
                    with dst.open("wb") as log_fp:
                        log_fp.write(f"Failed to parse minidump: {msg}".encode())
                        log_fp.write(b"\n\nminidump-stackwalk stderr:\n")
                        log_fp.write(err_fp.read())
                        log_fp.write(b"\n\nminidump-stackwalk stdout:\n")
                        log_fp.write(out_fp.read())
        return dst

    @classmethod
    def mdsw_available(
        cls, force_check: bool = False, min_version: str = "0.15.2"
    ) -> bool:
        """Check if minidump-stackwalk binary is available.

        Args:
            force_check: Always perform a check.
            min_version: Minimum supported minidump-stackwalk version.

        Returns:
            True if binary is available otherwise False.
        """
        if not cls.MDSW_BIN:
            LOG.debug("minidump-stackwalk not found")
            return False
        global MDSW_AVAILABLE  # pylint: disable=global-statement
        if not MDSW_AVAILABLE or force_check:
            assert len(min_version.split(".")) == 3
            try:
                result = run(
                    [cls.MDSW_BIN, "--version"], check=False, capture_output=True
                )
            except OSError:
                LOG.debug("minidump-stackwalk not available (%s)", cls.MDSW_BIN)
                return False
            # expected output is 'minidump-stackwalk #.#.#'
            current_version = result.stdout.strip().split()[-1].decode()
            if len(current_version.split(".")) != 3:
                LOG.error(
                    "Unknown minidump-stackwalk version: %r",
                    result.stdout.decode(errors="ignore"),
                )
                return False
            # version check
            for cver, mver in zip(current_version.split("."), min_version.split(".")):
                if int(cver) > int(mver):
                    break
                if int(cver) < int(mver):
                    LOG.error(
                        "minidump-stackwalk %r is unsupported (minimum %r)",
                        current_version,
                        min_version,
                    )
                    return False
            MDSW_AVAILABLE = True
        return True


def process_minidumps(path: Path, symbols: Path) -> Iterator[Path]:
    """Scan for minidump (.dmp) files in path and a log is yielded for each.

    Args:
        path: Path to scan for minidump files.
        symbols: Directory containing symbols for the target binary.

    Yields:
        Formatted minidump logs.
    """
    if not MinidumpParser.mdsw_available():
        LOG.error(
            "Unable to process minidump."
            " See README.md for details on obtaining the latest minidump-stackwalk."
        )
        return
    assert path.is_dir(), f"missing minidump scan path '{path!s}'"
    local_symbols = True
    if not symbols.is_dir():
        LOG.warning("Local packaged symbols not found: '%s'", symbols)
        local_symbols = False

    with MinidumpParser(symbols=symbols if local_symbols else None) as md_parser:
        # order by last modified date hopefully the oldest log is the cause of the issue
        dmp_files = sorted(path.glob("*.dmp"), key=lambda x: x.stat().st_mtime)
        for count, dmp_file in enumerate(dmp_files):
            yield md_parser.create_log(dmp_file, f"minidump_{count:02}.txt")
