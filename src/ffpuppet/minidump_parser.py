# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet minidump parsing module"""
from json import JSONDecodeError, load
from logging import getLogger
from pathlib import Path
from shutil import copy2, rmtree, which
from subprocess import DEVNULL, CalledProcessError, TimeoutExpired, run
from tempfile import NamedTemporaryFile, mkdtemp
from typing import IO, Any, Callable, Dict, List, Optional

LOG = getLogger(__name__)

MDSW_AVAILABLE = False

__author__ = "Tyson Smith"
__all__ = ("process_minidumps",)


class MinidumpStackwalkFailure(Exception):
    """
    Raised when the minidump-stackwalk fails.
    """


class MinidumpParser:
    """Parse minidump files via minidump-stackwalk.
    https://lib.rs/crates/minidump-stackwalk

    Attributes:
        symbols_path: Path containing debug symbols.
    """

    MDSW_BIN = which("minidump-stackwalk")

    __slots__ = ("_symbols_path",)

    def __init__(self, symbols_path: Optional[Path] = None):
        self._symbols_path = symbols_path

    @staticmethod
    def format_output(
        md_data: Dict[str, Any], out_fp: IO[bytes], limit: int = 150
    ) -> None:
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
        frames = md_data["crashing_thread"]["frames"]
        reg_lines: List[str] = []
        for reg, value in frames[0]["registers"].items():
            # display three registers per line
            sep = "\t" if (len(reg_lines) + 1) % 3 else "\n"
            reg_lines.append(f"{reg:>3} = {value}{sep}")
        out_fp.write("".join(reg_lines).strip().encode())
        out_fp.write(b"\n")

        # generate OS information line
        line = "|".join(
            ("OS", md_data["system_info"]["os"], md_data["system_info"]["os_ver"])
        )
        out_fp.write(line.encode())
        out_fp.write(b"\n")

        # generate CPU information line
        line = "|".join(
            (
                "CPU",
                md_data["system_info"]["cpu_arch"],
                md_data["system_info"]["cpu_info"],
                str(md_data["system_info"]["cpu_count"]),
            )
        )
        out_fp.write(line.encode())
        out_fp.write(b"\n")

        # generate Crash information line
        crashing_thread = str(md_data["crash_info"]["crashing_thread"])
        line = "|".join(
            (
                "Crash",
                md_data["crash_info"]["type"],
                md_data["crash_info"]["address"],
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

    def to_json(self, src: Path, dst: Path) -> Path:
        """Convert a minidump to json a file.

        Args:
            src: Minidump file.
            dst: Location to save JSON file.

        Returns:
            A file containing JSON output.
        """
        assert self.MDSW_BIN
        cmd = [self.MDSW_BIN, "--no-color", "--json"]
        if self._symbols_path:
            cmd.extend(["--symbols-path", str(self._symbols_path)])
        else:
            cmd.extend(["--symbols-url", "https://symbols.mozilla.org/"])
        # add output files
        with NamedTemporaryFile(dir=dst, prefix="mdsw_out_", suffix=".json") as ofp:
            out_json = Path(ofp.name)
        cmd.extend(["--output-file", str(out_json)])
        cmd.append(str(src))
        LOG.debug("running %r", " ".join(cmd))
        try:
            run(cmd, check=True, stdout=DEVNULL, timeout=60)
        except CalledProcessError:
            LOG.error("Failed to process: %s", src)
            raise MinidumpStackwalkFailure(b"minidump-stackwalk failed") from None
        except TimeoutExpired:
            LOG.error("Failed to process: %s", src)
            raise MinidumpStackwalkFailure("minidump-stackwalk hung") from None
        return out_json

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


def process_minidumps(
    path: Path,
    symbols_path: Path,
    cb_create_log: Callable[..., Any],
    working_path: Optional[str] = None,
) -> None:
    """Scan for minidump (.dmp) files in path. If files are found they
    are parsed and new logs are added via the cb_create_log callback.

    Args:
        path: Path to scan for minidump files.
        symbols_path: Directory containing symbols for the target binary.
        cb_create_log: A callback to the add_log() of a PuppetLogger.
        working_path: Used as base directory for temporary files.

    Returns:
        None
    """
    if not MinidumpParser.mdsw_available():
        LOG.warning(
            "Unable to process minidump."
            " See README.md for details on obtaining the latest minidump-stackwalk."
        )
        return
    assert path.is_dir(), f"missing minidump scan path '{path!s}'"
    local_symbols = True
    if not symbols_path.is_dir():
        LOG.warning("Local packaged symbols not found: %r", str(symbols_path))
        local_symbols = False

    # create working path
    working_path = mkdtemp(prefix="minidump_", dir=working_path)

    md_parser = MinidumpParser(symbols_path=symbols_path if local_symbols else None)
    # order by last modified date hopefully the oldest log is the cause of the issue
    dmp_files = sorted(path.glob("*.dmp"), key=lambda x: x.stat().st_mtime)
    for count, file in enumerate(dmp_files):
        # filter out zero byte files and warn
        if file.stat().st_size == 0:
            LOG.warning("Ignored zero byte minidump: %s", file)
            continue
        try:
            # parse minidump with minidump-stackwalk
            md_json = md_parser.to_json(file, Path(working_path))
            # load json data from file to dict
            with md_json.open("rb") as json_fp:
                md_data = load(json_fp)
            md_json.unlink()
            # write formatted minidump output to log file
            md_parser.format_output(md_data, cb_create_log(f"minidump_{count:02}"))
        except (JSONDecodeError, KeyError, MinidumpStackwalkFailure):
            # save a copy of the minidump
            saved_md = copy2(file, working_path)
            LOG.error("Minidump saved as '%s'", saved_md)
            raise

    # if successful remove the working path
    rmtree(working_path)
