# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet minidump parsing module"""
from json import JSONDecodeError, load
from logging import getLogger
from pathlib import Path
from subprocess import DEVNULL, CalledProcessError, TimeoutExpired, call, run
from tempfile import NamedTemporaryFile
from typing import IO, Any, Callable, Dict, List, Optional, Tuple

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("process_minidumps",)


class MinidumpParser:
    """Parse minidump files via minidump-stackwalk.
    https://lib.rs/crates/minidump-stackwalk

    Attributes:
        symbols_path: Path containing debug symbols.
        working_path: Path to use as base directory for temporary files.
    """

    MDSW_BIN = "minidump-stackwalk"

    __slots__ = ("_symbols_path", "_working_path")

    def __init__(
        self, symbols_path: Optional[Path] = None, working_path: Optional[str] = None
    ):
        self._symbols_path = symbols_path
        self._working_path = working_path

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
        # generate regester information lines
        frames = md_data["crashing_thread"]["frames"]
        reg_lines: List[str] = list()
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

    def to_json(self, path: Path) -> Tuple[bool, Path]:
        """Convert a minidump to json a file.

        Args:
            path: Minidump file.

        Returns:
            A boolean indicating success of the minidump-stackwalk call and a file
            containing the output.
        """
        cmd = [self.MDSW_BIN, "--json"]
        if self._symbols_path:
            cmd.extend(["--symbols-path", str(self._symbols_path)])
        else:
            cmd.extend(["--symbols-url", "https://symbols.mozilla.org/"])
        cmd.append(str(path))
        with NamedTemporaryFile(
            delete=False, dir=self._working_path, prefix="mdsw_"
        ) as out_fp:
            success = False
            LOG.debug("running %r", " ".join(cmd))
            try:
                run(cmd, check=True, stderr=out_fp, stdout=out_fp, timeout=60)
                success = True
            except CalledProcessError:
                LOG.debug("error processing %r", str(path))
            except TimeoutExpired:
                LOG.debug("timeout while processing %r", str(path))
            md_out = Path(out_fp.name)
        return success, md_out

    @classmethod
    def mdsw_available(cls) -> bool:
        """Check if MDSW binary is available.

        Args:
            None

        Returns:
            True if binary is available otherwise False.
        """
        try:
            call([cls.MDSW_BIN], stdout=DEVNULL, stderr=DEVNULL)
        except OSError:
            return False
        return True


def process_minidumps(
    path: Path,
    symbols_path: Path,
    cb_create_log: Callable[..., Any],
    working_path: Optional[str] = None,
) -> None:
    """Scan for minidump (.dmp) files a in path. If files are found they
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
            "Found a minidump, but can't process it without minidump-stackwalk."
            " See README.md for how to obtain it."
        )
        return
    assert path.is_dir(), f"missing minidump scan path '{path!s}'"
    local_symbols = True
    if not symbols_path.is_dir():
        LOG.warning("Local packaged symbols not found: %r", str(symbols_path))
        local_symbols = False
    md_parser = MinidumpParser(
        symbols_path=symbols_path if local_symbols else None,
        working_path=working_path,
    )
    for count, file in enumerate(path.glob("*.dmp")):
        success, md_json = md_parser.to_json(file)
        if success:
            # load json data from file to dict
            try:
                with md_json.open("rb") as json_fp:
                    md_data = load(json_fp)
                md_json.unlink()
            except JSONDecodeError:
                LOG.debug("JSONDecodeError while loading %r", str(file))
                success = False
        # handle failures
        if not success:
            LOG.warning("Failed to process minidump %r", str(file))
            # collect minidump-stackwalk stderr/stdout
            cb_create_log(f"mdsw_out_{count:02}", logfp=md_json.open("rb"))
            continue
        # write formatted minidump output to file
        md_parser.format_output(md_data, cb_create_log(f"minidump_{count:02}"))
