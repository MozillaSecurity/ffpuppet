# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet minidump parsing module"""
from json import JSONDecodeError, load
from logging import DEBUG, INFO, basicConfig, getLogger
from pathlib import Path
from shutil import rmtree, which
from subprocess import CalledProcessError, TimeoutExpired, run
from tempfile import TemporaryFile, mkdtemp
from typing import IO, Any, Dict, List, Optional

LOG = getLogger(__name__)
MDSW_URL = "https://lib.rs/crates/minidump-stackwalk"
SYMS_URL = "https://symbols.mozilla.org/"

__author__ = "Tyson Smith"
__all__ = ("MinidumpParser",)


class MinidumpParser:
    """Parse minidump files via minidump-stackwalk.

    Attributes:
        symbols: Path containing debug symbols.
    """

    MDSW_BIN = which("minidump-stackwalk")

    __slots__ = ("_storage", "_symbols")

    def __init__(self, symbols: Optional[Path] = None) -> None:
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
        cmd = [self.MDSW_BIN, "--no-color", "--no-interactive", "--json"]
        if self._symbols:
            cmd.extend(["--symbols-path", str(self._symbols.resolve(strict=True))])
        else:
            cmd.extend(["--symbols-url", SYMS_URL])
        cmd.append(str(src.resolve(strict=True)))
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
        out_fp.write("".join(reg_lines).rstrip().encode())
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
                data["system_info"]["cpu_arch"] or "unknown",
                data["system_info"]["cpu_info"] or "",
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
                func_offset = hex(int(frame["function_offset"], 16))
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

    def create_log(self, src: Path, filename: str, timeout: int = 300) -> Path:
        """Create a human readable log from a minidump file.

        Args:
            src: Minidump file.
            filename: Name to use for output file.
            timeout: Maximum runtime of minidump-stackwalk. NOTE: Symbols may be
                downloaded if not provided which can add overhead.

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
    def mdsw_available(cls, min_version: str = "0.15.2") -> bool:
        """Check if minidump-stackwalk binary is available.

        Args:
            min_version: Minimum supported minidump-stackwalk version.

        Returns:
            True if binary is available otherwise False.
        """
        assert min_version.count(".") == 2

        if not cls.MDSW_BIN:
            LOG.debug("minidump-stackwalk not found")
            return False
        try:
            result = run([cls.MDSW_BIN, "--version"], check=False, capture_output=True)
        except OSError:
            LOG.debug("minidump-stackwalk not available (%s)", cls.MDSW_BIN)
            return False
        LOG.debug("using minidump-stackwalk (%s)", cls.MDSW_BIN)
        # expected output is 'minidump-stackwalk #.#.#'
        current_version = result.stdout.strip().split()[-1].decode()
        if current_version.count(".") != 2:
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
        LOG.debug("detected minidump-stackwalk version %r", current_version)
        return True


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("minidump", type=Path, help="Minidump to process.")
    parser.add_argument("--debug", action="store_true", help="Display debug output.")
    parser.add_argument(
        "--symbols",
        type=Path,
        help="Local symbols directory. "
        f"If not provided attempt to download symbols from {SYMS_URL}",
    )
    args = parser.parse_args()

    # set output verbosity
    if args.debug:
        basicConfig(format="[%(levelname).1s] %(message)s", level=DEBUG)
    else:
        basicConfig(format="%(message)s", level=INFO)

    if MinidumpParser.mdsw_available():
        with MinidumpParser(symbols=args.symbols) as md_parser:
            log = md_parser.create_log(args.minidump, "minidump_tmp.txt")
            LOG.info("Parsed %s\n%s", args.minidump.resolve(), log.read_text())
    else:
        LOG.error(
            "Unable to process minidump, minidump-stackwalk is required. %s", MDSW_URL
        )
