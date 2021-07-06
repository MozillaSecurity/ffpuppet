# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet minidump parsing module"""

from logging import getLogger
from os import getenv, scandir, stat
from os.path import getmtime, isdir
from os.path import join as pathjoin
from shutil import copy, copyfileobj
from subprocess import DEVNULL, call
from tempfile import TemporaryFile, mkdtemp

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("process_minidumps",)


class MinidumpParser:  # pylint: disable=missing-docstring
    MDSW_BIN = "minidump_stackwalk"
    MDSW_MAX_STACK = 150

    __slots__ = (
        "md_files",
        "symbols_path",
        "_include_raw",
        "_record_failures",
        "_working_path",
    )

    def __init__(self, scan_path, record_failures=True, working_path=None):
        self.md_files = [x.path for x in scandir(scan_path) if x.name.endswith(".dmp")]
        self.symbols_path = None
        self._include_raw = getenv("FFP_DEBUG_MDSW") is not None
        self._record_failures = record_failures  # mdsw failure reporting
        self._working_path = working_path

    def _call_mdsw(self, dump_file, out_fp, extra_flags=None):
        """Call minidump_stackwalk on a dmp file and collect output.

        Args:
            dump_file (str): Path to dmp file.
            out_fp (file): File to write output to.
            extra_flags (list(str)): Arguments to pass to minidump_stackwalk.

        Returns:
            None
        """
        cmd = [self.MDSW_BIN]
        if extra_flags:
            cmd += extra_flags
        cmd.append(dump_file)
        if self.symbols_path is not None:
            cmd.append(self.symbols_path)

        LOG.debug("calling %r", " ".join(cmd))
        with TemporaryFile(dir=self._working_path, prefix="mdsw_stderr_") as err_fp:
            ret_val = call(cmd, stdout=out_fp, stderr=err_fp)
            if ret_val != 0:
                # mdsw failed
                LOG.warning("%r returned %r", " ".join(cmd), ret_val)
                if self._record_failures:
                    # save the dmp file and the logs
                    report_dir = mkdtemp(dir=self._working_path, prefix="mdsw_err_")
                    copy(dump_file, report_dir)
                    with open(pathjoin(report_dir, "mdsw_cmd.txt"), "wb") as log_fp:
                        log_fp.write((" ".join(cmd)).encode("ascii"))
                    err_fp.seek(0)
                    with open(pathjoin(report_dir, "mdsw_stderr.txt"), "wb") as log_fp:
                        copyfileobj(err_fp, log_fp, 0x10000)
                    out_fp.seek(0)
                    with open(pathjoin(report_dir, "mdsw_stdout.txt"), "wb") as log_fp:
                        copyfileobj(out_fp, log_fp, 0x10000)
                    LOG.warning("mdsw logs can be found here %r", report_dir)
                # collect size of dmp file to help diagnose mdsw issues
                try:
                    dmp_size = stat(dump_file).st_size
                except OSError:
                    dmp_size = None
                raise RuntimeError("MDSW Error (dmp size: %r)" % (dmp_size,))

        out_fp.seek(0)

    def _read_registers(self, dump_file, log_fp):
        """Use minidump_stackwalk to retrieve register info from dump_file.

        Args:
            dump_file (str): Path to dmp file.
            out_fp (file): File to write output to.

        Returns:
            None
        """
        with TemporaryFile(dir=self._working_path, prefix="mdsw_reg_") as out_fp:
            self._call_mdsw(dump_file, out_fp)
            found_registers = False
            for line in out_fp:  # pylint: disable=not-an-iterable
                if not found_registers:
                    # look for the beginning of the register dump
                    if b"(crashed)" in line:
                        found_registers = True
                    continue
                line = line.lstrip()
                if line.startswith(b"0"):
                    # skip first line
                    continue
                if b"=" not in line:
                    # we reached the end
                    break
                log_fp.write(line)
            LOG.debug("collected register info: %r", found_registers)

    def _read_stacktrace(self, dump_file, log_fp, raw_fp=None, limit=MDSW_MAX_STACK):
        """Use minidump_stackwalk to retrieve stack trace from dump_file.

        Args:
            dump_file (str): Path to dmp file.
            log_fp (file): File to write output to.
            raw_fp (file): File to write unprocessed output to.
            limit (int): Maximum number of lines to include in stack trace.

        Returns:
            None
        """
        with TemporaryFile(dir=self._working_path, prefix="mdsw_stack_") as out_fp:
            self._call_mdsw(dump_file, out_fp, extra_flags=["-m"])
            if raw_fp is not None:
                copyfileobj(out_fp, raw_fp, 0x10000)  # read in 64K chunks
                out_fp.seek(0)
            crash_thread = None
            line_count = 0  # lines added to the log so far
            for line in out_fp:  # pylint: disable=not-an-iterable
                if b"|" not in line or line.startswith(b"Module|"):
                    # ignore line
                    continue

                # check if this is a stack entry (starts with '#|')
                try:
                    t_id = int(line.split(b"|", 1)[0])
                    # assume that the first entry in the stack is the crash_thread
                    # NOTE: an alternative would be to parse the 'Crash|' line
                    if crash_thread is None:
                        crash_thread = t_id
                    elif t_id != crash_thread:
                        break
                except ValueError:
                    # not a stack entry
                    pass

                log_fp.write(line)
                line_count += 1
                if line_count >= limit:
                    LOG.warning("Stack size limit reached (%d)", limit)
                    log_fp.write(b"WARNING: Hit stack size output limit!")
                    break

    def collect_logs(self, cb_create_log, symbols_path):
        """Collect logs from dmp files.

        Args:
            cb_create_log (callable): A callback to add log to PuppetLogger.
            symbols_path (str): Path to symbols directory.

        Returns:
            None
        """
        self.symbols_path = symbols_path
        # sort dumps by modified date since the oldest is likely the most interesting
        # this does assume that the dumps are written sequentially
        for count, file_path in enumerate(sorted(self.md_files, key=getmtime), start=1):
            log_fp = cb_create_log("minidump_%02d" % count)
            self._read_registers(file_path, log_fp)
            # create log for raw mdsw stack output if needed
            raw_fp = (
                cb_create_log("raw_mdsw_%02d" % count) if self._include_raw else None
            )
            self._read_stacktrace(file_path, log_fp, raw_fp)
            if log_fp.tell() < 1:
                LOG.warning("minidump_stackwalk log was empty (minidump_%02d)", count)
                log_fp.write(b"WARNING: minidump_stackwalk log was empty\n")

    @classmethod
    def mdsw_available(cls):
        """Check if minidump_stackwalk is available.

        Args:
            None

        Returns:
            bool: True if minidump_stackwalk is available otherwise False.
        """
        try:
            call([cls.MDSW_BIN], stdout=DEVNULL, stderr=DEVNULL)
        except OSError:
            return False
        return True


def process_minidumps(scan_path, symbols_path, cb_create_log, working_path=None):
    """Scan for minidump (.dmp) files a in scan_path. If dumps are found they
    are parsed and new logs are added via the cb_create_log callback.

    Args:
        scan_path (str): Directory potentially containing minidump files.
        symbols_path (str): Directory containing symbols for the target binary.
        cb_create_log (callable): A callback to the add_log() of a PuppetLogger.
        working_path (str): Used as base directory for temporary files.

    Returns:
        None
    """
    assert isinstance(scan_path, str)
    assert isinstance(symbols_path, str)
    assert callable(cb_create_log)
    if not isdir(scan_path):
        LOG.debug("scan_path %r does not exist", scan_path)
        return
    parser = MinidumpParser(scan_path, working_path=working_path)
    if not parser.md_files:
        LOG.debug("scan_path %r did not contain '.dmp' files", scan_path)
        return
    if not parser.mdsw_available():
        LOG.warning(
            "Found a minidump, but can't process it without minidump_stackwalk."
            " See README.md for how to obtain it."
        )
        return
    if not isdir(symbols_path):
        LOG.warning("Symbols path not found: %r", symbols_path)
        symbols_path = None
    parser.collect_logs(cb_create_log, symbols_path)
