# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""browser and debugger log management"""

from json import dump as json_dump
from logging import getLogger
from os import close as os_close
from os import getpid, makedirs, mkdir, scandir, stat, stat_result
from os.path import abspath, isdir, isfile
from os.path import join as pathjoin
from os.path import realpath
from shutil import copy2, copyfileobj, copytree, rmtree
from subprocess import STDOUT, CalledProcessError, check_output
from tempfile import mkdtemp, mkstemp

from .helpers import onerror, warn_open

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

__all__ = ("PuppetLogger",)


class PuppetLogger:  # pylint: disable=missing-docstring
    BUF_SIZE = 0x10000  # buffer size used to copy logs
    META_FILE = "log_metadata.json"
    PATH_RR = "rr-traces"
    PREFIX_SAN = "ffp_asan_%d.log" % (getpid(),)
    PREFIX_VALGRIND = "valgrind.%d" % (getpid(),)

    __slots__ = ("_base", "_logs", "_rr_packed", "closed", "watching", "working_path")

    def __init__(self, base_path=None):
        self._base = base_path
        self._logs = dict()
        self._rr_packed = False
        self.closed = True
        self.watching = dict()
        self.working_path = None
        self.reset()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.clean_up()

    def add_log(self, log_id, logfp=None):
        """Add a log file to the log manager.

        Args:
            log_id (str): ID of the log to add.
            logfp (file): File object to use. If None is provided a new log
                          file will be created.

        Returns:
            file: Newly added log file.
        """
        assert log_id not in self._logs
        assert not self.closed
        if logfp is None:
            logfp = PuppetLogger.open_unique(base_dir=self.working_path)
        self._logs[log_id] = logfp
        return logfp

    def add_path(self, name):
        """Add a directory that can be used as temporary storage for
        miscellaneous items such as additional debugger output.

        Args:
            name (str): Name of directory to create.

        Returns:
            str: Path of newly created directory.
        """
        assert not self.closed
        path = pathjoin(self.working_path, name)
        LOG.debug("adding path %r as %r", name, path)
        mkdir(path)
        return path

    def available_logs(self):
        """List of IDs for the available logs.

        Args:
            None

        Returns:
            list: A list containing log IDs.
        """
        return self._logs.keys()

    def clean_up(self, ignore_errors=False):
        """Remove log files from disk.

        Args:
            ignore_errors (bool): Ignore errors triggered by removing files and
                                  directories will be ignored.

        Returns:
            None
        """
        if not self.closed:
            self.close()
        if self.working_path is not None and isdir(self.working_path):
            for attempt in range(2):
                try:
                    rmtree(
                        self.working_path, ignore_errors=ignore_errors, onerror=onerror
                    )
                except OSError:
                    if attempt > 0:
                        warn_open(self.working_path)
                        raise
                    continue
                break
        self._logs.clear()
        self.working_path = None

    def clone_log(self, log_id, offset=None, target_file=None):
        """Create a copy of the specified log.

        Args:
            log_id (str): ID of the log to clone.
            target_file (str): The log contents will be saved to target_file.
            offset (int): Where to begin reading the log from.

        Returns:
            str: Name of the file containing the cloned log or None on failure.
        """
        log_fp = self.get_fp(log_id)
        if log_fp is None:
            return None
        if not log_fp.closed:
            log_fp.flush()
        with open(log_fp.name, "rb") as in_fp:
            if offset is not None:
                in_fp.seek(offset)
            if target_file is None:
                cpyfp = PuppetLogger.open_unique(base_dir=self._base)
                target_file = cpyfp.name
            else:
                # pylint: disable=consider-using-with
                cpyfp = open(target_file, "wb")
            try:
                copyfileobj(in_fp, cpyfp, self.BUF_SIZE)
            finally:
                cpyfp.close()
        return target_file

    def close(self):
        """Close all open file objects.

        Args:
            None

        Returns:
            None
        """
        for lfp in self._logs.values():
            if not lfp.closed:
                lfp.close()
        self.closed = True

    @property
    def files(self):
        """File names of log files.

        Args:
            None

        Yields:
            str: File names of log files.
        """
        for lfp in self._logs.values():
            if lfp.name is not None:
                yield lfp.name

    def get_fp(self, log_id):
        """Lookup log file object by ID.

        Args:
            log_id (str): ID of the log (stderr, stdout... etc).

        Returns:
            file: The file matching given ID otherwise None.
        """
        try:
            log_fp = self._logs[log_id]
        except KeyError:
            LOG.warning("log_id %r does not exist", log_id)
            return None
        if log_fp.name is None or not isfile(log_fp.name):
            raise IOError("log file %r does not exist" % log_fp.name)
        return log_fp

    def log_length(self, log_id):
        """Get the length of the specified log.

        Args:
            log_id (str): ID of the log to measure.

        Returns:
            int: Length of the specified log in bytes or None if the log does
                 not exist.
        """
        log_fp = self.get_fp(log_id)
        if log_fp is None:
            return None
        if not log_fp.closed:
            log_fp.flush()
        return stat(log_fp.name).st_size

    @staticmethod
    def open_unique(base_dir=None, mode="wb"):
        """Create and open a unique file.

        Args:
            base_dir (str): This is where the file will be created. If None is
                            passed mkstemp() will use the system default.
            mode (str): File mode. See documentation for open().

        Returns:
            file: An open file object.
        """
        tmp_fd, log_file = mkstemp(suffix=".txt", prefix="ffp_log_", dir=base_dir)
        os_close(tmp_fd)
        # use open() so the file object 'name' attribute is correct
        return open(log_file, mode)  # pylint: disable=consider-using-with

    def reset(self):
        """Reset logger for reuse.

        Args:
            None

        Returns:
            None
        """
        self.clean_up()
        self.closed = False
        self._rr_packed = False
        self.working_path = realpath(mkdtemp(prefix="ffplogs_", dir=self._base))

    def save_logs(
        self, dest, logs_only=False, meta=False, bin_path=None, rr_pack=False
    ):
        """The browser logs will be saved to dest. This can only be called
        after close() has been called.

        Args:
            dest (str): Destination path for log data. Existing files will be
                        overwritten.
            logs_only (bool): Do not include other data, including debugger
                              output files.
            meta (bool): Output JSON file containing log file meta data.
            bin_path (str): Path to Firefox binary.
            rr_pack (bool): Pack rr trace if required.

        Returns:
            None
        """
        assert self.closed, "save_logs() cannot be called before calling close()"
        assert self.working_path is not None

        # copy log to location specified by dest
        makedirs(dest, exist_ok=True)
        dest = abspath(dest)

        meta_map = dict()
        for log_id, log_fp in self._logs.items():
            out_name = "log_%s.txt" % log_id
            if meta:
                file_stat = stat(log_fp.name)
                meta_map[out_name] = {
                    field: getattr(file_stat, field)
                    for field in dir(stat_result)
                    if field.startswith("st_")
                }
            copy2(log_fp.name, pathjoin(dest, out_name))

        if not logs_only:
            rr_trace = pathjoin(self.working_path, self.PATH_RR, "latest-trace")
            if isdir(rr_trace):
                if rr_pack and not self._rr_packed:
                    LOG.debug("packing rr trace")
                    try:
                        check_output(["rr", "pack", rr_trace], stderr=STDOUT)
                        self._rr_packed = True
                    except (OSError, CalledProcessError):
                        LOG.warning("Error calling 'rr pack %s'", rr_trace)
                # copy `taskcluster-build-task` for use with Pernosco if available
                if bin_path is not None:
                    task_info = pathjoin(bin_path, "taskcluster-build-task")
                    if isfile(task_info):
                        moz_rr = pathjoin(rr_trace, "files.mozilla")
                        makedirs(moz_rr, exist_ok=True)
                        copy2(task_info, moz_rr)
                        LOG.debug("Copied 'taskcluster-build-task' to trace")

            for entry in scandir(self.working_path):
                if entry.is_dir():
                    copytree(entry.path, pathjoin(dest, entry.name), symlinks=True)

        if meta_map:
            with open(pathjoin(dest, self.META_FILE), "w") as json_fp:
                json_dump(meta_map, json_fp, indent=2, sort_keys=True)
