# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from json import dump as json_dump
from logging import getLogger
from os import close as os_close, getpid, listdir, makedirs, mkdir, stat, stat_result
from os.path import abspath, isdir, isfile, join as pathjoin, realpath
from shutil import copy2, copyfileobj, copytree, rmtree
from subprocess import CalledProcessError, check_output, STDOUT
from tempfile import mkdtemp, mkstemp

from .helpers import onerror, wait_on_files

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

__all__ = ("PuppetLogger",)


class PuppetLogger(object):
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
        """
        Add a log file to the log manager.

        @type log_id: String
        @param log_id: ID of the log to add.

        @type logfp: file
        @param logfp: logfp is a file object. If None is provided a new log file will be created.

        @rtype: file
        @return: file object of the newly added log file.
        """
        assert log_id not in self._logs
        assert not self.closed
        if logfp is None:
            logfp = PuppetLogger.open_unique(base_dir=self.working_path)
        self._logs[log_id] = logfp
        return logfp

    def add_path(self, name):
        """
        Add a directory that can be used as temporary storage for miscellaneous
        items such as additional debugger output.

        @type name: String
        @param name: name of path to create.

        @rtype: String
        @return: path of newly created directory
        """
        assert not self.closed
        path = pathjoin(self.working_path, name)
        LOG.debug("adding path %r as %r", name, path)
        mkdir(path)
        return path

    def available_logs(self):
        """
        List of IDs for the currently available logs.

        @rtype: list
        @return: A list containing log IDs
        """
        return self._logs.keys()

    def clean_up(self, ignore_errors=False, wait_delay=10):
        """
        Remove log files from disk.

        @type ignore_errors: bool
        @param ignore_errors: Errors triggered by removing files and directories
                              will be ignored.

        @type wait_delay: int
        @param wait_delay: Maximum amount of time to wait for files to close if
                           an error is hit before retrying.

        @rtype: None
        @return: None
        """
        if not self.closed:
            self.close()
        if self.working_path is not None and isdir(self.working_path):
            for attempt in range(2):
                try:
                    rmtree(self.working_path, ignore_errors=ignore_errors, onerror=onerror)
                except OSError:
                    if attempt > 0:
                        raise
                    wait_on_files(self.files, timeout=wait_delay)
                    continue
                break
        self._logs.clear()
        self.working_path = None

    def clone_log(self, log_id, offset=None, target_file=None):
        """
        Create a copy of the specified log.

        @type log_id: String
        @param log_id: ID of the log to clone.

        @type target_file: String
        @param target_file: The log contents will be saved to target_file.

        @type offset: int
        @param offset: Where to begin reading the log from

        @rtype: String or None
        @return: Name of the file containing the cloned log or None on failure
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
                cpyfp = PuppetLogger.open_unique()
                target_file = cpyfp.name
            else:
                cpyfp = open(target_file, "wb")
            try:
                copyfileobj(in_fp, cpyfp, self.BUF_SIZE)
            finally:
                cpyfp.close()
        return target_file

    def close(self):
        """
        Close all open file objects.

        @rtype: None
        @return: None
        """
        for lfp in self._logs.values():
            if not lfp.closed:
                lfp.close()
        self.closed = True

    @property
    def files(self):
        """
        Generator containing file names
        """
        for lfp in self._logs.values():
            if lfp.name is not None:
                yield lfp.name

    def get_fp(self, log_id):
        """
        Lookup log file object by ID.

        @type log_id: String
        @param log_id: ID of the log (stderr, stdout... etc).

        @rtype: file object
        @return: A file object if ID is valid otherwise None.
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
        """
        Get the length of the specified log.

        @type log_id: String
        @param log_id: ID of the log to measure.

        @rtype: int
        @return: length of the specified log in bytes or None if the log does not exist.
        """
        log_fp = self.get_fp(log_id)
        if log_fp is None:
            return None
        if not log_fp.closed:
            log_fp.flush()
        return stat(log_fp.name).st_size

    @staticmethod
    def open_unique(base_dir=None, mode="wb"):
        """
        Create and open a unique file.

        @type base_dir: String
        @param base_dir: This is where the file will be created. If None is passed
                         mkstemp() will use the system default.

        @type mode: String
        @param mode: File mode. See documentation for open().

        @rtype: file object
        @return: An open file object.
        """
        tmp_fd, log_file = mkstemp(
            suffix=".txt",
            prefix="ffp_log_",
            dir=base_dir)
        os_close(tmp_fd)
        # use open() so the file object 'name' attribute is correct
        return open(log_file, mode)

    def reset(self):
        """
        Reset logger for reuse.

        @rtype: None
        @return: None
        """
        self.clean_up()
        self.closed = False
        self._rr_packed = False
        self.working_path = realpath(mkdtemp(prefix="ffplogs_", dir=self._base))

    def save_logs(self, dest, logs_only=False, meta=False):
        """
        The browser logs will be saved to dest.
        This should only be called after close() has been called.

        @type dest: String
        @param dest: Destination path for log data. Existing files will be overwritten.

        @type logs_only: bool
        @param logs_only: Do not include other data, including debugger output files.

        @type meta: bool
        @param meta: Output JSON file containing log file meta data.

        @rtype: None
        @return: None
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
                meta_map[out_name] = {field: getattr(file_stat, field)
                                      for field in dir(stat_result) if field.startswith("st_")}
            copy2(log_fp.name, pathjoin(dest, out_name))

        if not logs_only:
            rr_trace = pathjoin(self.working_path, self.PATH_RR, "latest-trace")
            if not self._rr_packed and isdir(rr_trace):
                LOG.debug("packing rr trace")
                try:
                    check_output(["rr", "pack", rr_trace], stderr=STDOUT)
                    self._rr_packed = True
                except (OSError, CalledProcessError):
                    LOG.warning("Error calling 'rr pack %s'", rr_trace)

            for path in listdir(self.working_path):
                full_path = pathjoin(self.working_path, path)
                if not isdir(full_path):
                    continue
                copytree(full_path, pathjoin(dest, path), symlinks=True)

        if meta_map:
            with open(pathjoin(dest, self.META_FILE), "w") as json_fp:
                json_dump(meta_map, json_fp, indent=2, sort_keys=True)
