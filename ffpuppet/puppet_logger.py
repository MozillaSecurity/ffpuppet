# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import logging
import os
import shutil
import tempfile

from .helpers import onerror, wait_on_files

log = logging.getLogger("puppet_logger")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

__all__ = ("PuppetLogger")


class PuppetLogger(object):
    LOG_ASAN_PREFIX = "ffp_asan_%d.log" % os.getpid()  # prefix for ASan logs
    LOG_BUF_SIZE = 0x10000  # buffer size used to copy logs
    META_FILE = "log_metadata.json"

    def __init__(self):
        self._logs = dict()
        self.closed = True
        self.working_path = None
        self.reset()


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
        if self.working_path is not None and os.path.isdir(self.working_path):
            for attempt in range(2):
                try:
                    shutil.rmtree(self.working_path, ignore_errors=ignore_errors, onerror=onerror)
                    break
                except OSError:
                    if attempt > 0:
                        raise
                    wait_on_files(self.files, timeout=wait_delay)
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
                shutil.copyfileobj(in_fp, cpyfp, self.LOG_BUF_SIZE)
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
            log.warning("log_id %r does not exist", log_id)
            return None
        if log_fp.name is None or not os.path.isfile(log_fp.name):
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
        return os.stat(log_fp.name).st_size


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
        tmp_fd, log_file = tempfile.mkstemp(
            suffix=".txt",
            prefix="ffp_log_",
            dir=base_dir)
        os.close(tmp_fd)
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
        self.working_path = os.path.realpath(tempfile.mkdtemp(prefix="ffplogs_"))


    def save_logs(self, log_path, meta=False):
        """
        The browser logs will be saved to log_path.
        This should only be called after close().

        @type log_path: String
        @param log_path: Directory to copy log files to. Existing files will be overwritten.

        @type meta: bool
        @param meta: Output JSON file containing log file meta data

        @rtype: None
        @return: None
        """
        assert self.closed, "save_logs() cannot be called before calling close()"
        meta_map = dict() if meta else None
        # copy log to location specified by log_path
        if not os.path.isdir(log_path):
            os.makedirs(log_path)
        log_path = os.path.abspath(log_path)

        for log_id, log_fp in self._logs.items():
            out_name = "log_%s.txt" % log_id
            if meta_map is not None:
                file_stat = os.stat(log_fp.name)
                meta_map[out_name] = {field: getattr(file_stat, field)
                                      for field in dir(os.stat_result) if field.startswith("st_")}
            shutil.copy2(log_fp.name, os.path.join(log_path, out_name))

        if meta_map is not None:
            with open(os.path.join(log_path, self.META_FILE), "w") as json_fp:
                json.dump(meta_map, json_fp, indent=2, sort_keys=True)
