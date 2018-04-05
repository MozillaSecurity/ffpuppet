# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import shutil
import tempfile
import time

from .helpers import onerror

log = logging.getLogger("puppet_logger") # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

__all__ = ("PuppetLogger")


class PuppetLogger(object):
    LOG_ASAN_PREFIX = "ffp_asan_%d.log" % os.getpid() # prefix for ASan logs
    LOG_BUF_SIZE = 0x10000 # buffer size used to copy logs

    def __init__(self):
        self._logs = dict()
        self.closed = False
        self.working_path = tempfile.mkdtemp(prefix="ffplogs_")


    def add_log(self, log_id, logfp=None):
        """
        Add a log file to the log manager.

        @type log_id: String
        @param log_id: The id (key) of the log to clone (stderr, stdout... etc).

        @type logfp: file
        @param logfp: logfp is a file object. If None is provided a new log file will be created.

        @rtype: file
        @return: file object of the newly added log file.
        """
        assert log_id not in self._logs
        assert not self.closed
        if logfp is None:
            logfp = PuppetLogger.open_unique()
        self._logs[log_id] = logfp
        return logfp


    def available_logs(self):
        """
        List of IDs for the currently available logs.

        @rtype: list
        @return: A list containing 'log_id's
        """
        return self._logs.keys()


    def clean_up(self):
        """
        Remove log files from disk.

        @rtype: None
        @return: None
        """
        self.close()
        for lfp in self._logs.values():
            if lfp.name is not None and os.path.isfile(lfp.name):
                os.remove(lfp.name)
        self._logs = dict()

        if self.working_path is not None and os.path.isdir(self.working_path):
            shutil.rmtree(self.working_path, onerror=onerror)
        self.working_path = None


    def clone_log(self, log_id, offset=None, target_file=None):
        """
        Create a copy of the current browser log.

        @type log_id: String
        @param log_id: The id (key) of the log to clone (stderr, stdout... etc).

        @type target_file: String
        @param target_file: The log contents will be saved to target_file.

        @type offset: int
        @param offset: Where to begin reading the log from

        @rtype: String or None
        @return: Name of the file containing the cloned log or None on failure
        """

        cur_log = self.get_fp(log_id)
        if cur_log is None:
            return None

        with open(cur_log.name, "rb") as logfp:
            if offset is not None:
                logfp.seek(offset)
            if target_file is None:
                cpyfp = PuppetLogger.open_unique()
                target_file = cpyfp.name
            else:
                cpyfp = open(target_file, "wb")
            try:
                shutil.copyfileobj(logfp, cpyfp, self.LOG_BUF_SIZE)
            finally:
                cpyfp.close()

        return target_file


    def close(self):
        for lfp in self._logs.values():
            if not lfp.closed:
                lfp.close()
        self.closed = True


    def get_fp(self, log_id):
        try:
            cur_log = self._logs[log_id]
        except KeyError:
            log.warning("log_id %r does not exist", log_id)
            return None
        if cur_log.name is None or not os.path.isfile(cur_log.name):
            raise IOError("log file %r does not exist" % cur_log.name)
        try:
            cur_log.flush()
        except ValueError: # ignore exception if file is closed
            pass
        return cur_log


    def log_length(self, log_id):
        """
        Get the length of the browser log.

        @type log_id: String
        @param log_id: The id (key) of the log to clone (stderr, stdout... etc).

        @rtype: int
        @return: length of the current browser log in bytes or None if the log does not exist.
        """
        cur_log = self.get_fp(log_id)
        if cur_log is None:
            return None
        return os.stat(cur_log.name).st_size


    @staticmethod
    def open_unique(mode="wb"):
        """
        Create and open a unique file.

        @type mode: String
        @param mode: File mode. See documentation for open().

        @rtype: file object
        @return: An open file object.
        """

        tmp_fd, log_file = tempfile.mkstemp(
            suffix="_log.txt",
            prefix=time.strftime("ffp_%Y-%m-%d_%H-%M-%S_"))
        os.close(tmp_fd)

        # open with 'open' so the file object 'name' attribute is correct
        return open(log_file, mode)


    def reset(self):
        """
        Reset logger for reuse.

        @rtype: None
        @return: None
        """
        self.clean_up()
        self.closed = False
        self.working_path = tempfile.mkdtemp(prefix="ffplogs_")


    def save_logs(self, log_path):
        """
        The browser log will be saved to log_file.
        This should only be called after close().

        @type log_path: String
        @param log_path: Directory to dump log file in. Existing files will be overwritten.

        @rtype: None
        @return: None
        """

        # copy log to location specified by log_file
        if not os.path.isdir(log_path):
            os.makedirs(log_path)

        for log_id, log_fp in self._logs.items():
            shutil.copy(log_fp.name, os.path.join(os.path.abspath(log_path), "log_%s.txt" % log_id))
