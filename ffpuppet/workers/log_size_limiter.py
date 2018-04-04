# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import threading
import time

from . import puppet_worker

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class LogSizeLimiterWorker(puppet_worker.BaseWorker):
    """
    LogSizeLimiterWorker will monitor the file size of the browser log.
    When the max size is exceeded terminate() is called on the browser process.
    """
    name = os.path.splitext(os.path.basename(__file__))[0]

    def start(self, puppet, limit):
        self._worker = threading.Thread(target=self._run, args=(puppet, limit))
        self._worker.start()


    def _run(self, puppet, max_size):
        """
        _run(puppet, max_size) -> None

        returns None
        """

        stderr_log = puppet._logs.get_fp("stderr").name
        stdout_log = puppet._logs.get_fp("stdout").name
        while puppet.is_running():
            err_size = os.stat(stderr_log).st_size
            out_size = os.stat(stdout_log).st_size
            current_size = err_size + out_size
            if current_size > max_size:
                self.aborted.set()
                puppet._terminate(5)  # pylint: disable=protected-access
                self.log_fp.write(("LOG_SIZE_LIMIT_EXCEEDED: %d\n" % current_size).encode("utf-8"))
                self.log_fp.write(("Current Limit: %d (%dMB)\n" % (max_size, max_size/1048576)).encode("utf-8"))
                self.log_fp.write(("stderr log: %d (%dMB)\n" % (err_size, err_size/1048576)).encode("utf-8"))
                self.log_fp.write(("stdout log: %d (%dMB)\n" % (out_size, out_size/1048576)).encode("utf-8"))
                break
            time.sleep(0.2) # don't be a CPU hog
