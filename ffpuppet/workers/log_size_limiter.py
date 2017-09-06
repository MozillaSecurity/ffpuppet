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
        self._worker = threading.Thread(target=_run, args=(puppet, limit, self.log_fp))
        self._worker.start()


def _run(puppet, max_size, log_fp):
    """
    _run(puppet, max_size) -> None

    returns None
    """

    while puppet.is_running():
        if not os.path.isfile(puppet._log.name):
            break

        current_size = os.stat(puppet._log.name).st_size
        if current_size > max_size:
            puppet._terminate(5)
            log_fp.write("LOG_SIZE_LIMIT_EXCEEDED: %d\n" % current_size)
            log_fp.write("Current Limit: %d (%dMB)\n" % (max_size, max_size/1048576))
            break
        time.sleep(0.1) # don't be a CPU hog
