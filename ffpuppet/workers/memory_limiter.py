# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import threading
import time

from psutil import AccessDenied, NoSuchProcess, Process

from . import puppet_worker

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class MemoryLimiterWorker(puppet_worker.BaseWorker):
    """
    MemoryLimiterWorker intended to be used with ffpuppet to limit the about of memory
    used by the browser process.
    """
    name = os.path.splitext(os.path.basename(__file__))[0]

    def start(self, puppet, memory_limit):
        self._worker = threading.Thread(target=self._run, args=(puppet, memory_limit))
        self._worker.start()


    def _run(self, puppet, limit):
        """
        _run(puppet, limit) -> None
        Use psutil to actively monitor the amount of memory in use by the process with the
        matching target process ID. If that amount exceeds limit the process will be terminated.
        Information is collected and stored to log_fp.

        returns None
        """

        target_pid = puppet.get_pid()
        if target_pid is None:
            return

        try:
            process = Process(target_pid)
        except (AccessDenied, NoSuchProcess):
            return

        while puppet.is_running():
            proc_info = list()
            total_usage = 0
            try:
                cur_rss = process.memory_info().rss
                total_usage += cur_rss
                proc_info.append((process.pid, cur_rss))
                for child in process.children():
                    try:
                        cur_rss = child.memory_info().rss
                        total_usage += cur_rss
                        proc_info.append((child.pid, cur_rss))
                    except (AccessDenied, NoSuchProcess):
                        pass
            except (AccessDenied, NoSuchProcess):
                break  # process is dead?

            if total_usage >= limit:
                self.aborted.set()
                puppet._terminate(5)  # pylint: disable=protected-access
                self.log_fp.write(("MEMORY_LIMIT_EXCEEDED: %d\n" % total_usage).encode("utf-8"))
                self.log_fp.write(("Current Limit: %d (%dMB)\n" % (limit, limit/1048576)).encode("utf-8"))
                self.log_fp.write(("Parent PID: %d\n" % target_pid).encode("utf-8"))
                for pid, proc_usage in proc_info:
                    self.log_fp.write(("-> PID %6d: %10d\n" % (pid, proc_usage)).encode("utf-8"))
                break

            time.sleep(0.25)  # check maximum 4x per second
