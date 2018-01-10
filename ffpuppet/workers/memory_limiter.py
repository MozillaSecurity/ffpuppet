# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import threading
import time

import psutil

from . import puppet_worker

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class MemoryLimiterWorker(puppet_worker.BaseWorker):
    """
    MemoryLimiterWorker intended to be used with ffpuppet to limit the about of memory
    used by the browser process.
    """
    name = os.path.splitext(os.path.basename(__file__))[0]

    def start(self, process_id, memory_limit):
        self._worker = threading.Thread(target=self._run, args=(process_id, memory_limit))
        self._worker.start()


    def _run(self, process_id, limit):
        """
        _run(process_id, limit) -> None
        Use psutil to actively monitor the amount of memory in use by the process with the
        matching process_id. If that amount exceeds limit the process will be terminated.
        Information is collected and stored to log_fp.

        returns None
        """

        try:
            process = psutil.Process(process_id)
        except psutil.NoSuchProcess:
            return

        while process.is_running():
            proc_info = list()
            total_usage = 0
            try:
                cur_rss = process.memory_info().rss
                total_usage += cur_rss
                proc_info.append((process.pid, cur_rss))
                for child in process.children(recursive=True):
                    try:
                        cur_rss = child.memory_info().rss
                        total_usage += cur_rss
                        proc_info.append((child.pid, cur_rss))
                    except psutil.NoSuchProcess:
                        pass
            except psutil.NoSuchProcess:
                break # process is dead?

            if total_usage >= limit:
                self.aborted.set()
                try:
                    process.kill()
                    process.wait()
                except psutil.NoSuchProcess:
                    pass # process is dead?

                self.log_fp.write(("MEMORY_LIMIT_EXCEEDED: %d\n" % total_usage).encode("utf-8"))
                self.log_fp.write(("Current Limit: %d (%dMB)\n" % (limit, limit/1048576)).encode("utf-8"))
                self.log_fp.write(("Parent PID: %d\n" % process_id).encode("utf-8"))
                for pid, proc_usage in proc_info:
                    self.log_fp.write(("-> PID %6d: %10d\n" % (pid, proc_usage)).encode("utf-8"))
                break

            time.sleep(0.25) # check maximum 4x per second
