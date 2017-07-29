# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import platform
import threading
import time

try:
    import psutil
except ImportError:
    psutil = None

from . import puppet_worker

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class MemoryLimiterWorker(puppet_worker.BaseWorker):
    """
    MemoryLimiterWorker intended to be used with ffpuppet to limit the about of memory
    used by the browser process.
    """
    available = psutil is not None
    name = os.path.splitext(os.path.basename(__file__))[0]

    def start(self, process_id, memory_limit):
        self._worker = threading.Thread(target=_run, args=(process_id, memory_limit, self._log))
        self._worker.start()


def _run(process_id, limit, log_file):
    """
    _run(process_id, limit, log_file) -> None
    Use psutil to actively monitor the amount of memory in use by the process with the
    matching process_id. If that amount exceeds limit the process will be terminated.
    Information is collected and stored in log_file.

    returns None
    """

    plat = platform.system().lower()
    with open(log_file, "w") as log_fp:
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
                if plat == "linux":
                    mem_hog = (0, 0) # process using the most memory
                    for pid, proc_usage in proc_info:
                        if mem_hog[1] < proc_usage:
                            mem_hog = (pid, proc_usage)
                    log_fp.write(puppet_worker.gdb_log_dumpper(mem_hog[0]))
                    log_fp.write("\n")

                try:
                    process.kill()
                    process.wait()
                except psutil.NoSuchProcess:
                    pass # process is dead?

                log_fp.write("MEMORY_LIMIT_EXCEEDED: %d\n" % total_usage)
                log_fp.write("Current Limit: %d (%dMB)\n" % (limit, limit/1048576))
                log_fp.write("Parent PID: %d\n" % process_id)
                for pid, proc_usage in proc_info:
                    log_fp.write("-> PID %6d: %10d\n" % (pid, proc_usage))

                break

            time.sleep(0.1) # check 10x a second
