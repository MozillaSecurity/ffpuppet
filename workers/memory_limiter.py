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
            try:
                proc_mem = process.memory_info().rss
                for child in process.children(recursive=True):
                    try:
                        proc_mem += child.memory_info().rss
                    except psutil.NoSuchProcess:
                        pass
            except psutil.NoSuchProcess:
                break# process is dead?

            # did we hit the memory limit?
            if proc_mem >= limit:
                if plat == "linux":
                    log_fp.write(puppet_worker.gdb_log_dumpper(process_id))
                    log_fp.write("\n")
                log_fp.write("MEMORY_LIMIT_EXCEEDED: %d\n" % proc_mem)
                try:
                    process.terminate()
                    process.wait()
                except psutil.NoSuchProcess:
                    pass # process is dead?
                break

            time.sleep(0.1) # check 10x a second
