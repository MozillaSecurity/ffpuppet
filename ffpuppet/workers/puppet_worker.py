# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import re
import subprocess
import tempfile
import time

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class BaseWorker(object):
    """
    BaseWorker is the base class that is to be used to create workers to perform
    asynchronous tasks related to FFPuppet or the browser process.
    """
    available = True
    name = "BaseWorker" # override in subclass

    def __init__(self):
        self._log = self._create_logfile()
        self._worker = None


    @staticmethod
    def _create_logfile():
        tmp_fd, log = tempfile.mkstemp(
            suffix="_log.txt",
            prefix=time.strftime("ffpworker_%m-%d_%H-%M-%S_"))
        os.close(tmp_fd)

        return log


    def clean_up(self):
        if os.path.isfile(self._log):
            os.remove(self._log)


    def collect_log(self):
        if self._worker is not None and self._worker.is_alive():
            raise RuntimeError("Worker must exit before collecting log")

        if not os.path.isfile(self._log):
            return None

        with open(self._log, "r") as log_fp:
            log_data = log_fp.read()

        return log_data.strip()


    def join(self):
        if self._worker is not None:
            self._worker.join()


def gdb_log_dumpper(pid):
    try:
        gdb_bin = subprocess.check_output(["which", "gdb"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        return "Could not dump process info, gdb is not installed"

    tmp_fd, cmd_file = tempfile.mkstemp(
        suffix="_gdb.cmd",
        prefix=time.strftime("ffpworker_%m-%d_%H-%M-%S_"))
    os.close(tmp_fd)
    try:
        # create temporary cmd file
        with open(cmd_file, "w") as cmd_fp:
            cmd_fp.write("if $_siginfo\n")
            cmd_fp.write("  echo connected\n")
            cmd_fp.write("else\n")
            cmd_fp.write("  quit 1\n")
            cmd_fp.write("end\n")
            cmd_fp.write("echo \\n received signal SIG (this is here to trigger FM parsing)\\n\n")
            cmd_fp.write("bt\n")
            cmd_fp.write("info threads\n")
            cmd_fp.write("quit\n")

        # this requires kernel.yama.ptrace_scope=0
        # on Ubuntu run "sudo sysctl kernel.yama.ptrace_scope=0"
        gdb_cmd = [gdb_bin, "-q", "-batch", "-x", cmd_file, "-p", "%d" % pid]

        with tempfile.TemporaryFile(mode="w+") as log_fp:
            try:
                subprocess.check_call(gdb_cmd, shell=False, stderr=log_fp, stdout=log_fp)
            except subprocess.CalledProcessError:
                log_fp.seek(0)
                return "Error executing: %s\n%s" % (" ".join(gdb_cmd), log_fp.read())
            log_fp.seek(0)

            flt = re.compile(
                r"(\[New LWP \d+\]|" \
                r"No locals\.|" \
                r"Quit anyway\? \(y or n\) \[answered Y; input not from terminal\])$")
            return "\n".join([x for x in log_fp.read().splitlines() if flt.match(x) is None])
    finally:
        if os.path.isfile(cmd_file):
            os.remove(cmd_file)
