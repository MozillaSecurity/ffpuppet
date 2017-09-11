# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import re
import shutil
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
    READ_BUF = 0x10000 # 64KB
    SPOOL_LIMIT = 0x10000 # 64KB

    available = True
    name = "BaseWorker" # override in subclass

    def __init__(self):
        self.log_fp = tempfile.SpooledTemporaryFile(max_size=self.SPOOL_LIMIT, mode="w+b")
        self._worker = None


    def clean_up(self):
        self.log_fp.close()


    def collect_log(self, dst_fp):
        if self._worker is not None and self._worker.is_alive():
            raise RuntimeError("Worker must exit before collecting log")

        self.log_fp.seek(0)
        shutil.copyfileobj(self.log_fp, dst_fp, self.READ_BUF)


    def join(self):
        if self._worker is not None:
            self._worker.join()


    def log_available(self):
        return self.log_fp.tell() > 0


def gdb_log_dumpper(pid):
    try:
        gdb_bin = subprocess.check_output(["which", "gdb"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        return b"Could not dump process info, gdb is not installed"

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

        with tempfile.TemporaryFile(mode="w+b") as log_fp:
            try:
                subprocess.check_call(gdb_cmd, shell=False, stderr=log_fp, stdout=log_fp)
            except subprocess.CalledProcessError:
                log_fp.seek(0)
                return b"Error executing: %s\n%s" % (" ".join(gdb_cmd).encode("utf-8"), log_fp.read())
            log_fp.seek(0)

            flt = re.compile(
                r"(\[New LWP \d+\]|" \
                r"No locals\.|" \
                r"Quit anyway\? \(y or n\) \[answered Y; input not from terminal\])$")
            return b"\n".join([x for x in log_fp.read().splitlines() if flt.match(x) is None]).encode("utf-8")
    finally:
        if os.path.isfile(cmd_file):
            os.remove(cmd_file)
