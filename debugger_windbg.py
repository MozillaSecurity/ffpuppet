# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import
import os
import multiprocessing

try:
    import pykd
except ImportError:
    pykd = None

from . import puppet_worker

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class DebuggerPyKDWorker(puppet_worker.BaseWorker):
    """
    DebuggerPyKDWorker is intended to be used with ffpuppet to provide basic debugger
    information with minimal interaction with the browser process.

    Note: Only works with x86 builds at the moment.
    """
    available = pykd is not None
    name = os.path.splitext(os.path.basename(__file__))[0]

    def start(self, process_id):
        self._worker = multiprocessing.Process(target=_run, args=(process_id, self._log))
        self._worker.start()


def _run(process_id, log_file):
    """
    _run(process_id, log_file) -> None
    _run() takes the process_id of the process to attach to.
    The collected debugger data is saved to log_file.

    returns None
    """
    with open(log_file, "w") as out_fp:
        out_fp.write("\nAttaching WinDBG debugger...\n")
        try:
            session_id = pykd.attachProcess(process_id)
            while True:
                pykd.go()
                if not pykd.getLastException().firstChance:
                    break
            dbg_info = pykd.dbgCommand(".lastevent;r;k")
            if dbg_info is not None:
                out_fp.write("%s\n" % dbg_info)
            pykd.detachProcess(session_id)
            out_fp.write("Debugger detached.\n")
        except pykd.DbgException as dbg_e:
            out_fp.write("DbgException: %s\n" % dbg_e)
        except KeyboardInterrupt:
            pass
