# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import threading
import time

from . import puppet_worker

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class LogScannerWorker(puppet_worker.BaseWorker):
    """
    LogScannerWorker will search through the browser log until a token is found.
    When a token is found terminate() is called on the browser process.
    """
    name = os.path.splitext(os.path.basename(__file__))[0]

    def start(self, puppet):
        self._worker = threading.Thread(target=_run, args=(puppet, self._log))
        self._worker.start()


def _run(puppet, log_file):
    """
    _run(puppet, log_file) -> None

    returns None
    """

    line_buffer = ""
    offset = 0
    while puppet.is_running():
        if not os.path.isfile(puppet._log.name):
            return

        with open(puppet._log.name, "r") as scan_fp:
            scan_fp.seek(0, os.SEEK_END)
            # check if file has new data
            if scan_fp.tell() > offset:
                scan_fp.seek(offset, os.SEEK_SET)
                data = scan_fp.read(0x10000) # 64KB
                offset = scan_fp.tell()
            else:
                data = None

        # don't be a CPU hog if there is no new data
        if data is None:
            time.sleep(0.1)
            continue

        # prepend chunk of previously read line to data
        if line_buffer:
            data = "".join([line_buffer, data])

        try:
            data, line_buffer = data.rsplit("\n", 1)
        except ValueError:
            line_buffer = data

        for token in puppet._abort_tokens:
            match = token.search(data)
            if match:
                puppet._proc.terminate()
                puppet._proc.wait()
                with open(log_file, "w") as log_fp:
                    log_fp.write("TOKEN_LOCATED: %s\n" % match.group())
                break

        time.sleep(0.05) # don't be a CPU hog
