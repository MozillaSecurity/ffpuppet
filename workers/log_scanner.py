# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import re
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
    _run(process_id, limit, log_file) -> None

    returns None
    """

    line_buffer = ""
    offset = 0
    token_found = None
    while puppet.is_running():
        if not os.path.isfile(puppet._log.name):
            return

        with open(puppet._log.name, "r") as scan_fp:
            scan_fp.seek(0, os.SEEK_END)
            # check if file has new data
            if scan_fp.tell() > offset:
                scan_fp.seek(offset, os.SEEK_SET)
                data = scan_fp.read()
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
            if isinstance(token, re._pattern_type):
                m = token.search(data)
                if m:
                    token_found = m.group()
            elif isinstance(token, str):
                if data.find(token) > -1:
                    token_found = token

        if token_found is not None:
            puppet._proc.terminate()
            with open(log_file, "w") as log_fp:
                log_fp.write("TOKEN_LOCATED: %s\n" % token_found)
            puppet._proc.wait()
            break

        time.sleep(0.05) # don't be a CPU hog
