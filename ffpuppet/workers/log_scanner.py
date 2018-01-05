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
        self._worker = threading.Thread(target=self._run, args=(puppet,))
        self._worker.start()


    def _run(self, puppet):
        """
        _run(puppet) -> None

        returns None
        """

        # logs to scan
        logs = (
            {"fname": puppet._logs.get_fp("stderr").name, "lbuf": "", "offset": 0},
            {"fname": puppet._logs.get_fp("stdout").name, "lbuf": "", "offset": 0})

        while puppet.is_running():
            for log in logs:
                # check if file has new data
                if os.stat(log["fname"]).st_size <= log["offset"]:
                    continue
                # collect new data
                with open(log["fname"], "r") as scan_fp:
                    scan_fp.seek(log["offset"], os.SEEK_SET)
                    data = scan_fp.read(0x20000) # 128KB
                    log["offset"] = scan_fp.tell()
                # prepend chunk of previously read line to data
                if log["lbuf"]:
                    data = "".join([log["lbuf"], data])

                for token in puppet._abort_tokens:
                    match = token.search(data)
                    if match:
                        self.aborted.set()
                        puppet._terminate(5)  # TODO: this could fail, use psutil.
                        self.log_fp.write(("TOKEN_LOCATED: %s\n" % match.group()).encode("utf-8"))
                        return

                try:
                    log["lbuf"] = data.rsplit("\n", 1)[1]
                except IndexError:
                    log["lbuf"] = data

            time.sleep(0.05) # don't be a CPU hog
