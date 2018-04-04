# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import shutil
import tempfile
import threading

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
        self.aborted = threading.Event()
        self.log_fp = tempfile.SpooledTemporaryFile(max_size=self.SPOOL_LIMIT, mode="w+b")
        self._worker = None


    def clean_up(self):
        self.log_fp.close()


    def dump_log(self, dst_fp):
        if self._worker is not None and self._worker.is_alive():
            raise RuntimeError("Worker must exit before dumping log")
        self.log_fp.seek(0)
        shutil.copyfileobj(self.log_fp, dst_fp, self.READ_BUF)


    def join(self):
        if self._worker is not None:
            self._worker.join()


    def log_available(self):
        return self.log_fp.tell() > 0
