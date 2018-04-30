# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import shutil
import subprocess
import tempfile

log = logging.getLogger("ffpuppet")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__all__ = ("process_minidumps")

class MinidumpParser(object):
    MDSW_BIN = "minidump_stackwalk"
    MDSW_MAX_STACK = 150

    def __init__(self, scan_path):
        if not os.path.isdir(scan_path):
            raise IOError("scan_path does not exist: %r" % scan_path)

        self.dump_path = scan_path
        self.dump_files = {fname for fname in os.listdir(self.dump_path) if fname.endswith(".dmp")}
        self.symbols_path = None
        self._include_raw = os.environ.get("FFP_DEBUG_MDSW") is not None


    def _call_mdsw(self, dump_file, out_fp, extra_flags=None, include_stderr=False):
        cmd = [MinidumpParser.MDSW_BIN]
        if extra_flags is None:
            extra_flags = list()
        cmd += extra_flags
        cmd.append(dump_file)
        cmd.append(self.symbols_path)

        try:
            err_fp = out_fp if include_stderr else open(os.devnull, "w")
            ret_val = subprocess.call(cmd, stdout=out_fp, stderr=err_fp)
        finally:
            if not include_stderr:
                # close devnull
                err_fp.close()

        if ret_val != 0:
            log.warning("minidump_stackwalk %s returned %r", " ".join(extra_flags), ret_val)

        out_fp.seek(0)


    def _read_registers(self, dump_file, log_fp):
        log.debug("calling minidump_stackwalk on %s", dump_file)
        with tempfile.TemporaryFile() as out_fp:
            self._call_mdsw(dump_file, out_fp)
            found_registers = False
            for line in out_fp:  # pylint: disable=not-an-iterable
                if not found_registers:
                    # look for the beginning of the register dump
                    if b"(crashed)" in line:
                        found_registers = True
                    continue
                line = line.lstrip()
                if line.startswith(b"0"):
                    continue  # skip first line
                if b"=" not in line:
                    break  # we reached the end
                log_fp.write(line)
            log.debug("collected register info: %r", found_registers)


    def _read_stacktrace(self, dump_file, log_fp, raw_fp=None):
        log.debug("calling minidump_stackwalk -m on %s", dump_file)
        with tempfile.TemporaryFile() as out_fp:
            include_stderr = raw_fp is not None
            self._call_mdsw(dump_file, out_fp, extra_flags=["-m"], include_stderr=include_stderr)
            if raw_fp is not None:
                shutil.copyfileobj(out_fp, raw_fp, 0x10000)  # read in 64K chunks
                out_fp.seek(0)
            crash_thread = None
            line_count = 0  # lines added to the log so far
            for line in out_fp:  # pylint: disable=not-an-iterable
                if b"|" not in line or line.startswith(b"Module|"):
                    continue # ignore line

                # check if this is a stack entry (starts with '#|')
                try:
                    t_id = int(line.split(b"|", 1)[0])
                    # assume that the first entry in the stack is the crash_thread
                    # NOTE: an alternative would be to parse the 'Crash|' line
                    if crash_thread is None:
                        crash_thread = t_id
                    elif t_id != crash_thread:
                        break
                except ValueError:
                    pass  # not a stack entry

                log_fp.write(line)
                line_count += 1
                if line_count >= MinidumpParser.MDSW_MAX_STACK:
                    log.warning("MDSW_MAX_STACK (%d) limit reached", MinidumpParser.MDSW_MAX_STACK)
                    log_fp.write(b"WARNING: Hit line output limit!")
                    break


    def collect_logs(self, cb_create_log, symbols_path):
        if not os.path.isdir(symbols_path):
            raise IOError("symbols_path does not exist: %r" % symbols_path)
        self.symbols_path = symbols_path

        for count, fname in enumerate(self.dump_files, start=1):
            log_fp = cb_create_log("minidump_%02d" % count)
            file_path = os.path.join(self.dump_path, fname)
            self._read_registers(file_path, log_fp)
            # create log for raw mdsw stack output if needed
            raw_fp = cb_create_log("raw_mdsw_%02d" % count) if self._include_raw else None
            self._read_stacktrace(file_path, log_fp, raw_fp)
            if log_fp.tell() < 1:
                log.warning("minidump_stackwalk log was empty")
                log_fp.write(b"WARNING: minidump_stackwalk log was empty")


    @staticmethod
    def mdsw_available():
        try:
            with open(os.devnull, "w") as null_fp:
                subprocess.call([MinidumpParser.MDSW_BIN], stdout=null_fp, stderr=null_fp)
        except OSError:
            return False
        return True


def process_minidumps(scan_path, symbols_path, cb_create_log):
    """
    Scan for minidump (.dmp) files a in scan_path. If dumps are found they are parsed and
    new logs are added via the cb_create_log callback.

    @type scan_path: String
    @param scan_path: Directory potentially containing minidump files

    @type symbols_path: String
    @param symbols_path: Directory containing symbols for the target binary

    @type cb_create_log: callback
    @param cb_create_log: A callback to the add_log() of a PuppetLogger

    @rtype: None
    @return: None
    """
    assert isinstance(scan_path, str)
    assert isinstance(symbols_path, str)
    assert callable(cb_create_log)

    if not os.path.isdir(scan_path):
        log.debug("scan_path %r does not exist", scan_path)
        return

    md_parser = MinidumpParser(scan_path)
    if not md_parser.dump_files:
        log.debug("scan_path %r did not contain '.dmp' files", scan_path)
        return

    if not os.path.isdir(symbols_path):
        log.warning("symbols_path not found: %r", symbols_path)
        return

    if not md_parser.mdsw_available():
        log.warning("Found a minidump, but can't process it without minidump_stackwalk."
                    " See README.md for how to obtain it.")
        return

    md_parser.collect_logs(cb_create_log, symbols_path)
