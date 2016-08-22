# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
debugger_windbg.py is intended to be used with ffpuppet to provide basic debugger
information with minimal iteration with the process.

Note: Only works with x86 builds at the moment.
"""

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

import pykd

COMPLETE_TOKEN = "Debugger session complete.\n"

def debug(process_id, output_log):
    """
    debug(process_id, output_log)
    Use debug() takes the process_id if the process to attach to and the collected
    debug data is saved to output_log.

    returns None
    """
    with open(output_log, "w") as out_fp:
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
        finally:
            # Add COMPLETE_TOKEN message to help sync the processes
            out_fp.write(COMPLETE_TOKEN)
