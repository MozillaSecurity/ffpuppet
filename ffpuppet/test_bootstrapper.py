# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet bootstrapper tests"""
import socket
import sys
import threading

import pytest

from .bootstrapper import Bootstrapper
from .exceptions import BrowserTerminatedError, BrowserTimeoutError, LaunchError

def test_bootstrapper_01():
    """test Bootstrapper"""
    bts = Bootstrapper()
    try:
        assert bts.location.startswith("http://127.0.0.1:")
        assert int(bts.location.split(":")[-1]) > 1024
        with pytest.raises(BrowserTimeoutError):
            bts.wait(lambda: True, timeout=0.1)
        with pytest.raises(BrowserTerminatedError):
            bts.wait(lambda: False)
        is_done = threading.Event()
        def _fake_browser(port, error=False, timeout=None, payload_size=5120):
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 50 x 0.1 = 5 seconds
            conn.settimeout(0.1)
            attempts = 50
            # open connection
            while True:
                try:
                    conn.connect(("127.0.0.1", port))
                    # prevent test hangs
                    conn.settimeout(10)
                except socket.timeout:
                    attempts -= 1
                    if attempts > 0:
                        continue
                    conn.close()
                    raise
                break
            # send request and receive response
            try:
                if timeout is not None:
                    # 30s should be longer than our set timeout
                    timeout.wait(30)
                    return
                conn.sendall(b"A" * payload_size)
                conn.send(b"")
                if error:
                    conn.shutdown(socket.SHUT_RDWR)
                    return
                conn.recv(8192)
            finally:
                conn.close()
        # without redirect
        browser_thread = threading.Thread(target=_fake_browser, args=(bts.port,))
        try:
            browser_thread.start()
            bts.wait(browser_thread.is_alive, timeout=10)
        finally:
            browser_thread.join()
        # with redirect
        browser_thread = threading.Thread(target=_fake_browser, args=(bts.port,))
        try:
            browser_thread.start()
            bts.wait(browser_thread.is_alive, timeout=10, url="http://localhost/")
        finally:
            browser_thread.join()
        # callback failure
        browser_thread = threading.Thread(
            target=_fake_browser,
            args=(bts.port,),
            kwargs={"timeout": is_done})
        try:
            browser_thread.start()
            with pytest.raises(BrowserTerminatedError):
                bts.wait(lambda: False, timeout=10)
        finally:
            is_done.set()
            browser_thread.join()
        # timeout waiting for connection data
        is_done.clear()
        browser_thread = threading.Thread(
            target=_fake_browser,
            args=(bts.port,),
            kwargs={"timeout": is_done})
        try:
            browser_thread.start()
            with pytest.raises(BrowserTimeoutError):
                bts.wait(lambda: True, timeout=0.25)
        finally:
            is_done.set()
            browser_thread.join()
        # exhaust port range
        init_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if sys.platform.startswith("win"):
                init_soc.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)  # pylint: disable=no-member
            init_soc.bind(("127.0.0.1", 0))  # bind to a random free port
            try:
                Bootstrapper.PORT_MAX = init_soc.getsockname()[1]
                Bootstrapper.PORT_MIN = Bootstrapper.PORT_MAX
                with pytest.raises(LaunchError, match="Could not find available port"):
                    Bootstrapper()
            finally:
                Bootstrapper.PORT_MAX = 0xFFFF
                Bootstrapper.PORT_MIN = 0x4000
        finally:
            init_soc.close()
    finally:
        bts.close()
