# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import errno
import logging
import platform
import random
import socket
import time

from .exceptions import BrowserTerminatedError, BrowserTimeoutError, LaunchError


log = logging.getLogger("ffpuppet")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__all__ = ("Bootstrapper",)


class Bootstrapper(object):
    BUF_SIZE = 4096  # receive buffer size
    PORT_MAX = 0xFFFF  # bootstrap range
    PORT_MIN = 0x2000  # bootstrap range
    PORT_RETRIES = 100  # number of attempts to find an available port

    __slots__ = ("_socket",)

    def __init__(self, poll_wait=0.25):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if platform.system().startswith("Windows"):
            self._socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_EXCLUSIVEADDRUSE,  # pylint: disable=no-member
                1)
        self._socket.settimeout(poll_wait)
        for _ in range(self.PORT_RETRIES):
            try:
                self._socket.bind(("127.0.0.1", random.randint(self.PORT_MIN, self.PORT_MAX)))
                self._socket.listen(5)
            except socket.error as soc_e:
                if soc_e.errno in (errno.EADDRINUSE, 10013):
                    # Address already in use
                    continue
                raise soc_e  # pragma: no cover
            break
        else:
            self._socket.close()
            raise LaunchError("Could not find available port")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    @property
    def location(self):
        assert self._socket is not None
        return "http://127.0.0.1:%d" % self.port

    @property
    def port(self):
        assert self._socket is not None
        return self._socket.getsockname()[1]

    def wait(self, cb_continue, timeout=60, url=None):
        assert self._socket is not None
        start_time = time.time()
        time_limit = start_time + timeout
        try:
            conn = None
            log.debug("waiting for browser connection...")
            while True:
                try:
                    conn, _ = self._socket.accept()
                except socket.timeout:
                    if not cb_continue():
                        raise BrowserTerminatedError("Failure waiting for browser connection")
                    if time.time() >= time_limit:
                        raise BrowserTimeoutError("Timeout waiting for browser connection")
                    continue
                break
            conn.settimeout(1)
            received = False
            log.debug("waiting to receive browser request...")
            while True:
                try:
                    request = conn.recv(self.BUF_SIZE)
                except socket.timeout:
                    if not cb_continue():
                        raise BrowserTerminatedError("Failure waiting for request")
                    if time.time() >= time_limit:
                        raise BrowserTimeoutError("Timeout waiting for request")
                    if not received:
                        continue
                if not received and not request:
                    log.warning("Empty request received from browser during bootstrap!")
                elif len(request) == self.BUF_SIZE:
                    # maybe there is more to read...
                    received = True
                    continue
                break
            # build response
            if url is None:
                resp = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
            else:
                resp = "HTTP/1.1 301 Moved Permanently\r\n" \
                       "Location: %s\r\n" \
                       "Connection: close\r\n\r\n" % url
            conn.settimeout(max(int(time_limit - time.time()), 1))
            log.debug("sending response (redirect %r)", url)
            try:
                conn.sendall(resp.encode("ascii"))
            except socket.timeout:
                resp_timeout = True
            else:
                resp_timeout = False
            if not cb_continue():
                raise BrowserTerminatedError("Failure during browser startup")
            if resp_timeout:
                raise BrowserTimeoutError("Timeout sending response")
            log.debug("bootstrap complete (%0.2fs)", time.time() - start_time)
        except socket.error as soc_e:  # pragma: no cover
            raise LaunchError("Error attempting to launch browser: %s" % soc_e)
        finally:
            if conn is not None:
                conn.close()
