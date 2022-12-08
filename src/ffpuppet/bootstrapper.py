# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet bootstrapper module"""
import socket
from logging import getLogger
from time import sleep, time
from typing import Any, Callable, Optional

from .exceptions import BrowserTerminatedError, BrowserTimeoutError, LaunchError

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("Bootstrapper",)


class Bootstrapper:  # pylint: disable=missing-docstring
    # see: searchfox.org/mozilla-central/source/netwerk/base/nsIOService.cpp
    # include ports above 1024
    BLOCKED_PORTS = (
        1719,
        1720,
        1723,
        2049,
        3659,
        4045,
        5060,
        5061,
        6000,
        6566,
        6665,
        6666,
        6667,
        6668,
        6669,
        6697,
        10080,
    )
    # receive buffer size
    BUF_SIZE = 4096
    # duration of initial blocking socket operations
    POLL_WAIT: float = 1
    # number of attempts to find an available port
    PORT_ATTEMPTS = 50

    __slots__ = ("_socket",)

    def __init__(self, attempts: int = PORT_ATTEMPTS, port: int = 0) -> None:
        assert attempts > 0
        assert port >= 0
        for _ in range(attempts):
            self._socket: Optional[socket.socket] = socket.socket()
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.settimeout(self.POLL_WAIT)
            try:
                self._socket.bind(("127.0.0.1", port))
                self._socket.listen(5)
            except (OSError, PermissionError) as exc:
                LOG.debug("%s: %s", type(exc).__name__, exc)
                self._socket.close()
                sleep(0.1)
                continue
            # avoid blocked ports
            if port == 0 and self._socket.getsockname()[1] in self.BLOCKED_PORTS:
                LOG.debug("bound to blocked port, retrying...")
                self._socket.close()
                continue
            break
        else:
            raise LaunchError("Could not find available port")

    def __enter__(self) -> "Bootstrapper":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close listening socket.

        Args:
            None

        Returns:
            None
        """
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    @property
    def location(self) -> str:
        """Location in the format of 'http://127.0.0.1:#'.

        Args:
            None

        Returns:
            Location.
        """
        assert self._socket is not None
        return f"http://127.0.0.1:{self.port}"

    @property
    def port(self) -> int:
        """Listening socket port number.

        Args:
            None

        Returns:
            Port number.
        """
        assert self._socket is not None
        return int(self._socket.getsockname()[1])

    def wait(
        self,
        cb_continue: Callable[[], bool],
        timeout: float = 60,
        url: Optional[str] = None,
    ) -> None:
        """Wait for browser connection, read request and send response.

        Args:
            cb_continue: Callback that return True if the browser
                         process is healthy otherwise False.
            timeout: Amount of time wait before raising BrowserTimeoutError.
            url: Location to redirect to.

        Returns:
            None
        """
        assert self._socket is not None
        assert timeout >= 0
        start_time = time()
        time_limit = start_time + timeout
        conn = None
        try:
            while conn is None:
                LOG.debug("waiting for browser connection...")
                while conn is None:
                    try:
                        conn, _ = self._socket.accept()
                    except socket.timeout:
                        if not cb_continue():
                            raise BrowserTerminatedError(
                                "Failure waiting for browser connection"
                            ) from None
                        if time() >= time_limit:
                            raise BrowserTimeoutError(
                                "Timeout waiting for browser connection"
                            ) from None

                conn.settimeout(1)
                count_recv = 0
                total_recv = 0
                LOG.debug("waiting for browser request...")
                while True:
                    try:
                        count_recv = len(conn.recv(self.BUF_SIZE))
                        total_recv += count_recv
                    except socket.timeout:
                        count_recv = None
                    if count_recv == self.BUF_SIZE:
                        # check if there is more to read
                        continue
                    if total_recv:
                        LOG.debug("request size: %d bytes(s)", total_recv)
                        break
                    if not cb_continue():
                        raise BrowserTerminatedError("Failure waiting for request")
                    if time() >= time_limit:
                        raise BrowserTimeoutError("Timeout waiting for request")
                    if count_recv == 0:
                        LOG.debug("connection failed, retrying")
                        conn.close()
                        conn = None
                        break

            # build response
            if url is None:
                resp = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
            else:
                resp = (
                    "HTTP/1.1 301 Moved Permanently\r\n"
                    f"Location: {url}\r\n"
                    "Connection: close\r\n\r\n"
                )
            conn.settimeout(max(int(time_limit - time()), 1))
            LOG.debug("sending response (redirect %r)", url)
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
            LOG.debug("bootstrap complete (%0.2fs)", time() - start_time)
        except OSError as exc:  # pragma: no cover
            raise LaunchError(f"Error attempting to launch browser: {exc}") from exc
        finally:
            if conn is not None:
                conn.close()
