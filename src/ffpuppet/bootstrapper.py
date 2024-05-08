# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet bootstrapper module"""

# as of python 3.10 socket.timeout was made an alias of TimeoutError
# pylint: disable=ungrouped-imports
from socket import timeout as socket_timeout  # isort: skip

from logging import getLogger
from select import select
from socket import SO_REUSEADDR, SOL_SOCKET, socket
from time import sleep, time
from typing import Any, Callable, Optional

from .exceptions import BrowserTerminatedError, BrowserTimeoutError, LaunchError

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("Bootstrapper",)


class Bootstrapper:  # pylint: disable=missing-docstring
    # see: searchfox.org/mozilla-central/source/netwerk/base/nsIOService.cpp
    # include ports above 1023
    BLOCKED_PORTS = {
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
    }
    # receive buffer size
    BUF_SIZE = 4096
    # duration of initial blocking socket operations
    POLL_WAIT = 1.0

    __slots__ = ("_socket",)

    def __init__(self, sock: socket) -> None:
        self._socket = sock

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
        self._socket.close()

    @classmethod
    def create(cls, attempts: int = 50, port: int = 0) -> "Bootstrapper":
        """Create a Bootstrapper.

        Args:
            attempts: Number of times to attempt to bind.
            port: Port to use. Use 0 for system select.

        Returns:
            Bootstrapper.
        """
        assert attempts > 0
        assert port == 0 or 1024 <= port <= 65535
        assert port not in cls.BLOCKED_PORTS
        for _ in range(attempts):
            sock = socket()
            sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                sock.listen()
            except (OSError, PermissionError) as exc:
                LOG.debug("%s: %s", type(exc).__name__, exc)
                sock.close()
                sleep(0.1)
                continue
            # avoid blocked ports
            if sock.getsockname()[1] in cls.BLOCKED_PORTS:
                LOG.debug("bound to blocked port, retrying...")
                sock.close()
                continue
            break
        else:
            raise LaunchError("Could not find available port")
        return cls(sock)

    @property
    def location(self) -> str:
        """Location in the format of 'http://127.0.0.1:#'.

        Args:
            None

        Returns:
            Location.
        """
        return f"http://127.0.0.1:{self.port}"

    @property
    def port(self) -> int:
        """Listening socket port number.

        Args:
            None

        Returns:
            Port number.
        """
        return int(self._socket.getsockname()[1])

    def wait(
        self,
        cb_continue: Callable[[], bool],
        timeout: float = 60,
        url: Optional[str] = None,
    ) -> None:
        """Wait for browser connection, read request and send response.

        Args:
            cb_continue: Callback that communicates browser process health.
            timeout: Amount of time wait before raising BrowserTimeoutError.
            url: Location to redirect to.

        Returns:
            None
        """
        assert timeout >= 0
        start_time = time()
        time_limit = start_time + timeout
        conn: Optional[socket] = None
        try:
            LOG.debug("waiting for browser connection...")
            while conn is None:
                readable, _, _ = select([self._socket], (), (), self.POLL_WAIT)
                if self._socket not in readable:
                    # no connections ready for reading
                    if not cb_continue():
                        raise BrowserTerminatedError(
                            "Failure waiting for browser connection"
                        )
                    if time() >= time_limit:
                        raise BrowserTimeoutError(
                            "Timeout waiting for browser connection"
                        )
                    continue
                conn, _ = self._socket.accept()
                conn.settimeout(1)
                count_recv = 0
                total_recv = 0
                LOG.debug("waiting for browser request...")
                while True:
                    try:
                        count_recv = len(conn.recv(self.BUF_SIZE))
                        total_recv += count_recv
                    except socket_timeout:
                        # use -1 to indicate timeout
                        count_recv = -1
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
                        LOG.debug("connection failed, waiting for next connection...")
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
            # set timeout to match remaining time
            conn.settimeout(max(time_limit - time(), 1))
            LOG.debug("sending response (redirect %r)", url)
            try:
                conn.sendall(resp.encode("ascii"))
            except socket_timeout:
                resp_timeout = True
            else:
                resp_timeout = False
            if not cb_continue():
                raise BrowserTerminatedError("Failure during browser startup")
            if resp_timeout:
                raise BrowserTimeoutError("Timeout sending response")
            LOG.debug("bootstrap complete (%0.1fs)", time() - start_time)
        except OSError as exc:  # pragma: no cover
            raise LaunchError(f"Error attempting to launch browser: {exc}") from exc
        finally:
            if conn is not None:
                conn.close()
