# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet bootstrapper tests"""
# pylint: disable=protected-access

# as of python 3.10 socket.timeout was made an alias of TimeoutError
# pylint: disable=ungrouped-imports
from socket import timeout as socket_timeout  # isort: skip

from itertools import repeat
from socket import socket
from threading import Thread

from pytest import mark, raises

from .bootstrapper import Bootstrapper
from .exceptions import BrowserTerminatedError, BrowserTimeoutError, LaunchError


def test_bootstrapper_01():
    """test Bootstrapper.create()"""
    with Bootstrapper.create() as bts:
        assert bts._socket is not None
        assert bts.location.startswith("http://127.0.0.1:")
        assert int(bts.location.rsplit(":", maxsplit=1)[-1]) >= 1024
        assert bts.port >= 1024
        assert bts.port not in Bootstrapper.BLOCKED_PORTS
        bts.close()


@mark.parametrize(
    "exc, msg, continue_cb",
    [
        # test failure
        (
            BrowserTerminatedError,
            "Failure waiting for browser connection",
            lambda: False,
        ),
        # test timeout
        (
            BrowserTimeoutError,
            "Timeout waiting for browser connection",
            lambda: True,
        ),
    ],
)
def test_bootstrapper_02(mocker, exc, msg, continue_cb):
    """test Bootstrapper.wait() failure waiting for initial connection"""
    mocker.patch("ffpuppet.bootstrapper.select", return_value=([], None, None))
    mocker.patch("ffpuppet.bootstrapper.perf_counter", side_effect=(1, 1, 2, 3))
    fake_sock = mocker.MagicMock(spec_set=socket)
    with Bootstrapper(fake_sock) as bts:
        with raises(exc, match=msg):
            bts.wait(continue_cb, timeout=2)
        assert fake_sock.accept.call_count == 0


def test_bootstrapper_03(mocker):
    """test Bootstrapper.wait() failure waiting for request"""
    fake_sock = mocker.MagicMock(spec_set=socket)
    fake_conn = mocker.Mock(spec_set=socket)
    fake_conn.recv.side_effect = socket_timeout
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.select", return_value=([fake_sock], None, None))
    with Bootstrapper(fake_sock) as bts:
        # test failure
        with raises(BrowserTerminatedError, match="Failure waiting for request"):
            bts.wait(lambda: False)
        assert fake_conn.recv.call_count == 1
        assert fake_conn.close.call_count == 1
        fake_conn.reset_mock()
        # test timeout
        mocker.patch("ffpuppet.bootstrapper.perf_counter", side_effect=(1, 1, 1, 1, 2))
        with raises(BrowserTimeoutError, match="Timeout waiting for request"):
            bts.wait(lambda: True, timeout=0.1)
        # should call recv() at least 2x for positive and negative timeout check
        assert fake_conn.recv.call_count > 1
        assert fake_conn.close.call_count == 1


def test_bootstrapper_04(mocker):
    """test Bootstrapper.wait() failure sending response"""
    fake_sock = mocker.MagicMock(spec_set=socket)
    fake_conn = mocker.Mock(spec_set=socket)
    fake_conn.recv.return_value = "A"
    fake_conn.sendall.side_effect = socket_timeout
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.select", return_value=([fake_sock], None, None))
    with Bootstrapper(fake_sock) as bts:
        # test timeout
        with raises(BrowserTimeoutError, match="Timeout sending response"):
            bts.wait(lambda: True)
        assert fake_conn.recv.call_count == 1
        assert fake_conn.sendall.call_count == 1
        assert fake_conn.close.call_count == 1
        fake_conn.reset_mock()
        # test failure
        with raises(BrowserTerminatedError, match="Failure during browser startup"):
            bts.wait(lambda: False)
        assert fake_conn.recv.call_count == 1
        assert fake_conn.sendall.call_count == 1
        assert fake_conn.close.call_count == 1


def test_bootstrapper_05(mocker):
    """test Bootstrapper.wait() target crashed"""
    fake_sock = mocker.MagicMock(spec_set=socket)
    fake_conn = mocker.Mock(spec_set=socket)
    fake_conn.recv.return_value = "foo"
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.select", return_value=([fake_sock], None, None))
    with (
        Bootstrapper(fake_sock) as bts,
        raises(BrowserTerminatedError, match="Failure during browser startup"),
    ):
        bts.wait(lambda: False)
    assert fake_conn.close.call_count == 1


@mark.parametrize(
    "redirect, recv, closed",
    [
        # normal startup
        (None, ("foo",), 1),
        # with a redirect url
        ("http://127.0.0.1:9999/test.html", ("foo",), 1),
        # request size matches buffer size
        (None, ("A" * Bootstrapper.BUF_SIZE, socket_timeout), 1),
        # large request
        (None, ("A" * Bootstrapper.BUF_SIZE, "foo"), 1),
        # slow startup
        (None, (socket_timeout, socket_timeout, "foo"), 1),
        # slow failed startup with retry
        (None, (socket_timeout, "", "foo"), 2),
    ],
)
def test_bootstrapper_06(mocker, redirect, recv, closed):
    """test Bootstrapper.wait()"""
    fake_sock = mocker.MagicMock(spec_set=socket)
    fake_conn = mocker.Mock(spec_set=socket)
    fake_conn.recv.side_effect = recv
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.select", return_value=([fake_sock], None, None))
    with Bootstrapper(fake_sock) as bts:
        bts.wait(lambda: True, url=redirect)
    assert fake_conn.close.call_count == closed
    assert fake_conn.recv.call_count == len(recv)
    assert fake_conn.sendall.call_count == 1


def test_bootstrapper_07():
    """test Bootstrapper.wait() with a fake browser"""

    def _fake_browser(port, payload_size=5120):
        conn = socket()
        # 50 x 0.1 = 5 seconds
        conn.settimeout(0.1)
        # open connection
        for attempt in reversed(range(50)):
            try:
                conn.connect(("127.0.0.1", port))
                break
            except socket_timeout:
                if not attempt:
                    raise
        # send request and receive response
        try:
            conn.settimeout(10)
            conn.sendall(b"A" * payload_size)
            conn.send(b"")
            conn.recv(8192)
        finally:
            conn.close()

    with Bootstrapper.create() as bts:
        browser_thread = Thread(target=_fake_browser, args=(bts.port,))
        try:
            browser_thread.start()
            bts.wait(lambda: True, timeout=10)
        finally:
            browser_thread.join()


@mark.parametrize(
    "bind, attempts",
    [
        # failed to bind (OSError)
        ((OSError(0, "foo1"),), 1),
        # failed to bind (PermissionError) - multiple attempts
        (repeat(PermissionError(10013, "foo2"), 4), 4),
    ],
)
def test_bootstrapper_08(mocker, bind, attempts):
    """test Bootstrapper.create_socket() - failures"""
    mocker.patch("ffpuppet.bootstrapper.sleep", autospec=True)
    fake_sock = mocker.MagicMock(spec_set=socket)
    fake_sock.bind.side_effect = bind
    mocker.patch("ffpuppet.bootstrapper.select", return_value=([fake_sock], None, None))
    mocker.patch("ffpuppet.bootstrapper.socket", return_value=fake_sock)
    assert Bootstrapper.create_socket(attempts=attempts) is None
    assert fake_sock.bind.call_count == attempts
    assert fake_sock.close.call_count == attempts


def test_bootstrapper_09(mocker):
    """test Bootstrapper() - blocked ports"""
    fake_sock = mocker.MagicMock(spec_set=socket)
    fake_sock.getsockname.side_effect = (
        (None, next(iter(Bootstrapper.BLOCKED_PORTS))),
        (None, 12345),
    )
    mocker.patch("ffpuppet.bootstrapper.socket", return_value=fake_sock)
    with Bootstrapper.create(attempts=2):
        pass
    assert fake_sock.close.call_count == 2


def test_bootstrapper_10(mocker):
    """test Bootstrapper.create() - failure"""
    mocker.patch("ffpuppet.bootstrapper.Bootstrapper.create_socket", return_value=None)
    with raises(LaunchError), Bootstrapper.create():
        pass


@mark.parametrize("value", [123, 5555])
def test_bootstrapper_11(value):
    """test Bootstrapper.create_socket() - unusable ports"""
    assert Bootstrapper.create_socket(blocked=[5555], port=value) is None


@mark.parametrize(
    "value, result",
    [
        (0, True),
        (1337, True),
        (32768, True),
        (-1, False),
        (1, False),
        (1023, False),
        (65536, False),
    ],
)
def test_bootstrapper_12(value, result):
    """test Bootstrapper.check_port()"""
    assert Bootstrapper.check_port(value) == result
