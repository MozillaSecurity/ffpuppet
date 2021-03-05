# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet bootstrapper tests"""
# pylint: disable=protected-access
import socket
import threading

from pytest import raises

from .bootstrapper import Bootstrapper
from .exceptions import BrowserTerminatedError, BrowserTimeoutError, LaunchError


def test_bootstrapper_01():
    """test simple Bootstrapper()"""
    with Bootstrapper() as bts:
        assert bts._socket is not None
        assert bts.location.startswith("http://127.0.0.1:")
        assert int(bts.location.split(":")[-1]) > 1024
        assert bts.port > 1024
        bts.close()
        assert bts._socket is None


def test_bootstrapper_02(mocker):
    """test Bootstrapper.wait() failure waiting for initial connection"""
    fake_sock = mocker.Mock(socket.socket)
    fake_sock.accept.side_effect = socket.timeout
    mocker.patch("ffpuppet.bootstrapper.socket.socket", return_value=fake_sock)
    with Bootstrapper() as bts:
        # test failure
        with raises(
            BrowserTerminatedError, match="Failure waiting for browser connection"
        ):
            bts.wait(lambda: False)
        assert fake_sock.accept.call_count == 1
        fake_sock.reset_mock()
        # test timeout
        mocker.patch("ffpuppet.bootstrapper.time", side_effect=(1, 1, 1, 2))
        with raises(
            BrowserTimeoutError, match="Timeout waiting for browser connection"
        ):
            bts.wait(lambda: True, timeout=0.1)
        # should call accept() at least 2x for positive and negative timeout check
        assert fake_sock.accept.call_count > 1


def test_bootstrapper_03(mocker):
    """test Bootstrapper.wait() failure waiting for request"""
    fake_sock = mocker.Mock(socket.socket)
    fake_conn = mocker.Mock(socket.socket)
    fake_conn.recv.side_effect = socket.timeout
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.socket.socket", return_value=fake_sock)
    with Bootstrapper() as bts:
        # test failure
        with raises(BrowserTerminatedError, match="Failure waiting for request"):
            bts.wait(lambda: False)
        assert fake_conn.recv.call_count == 1
        assert fake_conn.close.call_count == 1
        fake_conn.reset_mock()
        # test timeout
        mocker.patch("ffpuppet.bootstrapper.time", side_effect=(1, 1, 1, 1, 2))
        with raises(BrowserTimeoutError, match="Timeout waiting for request"):
            bts.wait(lambda: True, timeout=0.1)
        # should call recv() at least 2x for positive and negative timeout check
        assert fake_conn.recv.call_count > 1
        assert fake_conn.close.call_count == 1


def test_bootstrapper_04(mocker):
    """test Bootstrapper.wait() failure sending response"""
    fake_sock = mocker.Mock(socket.socket)
    fake_conn = mocker.Mock(socket.socket)
    fake_conn.recv.return_value = "A"
    fake_conn.sendall.side_effect = socket.timeout
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.socket.socket", return_value=fake_sock)
    with Bootstrapper() as bts:
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
    fake_sock = mocker.Mock(socket.socket)
    fake_conn = mocker.Mock(socket.socket)
    # return empty buffer for test coverage
    fake_conn.recv.return_value = ""
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.socket.socket", return_value=fake_sock)
    with Bootstrapper() as bts:
        with raises(BrowserTerminatedError, match="Failure during browser startup"):
            bts.wait(lambda: False)
    assert fake_conn.close.call_count == 1


def test_bootstrapper_06(mocker):
    """test Bootstrapper.wait() successful without redirect"""
    fake_sock = mocker.Mock(socket.socket)
    fake_conn = mocker.Mock(socket.socket)
    fake_conn.recv.side_effect = ("A" * Bootstrapper.BUF_SIZE, "")
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.socket.socket", return_value=fake_sock)
    with Bootstrapper() as bts:
        bts.wait(lambda: True)
    assert fake_conn.close.call_count == 1
    assert fake_conn.recv.call_count == 2
    assert fake_conn.sendall.call_count == 1


def test_bootstrapper_07(mocker):
    """test Bootstrapper.wait() successful with redirect"""
    fake_sock = mocker.Mock(socket.socket)
    fake_conn = mocker.Mock(socket.socket)
    fake_conn.recv.return_value = "AAAA"
    fake_sock.accept.return_value = (fake_conn, None)
    mocker.patch("ffpuppet.bootstrapper.socket.socket", return_value=fake_sock)
    # without redirect
    with Bootstrapper() as bts:
        bts.wait(lambda: True, url="http://127.0.0.1:9999/test.html")
    assert fake_conn.close.call_count == 1
    assert fake_conn.recv.call_count == 1
    assert fake_conn.sendall.call_count == 1


def test_bootstrapper_08():
    """test Bootstrapper.wait() with a fake browser"""

    def _fake_browser(port, payload_size=5120):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 50 x 0.1 = 5 seconds
        conn.settimeout(0.1)
        # open connection
        for attempt in reversed(range(50)):
            try:
                conn.connect(("127.0.0.1", port))
                break
            except socket.timeout:
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

    with Bootstrapper() as bts:
        browser_thread = threading.Thread(target=_fake_browser, args=(bts.port,))
        try:
            browser_thread.start()
            bts.wait(lambda: True, timeout=10)
        finally:
            browser_thread.join()


def test_bootstrapper_09(mocker):
    """test Bootstrapper() hit PORT_RETRIES"""
    fake_sock = mocker.Mock(socket.socket)
    fake_sock.bind.side_effect = socket.error(10013, "TEST")
    mocker.patch("ffpuppet.bootstrapper.socket.socket", return_value=fake_sock)
    with raises(LaunchError, match="Could not find available port"):
        with Bootstrapper():
            pass
    assert fake_sock.bind.call_count == Bootstrapper.PORT_RETRIES
