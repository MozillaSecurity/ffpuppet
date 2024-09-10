#!/usr/bin/env python
"""fake browser tree"""

from __future__ import annotations

# NOTE: this must only use the standard library
import signal
from argparse import ArgumentParser, Namespace
from logging import DEBUG, basicConfig, getLogger
from os import getpid
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, socket
from subprocess import Popen
from sys import executable
from time import perf_counter, sleep
from typing import Any

LOG = getLogger(__name__)
SHUTDOWN = False
SOCKET_TIMEOUT = 60


def handle_signal(signum: int, _frame: Any) -> None:
    """handle signal to allow manual shutdown"""
    # pylint: disable=global-statement
    global SHUTDOWN
    LOG.info("caught %r", signal.Signals(signum).name)
    SHUTDOWN = True


def main(args: Namespace) -> int:
    """Mock a Firefox browser process tree for testing purposes"""
    child_procs: tuple[Popen[bytes], ...] | None = None
    start = perf_counter()
    try:
        pid = getpid()
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        assert args.procs >= 1, f"procs must be >= 1 ({pid})"
        assert args.duration >= 1, f"duration must be >= 1 ({pid})"
        assert not args.sync.exists(), f"sync file should not exist ({pid})"

        cmd = [
            executable,
            __file__,
            str(args.procs),
            str(args.sync),
            "--parent-pid",
            str(pid),
            "--duration",
            str(args.duration),
        ]
        if args.no_deelevate and not args.launcher_is_parent:
            assert not args.contentproc, f"-contentproc not expected! ({pid})"
            LOG.info("Launcher process")
            # pylint: disable=consider-using-with
            child_procs = (Popen(cmd),)
        elif args.contentproc:
            LOG.info("Content process (ppid: %r)", args.parent_pid)
            with socket(AF_INET, SOCK_STREAM) as conn:
                conn.connect(("127.0.0.1", args.port))
                # don't hang forever
                conn.settimeout(SOCKET_TIMEOUT)
                conn.sendall(str(pid).encode())
        else:
            assert not args.no_deelevate or args.launcher_is_parent
            LOG.info("Parent process (ppid: %r)", args.parent_pid)
            with socket(AF_INET, SOCK_STREAM) as srv:
                srv.settimeout(SOCKET_TIMEOUT)
                srv.bind(("127.0.0.1", 0))
                srv.listen()
                cmd.append("--port")
                cmd.append(str(srv.getsockname()[1]))
                cmd.append("-contentproc")
                # pylint: disable=consider-using-with
                child_procs = tuple(Popen(cmd) for _ in range(args.procs))
                # wait for processes to launch
                for _ in range(args.procs):
                    conn, _ = srv.accept()
                    # don't hang forever
                    conn.settimeout(SOCKET_TIMEOUT)
                    with conn:
                        conn.recv(64)
                LOG.info("Tree running (%0.03f)", perf_counter() - start)
                args.sync.touch()

        # wait loop
        while not SHUTDOWN and perf_counter() - start < args.duration:
            if child_procs and all(x.poll() is not None for x in child_procs):
                break
            sleep(0.1)

    except KeyboardInterrupt:
        pass

    finally:
        if not args.contentproc:
            args.sync.unlink(missing_ok=True)
        if child_procs:
            for proc in child_procs:
                if proc.poll() is None:
                    proc.terminate()
            for proc in child_procs:
                proc.wait(timeout=10)
        LOG.info("Exiting, runtime %0.3fs", perf_counter() - start)

    return 0


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("procs", type=int, help="number of content processes")
    parser.add_argument("sync", type=Path, help="used to indicate tree readiness")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--launcher-is-parent", action="store_true")
    parser.add_argument("--parent-pid", type=int)
    parser.add_argument("--port", type=int)
    parser.add_argument("-contentproc", action="store_true", help="fake browser arg")
    parser.add_argument("-no-deelevate", action="store_true", help="fake browser arg")

    basicConfig(
        datefmt="%H:%M:%S",
        format="[%(asctime)s.%(msecs)03d][%(process)d] %(message)s",
        level=DEBUG,
    )

    raise SystemExit(main(parser.parse_args()))
