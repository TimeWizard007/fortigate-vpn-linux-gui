#!/usr/bin/env python3.12
# SPDX-License-Identifier: GPL-3.0-or-later
"""Persistent PTY SSH collector for FortiOS diagnose debug output.

Research-only. Does not change VPN/IKE runtime behavior. FortiOS async
debug is written to the CLI session that enabled it, so this process
keeps ONE ssh -tt session alive, enables ike/fnbamd debug, and copies
that session's output to a raw file.
"""

from __future__ import annotations

import argparse
import json
import os
import pty
import select
import signal
import sys
import termios
import time
from pathlib import Path

DEBUG_COMMANDS = (
    "diagnose debug disable",
    "diagnose debug console timestamp enable",
    "diagnose debug application ike -1",
    "diagnose debug application fnbamd -1",
    "diagnose debug enable",
)
SHUTDOWN_COMMANDS = (
    "diagnose debug disable",
    "exit",
)
HANDSHAKE_MARKERS = (
    "diagnose debug application ike -1",
    "diagnose debug application fnbamd -1",
    "diagnose debug enable",
)


def default_ssh_argv(alias: str) -> list[str]:
    return [
        "ssh",
        "-tt",
        "-o",
        "BatchMode=yes",
        "-o",
        "RequestTTY=force",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
        alias,
    ]


def write_status(path: Path, **fields: object) -> None:
    payload = {"state": "starting", **fields}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def handshake_accepted(log_text: str) -> bool:
    text = log_text.replace("\r", "")
    return all(marker in text for marker in HANDSHAKE_MARKERS)


def _disable_local_echo(fd: int) -> None:
    attrs = termios.tcgetattr(fd)
    attrs[3] &= ~(termios.ECHO | termios.ECHOE | termios.ECHOK | termios.ECHONL)
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def _send_line(master: int, line: str) -> None:
    os.write(master, (line + "\r\n").encode("utf-8", "replace"))


def role_fake_cli(*, die_immediately: bool = False) -> int:
    """Local stand-in for an interactive FortiOS CLI. Used by tests only."""
    sys.stdout.write("FortiGate-60F #\n")
    sys.stdout.flush()
    if die_immediately:
        return 1
    for raw in sys.stdin:
        sys.stdout.write(raw)
        sys.stdout.flush()
        line = raw.replace("\r", "").strip()
        if line == "diagnose debug enable":
            sys.stdout.write("Debug messages will be on this console.\n")
            sys.stdout.flush()
        if line in {"exit", "quit"}:
            break
        sys.stdout.write("FortiGate-60F #\n")
        sys.stdout.flush()
    return 0


def run_collector(
    *,
    ssh_argv: list[str],
    log_path: Path,
    status_path: Path,
    control_path: Path,
    ready_timeout: float = 20.0,
) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(b"")
    write_status(
        status_path,
        state="starting",
        pid=os.getpid(),
        log=str(log_path),
        reason="",
    )
    if control_path.exists():
        control_path.unlink()
    os.mkfifo(control_path)
    control_fd = os.open(control_path, os.O_RDWR | os.O_NONBLOCK)

    master, slave = pty.openpty()
    try:
        _disable_local_echo(slave)
    except termios.error:
        pass

    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.setsid()
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        if slave > 2:
            os.close(slave)
        try:
            os.execvp(ssh_argv[0], ssh_argv)
        except OSError:
            os._exit(127)

    os.close(slave)
    log_fd = os.open(log_path, os.O_WRONLY | os.O_APPEND)
    started = time.monotonic()
    handshake_sent = False
    active = False
    shutting_down = False
    exit_code = 1
    stop = False

    def on_term(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    def child_alive() -> bool:
        try:
            waited_pid, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return False
        return waited_pid == 0

    def fail(reason: str) -> int:
        write_status(
            status_path,
            state="failed",
            pid=os.getpid(),
            log=str(log_path),
            reason=reason,
            bytes=log_path.stat().st_size if log_path.exists() else 0,
        )
        return 1

    def drain_master(budget: float) -> None:
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if master not in ready:
                if not child_alive():
                    return
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:
                return
            if not chunk:
                return
            os.write(log_fd, chunk)

    try:
        while True:
            if stop and not shutting_down:
                shutting_down = True
                for command in SHUTDOWN_COMMANDS:
                    _send_line(master, command)
                drain_master(3.0)
                break
            timeout = 0.2
            readable, _, _ = select.select([master, control_fd], [], [], timeout)
            if master in readable:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    if not active:
                        return fail("persistent SSH session closed before debug handshake")
                    break
                os.write(log_fd, chunk)
            if control_fd in readable:
                try:
                    raw = os.read(control_fd, 4096)
                except OSError:
                    raw = b""
                if b"shutdown" in raw.replace(b"\r", b""):
                    shutting_down = True
                    for command in SHUTDOWN_COMMANDS:
                        _send_line(master, command)
                    drain_master(3.0)
                    break

            if not child_alive() and not shutting_down:
                if active:
                    break
                return fail("persistent SSH session exited during startup")

            if not handshake_sent and time.monotonic() - started >= 1.5:
                _send_line(master, "")
                for command in DEBUG_COMMANDS:
                    _send_line(master, command)
                handshake_sent = True

            if handshake_sent and not active and not shutting_down:
                text = log_path.read_text(encoding="utf-8", errors="replace")
                if handshake_accepted(text) and child_alive():
                    active = True
                    write_status(
                        status_path,
                        state="active",
                        pid=os.getpid(),
                        log=str(log_path),
                        reason="",
                        bytes=log_path.stat().st_size,
                    )
                elif time.monotonic() - started >= ready_timeout:
                    return fail("FortiOS CLI did not accept debug commands")

        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if active or handshake_accepted(log_text):
            write_status(
                status_path,
                state="stopped",
                pid=os.getpid(),
                log=str(log_path),
                reason="",
                bytes=log_path.stat().st_size,
            )
            exit_code = 0
        else:
            return fail("session ended without debug handshake")
    finally:
        try:
            os.close(log_fd)
        except OSError:
            pass
        try:
            os.close(control_fd)
        except OSError:
            pass
        try:
            os.close(master)
        except OSError:
            pass
        if child_alive():
            os.kill(pid, signal.SIGTERM)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        elif pid:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--role",
        choices=("collector", "fake-cli", "fake-cli-die"),
        default="collector",
    )
    parser.add_argument("--alias", default="fvl-fortigate")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--status", type=Path)
    parser.add_argument("--control", type=Path)
    parser.add_argument("--ready-timeout", type=float, default=20.0)
    parser.add_argument("--ssh-arg", action="append", dest="ssh_args")
    parser.add_argument("--fake-remote", action="store_true")
    parser.add_argument("--fake-remote-die", action="store_true")
    args = parser.parse_args(argv)
    if args.role == "fake-cli":
        return role_fake_cli(die_immediately=False)
    if args.role == "fake-cli-die":
        return role_fake_cli(die_immediately=True)
    if args.log is None or args.status is None or args.control is None:
        parser.error("--log, --status, and --control are required for the collector")
    self = str(Path(__file__).resolve())
    if args.fake_remote:
        ssh_argv = [sys.executable, self, "--role", "fake-cli"]
    elif args.fake_remote_die:
        ssh_argv = [sys.executable, self, "--role", "fake-cli-die"]
    elif args.ssh_args:
        ssh_argv = list(args.ssh_args)
    else:
        ssh_argv = default_ssh_argv(args.alias)
    return run_collector(
        ssh_argv=ssh_argv,
        log_path=args.log,
        status_path=args.status,
        control_path=args.control,
        ready_timeout=args.ready_timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
