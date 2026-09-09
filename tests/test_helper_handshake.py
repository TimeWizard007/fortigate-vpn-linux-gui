# SPDX-License-Identifier: GPL-3.0-or-later
"""Structured helper hello/version parsing. No real helper process as root."""

from __future__ import annotations

from fortigate_vpn_gui.helper.handshake import encode_hello_line, parse_helper_hello_output
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION


def test_valid_hello_json() -> None:
    result = parse_helper_hello_output(stdout=encode_hello_line() + "\n", returncode=0)
    assert result.status == "ok"
    assert result.helper_version == HELPER_VERSION
    assert result.protocol_version == 1


def test_valid_plain_version_line() -> None:
    result = parse_helper_hello_output(stdout="0.5.0\n", returncode=0)
    assert result.status == "ok"
    assert result.helper_version == "0.5.0"


def test_crash_traceback_is_startup_failed_not_version() -> None:
    stderr = (
        "Traceback (most recent call last):\n"
        '  File "helper/service.py", line 1, in <module>\n'
        "ImportError: cannot import name 'HelperService'\n"
    )
    result = parse_helper_hello_output(stdout="", stderr=stderr, returncode=1)
    assert result.status == "startup_failed"
    assert result.helper_version is None
    assert "Traceback" not in (result.helper_version or "")


def test_traceback_on_stdout_is_not_a_version() -> None:
    stdout = "Traceback (most recent call last):\nImportError: boom\n"
    result = parse_helper_hello_output(stdout=stdout, stderr="", returncode=1)
    assert result.status == "startup_failed"
    assert result.helper_version is None


def test_malformed_output() -> None:
    result = parse_helper_hello_output(stdout="not a hello event\n", returncode=0)
    assert result.status == "malformed"
    assert result.helper_version is None


def test_no_response() -> None:
    result = parse_helper_hello_output(stdout="", stderr="", returncode=0)
    assert result.status == "no_response"
    assert result.helper_version is None


def test_stderr_is_never_used_as_version() -> None:
    result = parse_helper_hello_output(stdout="", stderr="0.5.0\n", returncode=0)
    assert result.helper_version is None
    assert result.status == "no_response"
