# SPDX-License-Identifier: GPL-3.0-or-later
"""Subprocess wrapper tests. The real openfortivpn binary is never started."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fortigate_vpn_gui.vpn.process import SubprocessVpnProcess, default_process_factory


def test_popen_uses_argv_list_and_shell_false() -> None:
    captured: dict[str, object] = {}
    fake = MagicMock()
    fake.pid = 99
    fake.poll.return_value = 0
    fake.stdout = iter(())
    fake.wait.return_value = 0

    def popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return fake

    with patch("fortigate_vpn_gui.vpn.process.subprocess.Popen", side_effect=popen):
        process = SubprocessVpnProcess(
            ["/usr/bin/openfortivpn", "vpn.example.com:443"],
            lambda _line: None,
            lambda _code: None,
        )
        process.start()
        if process._reader is not None:
            process._reader.join(timeout=2)

    assert captured["argv"] == ["/usr/bin/openfortivpn", "vpn.example.com:443"]
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is not None


def test_default_factory_returns_subprocess_wrapper() -> None:
    process = default_process_factory(
        ["/usr/bin/openfortivpn", "vpn.example.com:443"],
        lambda _line: None,
        lambda _code: None,
    )
    assert isinstance(process, SubprocessVpnProcess)
    assert process.argv[0].endswith("openfortivpn")
