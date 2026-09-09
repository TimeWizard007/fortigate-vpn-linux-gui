# SPDX-License-Identifier: GPL-3.0-or-later
"""Certificate trust dialog tests. No network."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QPushButton

from fortigate_vpn_gui.gui.certificate_dialog import CertificateTrustDialog
from fortigate_vpn_gui.helper.protocol import CertificateInfo


def test_certificate_dialog_shows_pinning_wording(qapp) -> None:
    info = CertificateInfo(subject="CN=vpn.example.com", issuer="Example CA", sha256="aa" * 32)
    dialog = CertificateTrustDialog(gateway="vpn.example.com", certificate=info)
    intro = dialog.findChild(QLabel, "certificateTrustIntro")
    assert intro is not None
    assert "certificate pinning" in intro.text().lower()
    assert dialog.findChild(QLabel, "certificateGateway").text() == "vpn.example.com"
    assert dialog.findChild(QPushButton, "certificateTrustButton") is not None


def test_changed_certificate_dialog_shows_previous(qapp) -> None:
    info = CertificateInfo(subject="CN=vpn.example.com", issuer="Example CA", sha256="bb" * 32)
    dialog = CertificateTrustDialog(
        gateway="vpn.example.com",
        certificate=info,
        previous_fingerprint="aa" * 32,
        changed=True,
    )
    assert "has changed" in dialog.windowTitle().lower()
    previous = dialog.findChild(QLabel, "certificatePreviousFingerprint")
    assert previous is not None
    assert "AA:AA" in previous.text()
