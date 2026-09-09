# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit FortiGate gateway certificate trust dialogs.

Fingerprints may be shown. SAML tokens, cookies, and auth URL query values
are never displayed.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.helper.protocol import CertificateInfo
from fortigate_vpn_gui.helper.validation import format_sha256_fingerprint


class CertificateTrustDialog(QDialog):
    """Ask the user to pin a gateway certificate to the current profile."""

    def __init__(
        self,
        *,
        gateway: str,
        certificate: CertificateInfo,
        previous_fingerprint: str | None = None,
        changed: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._certificate = certificate
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setMinimumWidth(520)
        if changed:
            self.setWindowTitle("The gateway certificate has changed")
            intro = (
                "The gateway certificate has changed.\n\n"
                "This application will not replace the previously trusted "
                "fingerprint automatically. Treat this as a possible "
                "man-in-the-middle risk unless you expected a new certificate."
            )
        else:
            self.setWindowTitle("Gateway certificate could not be validated")
            intro = (
                "Gateway certificate could not be validated automatically.\n\n"
                "Trusting this certificate pins its SHA-256 fingerprint to this "
                "VPN profile only. This is certificate pinning, not a general "
                "disable of TLS validation. Do not continue unless you expected "
                "this FortiGate certificate."
            )

        heading = QLabel(intro)
        heading.setWordWrap(True)
        heading.setObjectName("certificateTrustIntro")

        gateway_label = QLabel(gateway)
        gateway_label.setObjectName("certificateGateway")
        gateway_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        subject_label = QLabel(certificate.subject)
        subject_label.setObjectName("certificateSubject")
        subject_label.setWordWrap(True)
        issuer_label = QLabel(certificate.issuer)
        issuer_label.setObjectName("certificateIssuer")
        issuer_label.setWordWrap(True)
        fingerprint_label = QLabel(format_sha256_fingerprint(certificate.sha256))
        fingerprint_label.setObjectName("certificateFingerprint")
        fingerprint_label.setWordWrap(True)

        form = QFormLayout()
        form.addRow("Gateway:", gateway_label)
        form.addRow("Subject:", subject_label)
        form.addRow("Issuer:", issuer_label)
        form.addRow("SHA-256 fingerprint:", fingerprint_label)
        if changed and previous_fingerprint:
            previous_label = QLabel(format_sha256_fingerprint(previous_fingerprint))
            previous_label.setObjectName("certificatePreviousFingerprint")
            previous_label.setWordWrap(True)
            form.addRow("Previously trusted fingerprint:", previous_label)

        buttons = QDialogButtonBox()
        cancel = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        trust = buttons.addButton(
            "Trust this certificate for this VPN profile",
            QDialogButtonBox.ButtonRole.AcceptRole,
        )
        trust.setObjectName("certificateTrustButton")
        cancel.setObjectName("certificateCancelButton")
        buttons.rejected.connect(self.reject)
        trust.clicked.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def certificate(self) -> CertificateInfo:
        return self._certificate
