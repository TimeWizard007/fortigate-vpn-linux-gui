# SPDX-License-Identifier: GPL-3.0-or-later
"""Add/Edit dialog for a connection profile."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.helper.validation import format_sha256_fingerprint
from fortigate_vpn_gui.profiles.ipsec import (
    ADDR_MODECONFIG,
    AUTH_EAP,
    AUTH_PSK_XAUTH,
    CHILD_PROPOSAL_CHOICES,
    DH_GROUPS,
    IKE_MODE_AGGRESSIVE,
    IKE_MODE_MAIN,
    IKE_PROPOSAL_CHOICES,
    IKE_V1,
    IKE_V2,
    USER_AUTH_PSK_XAUTH,
    USER_AUTH_PSK_XAUTH_LABEL,
    USER_AUTH_SAML,
    USER_AUTH_SAML_LABEL,
    VPN_TYPE_IPSEC,
    VPN_TYPE_SSL,
    CryptoProposal,
    default_ikev2_saml_settings,
    default_ipsec_settings,
)
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import (
    PROFILE_FAMILY_IKEV1,
    PROFILE_FAMILY_IKEV2_SAML,
    PROFILE_FAMILY_SSL,
    VPN_TYPE_IKEV1_LABEL,
    VPN_TYPE_IKEV2_SAML_LABEL,
    VPN_TYPE_SSL_LABEL,
    ConnectionProfile,
    ProfileValidationError,
)
from fortigate_vpn_gui.system.psk_store import PSK_NOT_STORED_MESSAGE, PskStoreError

_ERROR_STYLE = "color: #c4564c;"
_ADVANCED_WIDE_MIN = 500


class _AdaptiveColumns(QWidget):
    """Two columns when wide enough, otherwise a single stacked column."""

    def __init__(self, left: QWidget, right: QWidget, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("profileIpsecAdvancedColumns")
        self._left = left
        self._right = right
        self._wide: bool | None = None
        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(0, 0, 0, 0)
        self._root.setSpacing(8)
        self._apply_layout(wide=True)

    def resizeEvent(self, event: QResizeEvent) -> None:
        wide = event.size().width() >= _ADVANCED_WIDE_MIN
        if wide != self._wide:
            self._apply_layout(wide=wide)
        super().resizeEvent(event)

    def is_wide(self) -> bool:
        return bool(self._wide)

    def _apply_layout(self, *, wide: bool) -> None:
        self._wide = wide
        old = self._root.takeAt(0)
        if old is not None:
            previous = old.layout()
            if previous is not None:
                previous.removeWidget(self._left)
                previous.removeWidget(self._right)
                holder = QWidget()
                holder.setLayout(previous)
                holder.deleteLater()
        layout = QHBoxLayout() if wide else QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self._left, 1)
        layout.addWidget(self._right, 1)
        self._root.addLayout(layout)


class _ProposalCheckList(QWidget):
    """Checkbox list of structured encryption/integrity pairs."""

    def __init__(
        self,
        object_name: str,
        choices: tuple[tuple[str, str], ...],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName(object_name)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(2)
        self._boxes: dict[CryptoProposal, QCheckBox] = {}
        for encryption, integrity in choices:
            self.ensure(CryptoProposal(encryption, integrity))

    def ensure(self, proposal: CryptoProposal) -> QCheckBox:
        existing = self._boxes.get(proposal)
        if existing is not None:
            return existing
        box = QCheckBox(proposal.label())
        box.setObjectName(f"{self.objectName()}_{proposal.encryption}_{proposal.integrity}")
        self._boxes[proposal] = box
        self._layout.addWidget(box)
        return box

    def selected(self) -> tuple[CryptoProposal, ...]:
        return tuple(proposal for proposal, box in self._boxes.items() if box.isChecked())

    def set_selected(self, proposals: tuple[CryptoProposal, ...]) -> None:
        wanted = set(proposals)
        for proposal in proposals:
            self.ensure(proposal)
        for proposal, box in self._boxes.items():
            box.setChecked(proposal in wanted)


class _DhCheckList(QWidget):
    """Checkbox list of DH group numbers."""

    def __init__(self, object_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName(object_name)
        self._layout = QGridLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setHorizontalSpacing(12)
        self._layout.setVerticalSpacing(2)
        self._boxes: dict[int, QCheckBox] = {}
        for index, group in enumerate(DH_GROUPS):
            box = QCheckBox(str(group))
            box.setObjectName(f"{object_name}_{group}")
            self._boxes[group] = box
            self._layout.addWidget(box, index // 4, index % 4)

    def selected(self) -> tuple[int, ...]:
        return tuple(group for group in DH_GROUPS if self._boxes[group].isChecked())

    def set_selected(self, groups: tuple[int, ...]) -> None:
        wanted = set(groups)
        for group, box in self._boxes.items():
            box.setChecked(group in wanted)


class ProfileEditorDialog(QDialog):
    """Collect profile fields and persist them through ``ProfileManager``."""

    def __init__(
        self,
        manager: ProfileManager,
        profile: ConnectionProfile | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._existing = profile
        self._updating_ipsec = False
        self.setWindowTitle("Edit profile" if profile else "New profile")
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setSizeGripEnabled(True)
        self.setMinimumWidth(420)
        self.setMinimumHeight(320)

        self._error_label = QLabel()
        self._error_label.setObjectName("profileEditorError")
        self._error_label.setWordWrap(True)
        self._error_label.setStyleSheet(_ERROR_STYLE)
        self._error_label.hide()

        self._name = QLineEdit()
        self._name.setObjectName("profileName")
        self._name.setPlaceholderText("Customer - ABC")
        self._name_error = self._field_error("profileNameError")

        self._gateway = QLineEdit()
        self._gateway.setObjectName("profileGateway")
        self._gateway.setPlaceholderText("vpn.example.com")
        self._gateway_error = self._field_error("profileGatewayError")

        self._port = QSpinBox()
        self._port.setObjectName("profilePort")
        self._port.setRange(1, 65535)
        self._port.setValue(443)
        self._port_error = self._field_error("profilePortError")

        self._description = QLineEdit()
        self._description.setObjectName("profileDescription")

        self._saml_radio = QRadioButton("SAML / SSO")
        self._saml_radio.setObjectName("profileAuthSaml")
        self._password_radio = QRadioButton("Username / Password")
        self._password_radio.setObjectName("profileAuthPassword")
        self._auth_group = QButtonGroup(self)
        self._auth_group.addButton(self._saml_radio)
        self._auth_group.addButton(self._password_radio)
        self._saml_radio.setChecked(True)
        self._saml_radio.toggled.connect(self._sync_auth_fields)

        self._vpn_type = QComboBox()
        self._vpn_type.setObjectName("profileVpnType")
        self._vpn_type.addItem(VPN_TYPE_SSL_LABEL, PROFILE_FAMILY_SSL)
        self._vpn_type.addItem(VPN_TYPE_IKEV1_LABEL, PROFILE_FAMILY_IKEV1)
        self._vpn_type.addItem(VPN_TYPE_IKEV2_SAML_LABEL, PROFILE_FAMILY_IKEV2_SAML)
        self._vpn_type.currentIndexChanged.connect(self._on_vpn_type_changed)

        self._local_id = QLineEdit()
        self._local_id.setObjectName("profileLocalId")
        self._peer_id = QLineEdit()
        self._peer_id.setObjectName("profilePeerId")
        self._ike_version = self._labeled_combo(
            "profileIkeVersion",
            (("ikev1", "IKEv1"), ("ikev2", "IKEv2")),
            "ikev1",
        )
        self._ike_mode = self._labeled_combo(
            "profileIkeMode",
            (("aggressive", "Aggressive"), ("main", "Main")),
            "aggressive",
        )
        self._user_auth = self._labeled_combo(
            "profileIpsecUserAuth",
            (
                (USER_AUTH_PSK_XAUTH, USER_AUTH_PSK_XAUTH_LABEL),
                (USER_AUTH_SAML, USER_AUTH_SAML_LABEL),
            ),
            USER_AUTH_PSK_XAUTH,
        )
        self._user_auth.setObjectName("profileIpsecUserAuth")
        self._user_auth.setParent(self)
        self._user_auth.hide()
        self._addr_assign = self._labeled_combo(
            "profileIpsecAddress",
            (("modeconfig", "Mode Config"), ("manual", "Manual")),
            "modeconfig",
        )
        self._ike_proposals = _ProposalCheckList("profileIkeProposals", IKE_PROPOSAL_CHOICES)
        self._ike_dh = _DhCheckList("profileIkeDhGroups")
        _legacy = default_ipsec_settings()
        self._ike_proposals.set_selected(_legacy.ike_proposals)
        self._ike_dh.set_selected(_legacy.ike_dh_groups)
        self._p1_life = QSpinBox()
        self._p1_life.setObjectName("profilePhase1Lifetime")
        self._p1_life.setRange(60, 604800)
        self._p1_life.setValue(86400)
        self._child_proposals = _ProposalCheckList("profileChildProposals", CHILD_PROPOSAL_CHOICES)
        self._child_proposals.set_selected(_legacy.child_proposals)
        self._pfs = QCheckBox("Perfect Forward Secrecy (PFS)")
        self._pfs.setObjectName("profilePfs")
        self._pfs.setChecked(True)
        self._pfs_dh = self._int_combo("profilePfsDh", DH_GROUPS, 14)
        self._p2_life = QSpinBox()
        self._p2_life.setObjectName("profilePhase2Lifetime")
        self._p2_life.setRange(60, 604800)
        self._p2_life.setValue(43200)
        self._natt = QCheckBox("NAT traversal")
        self._natt.setObjectName("profileNatT")
        self._natt.setChecked(True)
        self._dpd = QCheckBox("Dead Peer Detection")
        self._dpd.setObjectName("profileDpd")
        self._dpd.setChecked(True)
        self._dpd_interval = QSpinBox()
        self._dpd_interval.setObjectName("profileDpdInterval")
        self._dpd_interval.setRange(1, 604800)
        self._dpd_interval.setValue(60)
        self._replay = QCheckBox("Replay detection")
        self._replay.setObjectName("profileReplay")
        self._replay.setChecked(True)
        self._local_lan = QCheckBox("Local LAN access (stored; not fully implemented)")
        self._local_lan.setObjectName("profileLocalLan")
        self._ipsec_note = QLabel(
            "This release connects IKEv1 Aggressive + PSK + XAuth + Mode Config. "
            "Other stored combinations are not started."
        )
        self._ipsec_note.setWordWrap(True)
        self._ipsec_note.setObjectName("profileIpsecSupportNote")

        self._username_hint = QLineEdit()
        self._username_hint.setObjectName("profileUsernameHint")
        self._username_hint.setPlaceholderText("Optional reminder; passwords are not stored")
        self._username_label = QLabel("Username:")
        self._username_label.setObjectName("profileUsernameLabel")
        self._username_row = QWidget()
        self._username_row.setObjectName("profileUsernameRow")
        username_form = QFormLayout(self._username_row)
        self._apply_form_metrics(username_form)
        username_form.addRow(self._username_label, self._username_hint)

        self._psk = QLineEdit()
        self._psk.setObjectName("profileIpsecPsk")
        self._psk.setEchoMode(QLineEdit.EchoMode.Password)
        self._psk.setPlaceholderText("IPsec tunnel key; not the user password")
        self._psk_toggle = QPushButton("Show")
        self._psk_toggle.setObjectName("profileIpsecPskToggle")
        self._psk_toggle.setCheckable(True)
        self._psk_toggle.setFixedWidth(72)
        self._psk_toggle.setEnabled(False)
        self._psk_toggle.toggled.connect(self._on_psk_reveal)
        self._psk.textChanged.connect(self._sync_psk_reveal_button)
        psk_field = QWidget()
        psk_field.setObjectName("profileIpsecPskRow")
        psk_field_layout = QHBoxLayout(psk_field)
        psk_field_layout.setContentsMargins(0, 0, 0, 0)
        psk_field_layout.setSpacing(8)
        psk_field_layout.addWidget(self._psk, 1)
        psk_field_layout.addWidget(self._psk_toggle)
        self._save_psk = QCheckBox("Save pre-shared key securely")
        self._save_psk.setObjectName("profileSavePsk")
        self._psk_status = QLabel()
        self._psk_status.setObjectName("profilePskStatus")
        self._psk_status.setWordWrap(True)
        self._psk_status.hide()
        self._forget_psk = QPushButton("Forget saved pre-shared key")
        self._forget_psk.setObjectName("profileForgetPsk")
        self._forget_psk.clicked.connect(self._on_forget_psk)
        self._password_status = QLabel()
        self._password_status.setObjectName("profilePasswordStatus")
        self._password_status.setWordWrap(True)
        self._password_status.hide()
        self._forget_password = QPushButton("Forget saved XAuth password")
        self._forget_password.setObjectName("profileForgetPassword")
        self._forget_password.clicked.connect(self._on_forget_password)
        self._remember_username = QCheckBox("Remember username")
        self._remember_username.setObjectName("profileRememberUsername")
        self._xauth_note = QLabel(
            "Sign-in uses a username and password. These are not the IPsec tunnel key."
        )
        self._xauth_note.setObjectName("profileXauthNote")
        self._xauth_note.setWordWrap(True)
        self._sso_browser_note = QLabel(
            "Sign-in opens your system browser. Save the IPsec tunnel pre-shared key; "
            "it is not your SAML password."
        )
        self._sso_browser_note.setObjectName("profileIpsecSsoBrowserNote")
        self._sso_browser_note.setWordWrap(True)
        self._sso_protocol_note = QLabel(
            "After browser sign-in, the application starts the IPsec tunnel automatically."
        )
        self._sso_protocol_note.setObjectName("profileIpsecSsoProtocolNote")
        self._sso_protocol_note.setWordWrap(True)
        self._saml_port = QSpinBox()
        self._saml_port.setObjectName("profileIpsecSamlPort")
        self._saml_port.setRange(1, 65535)
        self._saml_port.setValue(1001)
        self._saml_port_host = QWidget()
        self._saml_port_host.setObjectName("profileIpsecSamlPortRow")
        saml_port_form = QFormLayout(self._saml_port_host)
        self._apply_form_metrics(saml_port_form)
        saml_port_form.setContentsMargins(0, 0, 0, 0)
        saml_port_form.addRow("SAML port:", self._saml_port)
        self._user_auth.currentIndexChanged.connect(self._on_user_auth_changed)
        self._ike_version.currentIndexChanged.connect(self._sync_ipsec_auth_ui)
        self._pfs.toggled.connect(self._sync_pfs_dh)
        self._psk_has_stored = False
        self._password_has_stored = False

        self._clear_trust = False
        self._cert_status = QLabel("No certificate pinned")
        self._cert_status.setObjectName("profileCertStatus")
        self._cert_status.setWordWrap(True)
        self._reset_cert = QPushButton("Remove certificate trust")
        self._reset_cert.setObjectName("profileResetCert")
        self._reset_cert.clicked.connect(self._on_reset_cert)

        self._basic_box = self._section("Connection", "profileBasicBox")
        basic_form = self._compact_form(self._basic_box)
        basic_form.addRow("Profile name:", self._stack_field(self._name, self._name_error))
        basic_form.addRow("VPN type:", self._vpn_type)
        basic_form.addRow("Gateway / Host:", self._stack_field(self._gateway, self._gateway_error))
        basic_form.addRow("Port:", self._stack_field(self._port, self._port_error))
        basic_form.addRow("Description:", self._description)

        self._ssl_auth_box = self._section("Authentication", "profileSslAuthBox")
        self._ssl_auth_layout = QVBoxLayout(self._ssl_auth_box)
        self._ssl_auth_layout.setContentsMargins(10, 8, 10, 8)
        self._ssl_auth_layout.setSpacing(4)
        self._ssl_auth_layout.addWidget(self._saml_radio)
        self._ssl_auth_layout.addWidget(self._password_radio)

        self._ipsec_box = self._section("Authentication", "profileIpsecBox")
        self._ipsec_layout = QVBoxLayout(self._ipsec_box)
        self._ipsec_layout.setContentsMargins(10, 8, 10, 8)
        self._ipsec_layout.setSpacing(6)
        tunnel_heading = QLabel("Tunnel authentication: Pre-shared key")
        tunnel_heading.setObjectName("profileIpsecTunnelAuthLabel")
        psk_form = QFormLayout()
        self._apply_form_metrics(psk_form)
        psk_form.addRow("Pre-shared key:", psk_field)
        self._ipsec_layout.addWidget(tunnel_heading)
        self._ipsec_layout.addLayout(psk_form)
        self._ipsec_layout.addWidget(self._save_psk)
        self._ipsec_layout.addWidget(self._psk_status)
        self._ipsec_layout.addWidget(self._forget_psk)
        self._ipsec_layout.addWidget(self._xauth_note)
        self._ipsec_layout.addWidget(self._sso_browser_note)
        self._ipsec_layout.addWidget(self._sso_protocol_note)
        self._ipsec_layout.addWidget(self._saml_port_host)

        self._cert_box = self._section("Certificate pin", "profileCertBox")
        cert_layout = QVBoxLayout(self._cert_box)
        cert_layout.setContentsMargins(10, 8, 10, 8)
        cert_layout.setSpacing(6)
        cert_layout.addWidget(self._cert_status)
        cert_layout.addWidget(self._reset_cert, alignment=Qt.AlignmentFlag.AlignLeft)

        self._ike_mode_row = QWidget()
        self._ike_mode_row.setObjectName("profileIkeModeRow")
        ike_mode_form = QFormLayout(self._ike_mode_row)
        self._apply_form_metrics(ike_mode_form)
        ike_mode_form.setContentsMargins(0, 0, 0, 0)
        ike_mode_form.addRow("IKE mode:", self._ike_mode)

        phase1 = self._section("IKE / Phase 1", "profileIpsecPhase1Box")
        phase1_form = self._compact_form(phase1)
        phase1_form.addRow("IKE version:", self._ike_version)
        phase1_form.addRow(self._ike_mode_row)
        phase1_form.addRow("Address assignment:", self._addr_assign)
        phase1_form.addRow("IKE proposals:", self._ike_proposals)
        phase1_form.addRow("DH groups:", self._ike_dh)
        phase1_form.addRow("IKE lifetime (s):", self._p1_life)
        phase1_form.addRow(self._dpd)
        phase1_form.addRow("DPD interval (s):", self._dpd_interval)
        phase1_form.addRow("Local ID:", self._local_id)
        phase1_form.addRow("Peer ID:", self._peer_id)

        phase2 = self._section("CHILD_SA / Phase 2", "profileIpsecPhase2Box")
        phase2_form = self._compact_form(phase2)
        phase2_form.addRow("CHILD_SA proposals:", self._child_proposals)
        phase2_form.addRow(self._pfs)
        phase2_form.addRow("PFS DH group:", self._pfs_dh)
        phase2_form.addRow("CHILD_SA lifetime (s):", self._p2_life)
        phase2_form.addRow(self._replay)

        transport = self._section("Transport", "profileIpsecTransportBox")
        transport_form = self._compact_form(transport)
        transport_form.addRow(self._natt)
        transport_form.addRow(self._local_lan)

        right_column = QWidget()
        right_layout = QVBoxLayout(right_column)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        right_layout.addWidget(phase2)
        right_layout.addWidget(transport)
        right_layout.addStretch(1)

        self._advanced_columns = _AdaptiveColumns(phase1, right_column)
        self._ipsec_advanced = QGroupBox("Advanced")
        self._ipsec_advanced.setObjectName("profileIpsecAdvancedBox")
        self._ipsec_advanced.setCheckable(True)
        advanced_layout = QVBoxLayout(self._ipsec_advanced)
        advanced_layout.setContentsMargins(10, 8, 10, 8)
        advanced_layout.setSpacing(8)
        advanced_layout.addWidget(self._ipsec_note)
        advanced_layout.addWidget(self._advanced_columns)

        if profile is not None:
            self._name.setText(profile.name)
            self._gateway.setText(profile.gateway)
            self._port.setValue(profile.port)
            self._description.setText(profile.description)
            self._username_hint.setText(profile.username_hint)
            self._remember_username.setChecked(bool(profile.username_hint))
            self._saml_radio.setChecked(profile.use_sso)
            self._password_radio.setChecked(not profile.use_sso)
            self._vpn_type.blockSignals(True)
            self._set_combo(self._vpn_type, profile.profile_family())
            self._vpn_type.blockSignals(False)
            if profile.is_ipsec():
                self._apply_ipsec(profile.ipsec or default_ipsec_settings())
            self._refresh_cert_status(profile.trusted_cert_sha256)
        else:
            self._refresh_cert_status(None)
            self._reset_cert.setEnabled(False)

        content = QWidget()
        content.setObjectName("profileEditorContent")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 2, 0)
        content_layout.setSpacing(8)
        content_layout.addWidget(self._basic_box)
        content_layout.addWidget(self._ssl_auth_box)
        content_layout.addWidget(self._ipsec_box)
        content_layout.addWidget(self._cert_box)
        content_layout.addWidget(self._ipsec_advanced)
        content_layout.addStretch(0)

        self._scroll = QScrollArea()
        self._scroll.setObjectName("profileEditorScroll")
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._scroll.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        self._scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._scroll.setWidget(content)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.setObjectName("profileEditorButtons")
        buttons.accepted.connect(self.submit)
        buttons.rejected.connect(self.reject)
        ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        if ok_button is not None:
            ok_button.setDefault(True)
            ok_button.setAutoDefault(True)
            self._ok_button = ok_button

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(self._error_label)
        layout.addWidget(self._scroll, 1)
        layout.addWidget(buttons)
        self._sync_auth_fields()
        self._sync_vpn_type()
        self._sync_psk_reveal_button()
        self._fit_to_screen()

    def error_text(self) -> str:
        """Return the validation message shown in the dialog."""
        return self._error_label.text()

    def field_error_text(self, field: str) -> str:
        """Return the per-field validation message, if any."""
        label = {
            "name": self._name_error,
            "gateway": self._gateway_error,
            "port": self._port_error,
        }.get(field)
        if label is None or label.isHidden():
            return ""
        return label.text()

    def submit(self) -> bool:
        """Validate and save. Returns True when the dialog is accepted."""
        self._clear_errors()
        ipsec = self._is_ipsec_family()
        if ipsec and self._save_psk.isChecked():
            typed = self._psk.text()
            if not typed and not self._psk_has_stored:
                message = "Enter the IPsec pre-shared key to save it, or clear Save pre-shared key."
                self._show_errors(ProfileValidationError([message], field_errors={"psk": message}))
                return False
        values = {
            "name": self._name.text(),
            "gateway": self._gateway.text(),
            "port": self._port.value(),
            "description": self._description.text(),
            "username_hint": self._stored_username_hint(),
            "use_sso": (self._is_saml_user_auth() if ipsec else self._saml_radio.isChecked()),
            "vpn_type": VPN_TYPE_IPSEC if ipsec else VPN_TYPE_SSL,
            "ipsec": self._ipsec_values(),
        }
        if self._existing is not None:
            values["trusted_cert_sha256"] = (
                None if self._clear_trust else self._existing.trusted_cert_sha256
            )
        ok = getattr(self, "_ok_button", None)
        if ok is not None:
            ok.setEnabled(False)
        try:
            if self._existing is None:
                profile = self._manager.add(**values)
            else:
                profile = self._manager.update(self._existing.id, **values)
        except ProfileValidationError as exc:
            if ok is not None:
                ok.setEnabled(True)
            self._show_errors(exc)
            return False
        self._persist_psk(profile)
        self.accept()
        return True

    def _show_errors(self, exc: ProfileValidationError) -> None:
        self._error_label.setText("\n".join(exc.errors))
        self._error_label.show()
        mapping = {
            "name": self._name_error,
            "gateway": self._gateway_error,
            "port": self._port_error,
        }
        for field, message in exc.field_errors.items():
            label = mapping.get(field)
            if label is None:
                continue
            label.setText(message)
            label.show()

    def _clear_errors(self) -> None:
        self._error_label.hide()
        self._error_label.clear()
        for label in (self._name_error, self._gateway_error, self._port_error):
            label.hide()
            label.clear()

    def _sync_auth_fields(self) -> None:
        ipsec = self._is_ipsec_family()
        self._username_row.setVisible(ipsec or self._password_radio.isChecked())
        if ipsec:
            self._sync_ipsec_auth_ui()

    def _family(self) -> str:
        return str(self._vpn_type.currentData() or PROFILE_FAMILY_SSL)

    def _is_ipsec_family(self) -> bool:
        return self._family() != PROFILE_FAMILY_SSL

    def _on_vpn_type_changed(self) -> None:
        family = self._family()
        ipsec = family != PROFILE_FAMILY_SSL
        if ipsec and self._port.value() == 443:
            self._port.setValue(500)
        elif not ipsec and self._port.value() == 500:
            self._port.setValue(443)
        if family == PROFILE_FAMILY_IKEV2_SAML:
            self._updating_ipsec = True
            try:
                self._set_combo(self._user_auth, USER_AUTH_SAML)
            finally:
                self._updating_ipsec = False
            self._apply_saml_ike_defaults()
        elif family == PROFILE_FAMILY_IKEV1:
            self._updating_ipsec = True
            try:
                self._set_combo(self._user_auth, USER_AUTH_PSK_XAUTH)
            finally:
                self._updating_ipsec = False
            # Widgets already default to IKEv1. Applying full defaults here
            # would wipe local_id/peer_id/proposals on an existing profile if
            # this handler runs for any reason other than leaving IKEv2 SAML.
            if self._ike_version.currentData() == IKE_V2:
                self._apply_ikev1_defaults()
            else:
                self._set_combo(self._ike_version, IKE_V1)
                self._set_combo(self._ike_mode, IKE_MODE_AGGRESSIVE)
                self._set_combo(self._addr_assign, ADDR_MODECONFIG)
        self._sync_vpn_type()

    def _sync_vpn_type(self) -> None:
        ipsec = self._is_ipsec_family()
        self._ssl_auth_box.setVisible(not ipsec)
        self._ipsec_box.setVisible(ipsec)
        self._ipsec_advanced.setVisible(ipsec)
        self._cert_box.setVisible(not ipsec)
        self._reset_cert.setVisible(not ipsec)
        self._cert_status.setVisible(not ipsec)
        if ipsec:
            self._password_radio.setChecked(True)
            self._username_label.setText("Username:")
            self._username_hint.setPlaceholderText("XAuth username, for example mwi")
            if not self._username_hint.text():
                self._remember_username.setChecked(True)
            self._place_username_row(ipsec=True)
            existing_ipsec = self._existing is not None and self._existing.is_ipsec()
            self._ipsec_advanced.setChecked(existing_ipsec)
        else:
            self._username_label.setText("Username hint:")
            self._username_hint.setPlaceholderText("Optional reminder; passwords are not stored")
            self._place_username_row(ipsec=False)
        self._sync_psk_storage_ui()
        self._sync_psk_reveal_button()
        self._sync_auth_fields()
        self._sync_ipsec_auth_ui()

    def _is_saml_user_auth(self) -> bool:
        family = self._family()
        if family == PROFILE_FAMILY_IKEV2_SAML:
            return True
        if family == PROFILE_FAMILY_IKEV1:
            return False
        return self._user_auth.currentData() == USER_AUTH_SAML

    def _on_user_auth_changed(self) -> None:
        if self._updating_ipsec:
            return
        if self._user_auth.currentData() == USER_AUTH_SAML:
            self._vpn_type.blockSignals(True)
            self._set_combo(self._vpn_type, PROFILE_FAMILY_IKEV2_SAML)
            self._vpn_type.blockSignals(False)
            self._apply_saml_ike_defaults()
        elif self._ike_version.currentData() == IKE_V2:
            self._vpn_type.blockSignals(True)
            self._set_combo(self._vpn_type, PROFILE_FAMILY_IKEV1)
            self._vpn_type.blockSignals(False)
            self._set_combo(self._ike_version, IKE_V1)
            self._set_combo(self._ike_mode, IKE_MODE_AGGRESSIVE)
        self._sync_ipsec_auth_ui()

    def _apply_ikev1_defaults(self) -> None:
        defaults = default_ipsec_settings()
        local_id = self._local_id.text()
        peer_id = self._peer_id.text()
        self._updating_ipsec = True
        try:
            self._set_combo(self._ike_version, defaults.ike_version)
            self._set_combo(self._ike_mode, defaults.ike_mode)
            self._set_combo(self._user_auth, USER_AUTH_PSK_XAUTH)
            self._set_combo(self._addr_assign, defaults.address_assignment)
            self._ike_proposals.set_selected(defaults.ike_proposals)
            self._ike_dh.set_selected(defaults.ike_dh_groups)
            self._p1_life.setValue(defaults.phase1_lifetime)
            self._child_proposals.set_selected(defaults.child_proposals)
            self._pfs.setChecked(defaults.pfs)
            self._set_combo(self._pfs_dh, defaults.pfs_dh_group)
            self._p2_life.setValue(defaults.phase2_lifetime)
            self._natt.setChecked(defaults.nat_traversal)
            self._dpd.setChecked(defaults.dpd)
            self._replay.setChecked(defaults.replay_detection)
            self._local_id.setText(local_id)
            self._peer_id.setText(peer_id)
        finally:
            self._updating_ipsec = False

    def _apply_saml_ike_defaults(self) -> None:
        defaults = default_ikev2_saml_settings()
        self._updating_ipsec = True
        try:
            self._set_combo(self._ike_version, defaults.ike_version)
            self._set_combo(self._ike_mode, defaults.ike_mode)
            self._set_combo(self._addr_assign, defaults.address_assignment)
            self._ike_proposals.set_selected(defaults.ike_proposals)
            self._ike_dh.set_selected(defaults.ike_dh_groups)
            self._p1_life.setValue(defaults.phase1_lifetime)
            self._child_proposals.set_selected(defaults.child_proposals)
            self._pfs.setChecked(defaults.pfs)
            self._set_combo(self._pfs_dh, defaults.pfs_dh_group)
            self._p2_life.setValue(defaults.phase2_lifetime)
            self._natt.setChecked(defaults.nat_traversal)
            self._dpd.setChecked(defaults.dpd)
            self._replay.setChecked(defaults.replay_detection)
            self._saml_port.setValue(defaults.saml_port)
        finally:
            self._updating_ipsec = False

    def _sync_ipsec_auth_ui(self) -> None:
        ipsec = self._is_ipsec_family()
        if not ipsec:
            return
        saml = self._is_saml_user_auth()
        ikev2 = saml or self._ike_version.currentData() == IKE_V2
        self._ike_version.setEnabled(not saml)
        self._ike_mode_row.setVisible(not ikev2)
        self._xauth_note.setVisible(not saml)
        self._username_row.setVisible(not saml)
        self._remember_username.setVisible(not saml)
        self._password_status.setVisible(not saml)
        self._forget_password.setVisible(not saml)
        self._saml_port_host.setVisible(saml)
        self._sso_browser_note.setVisible(saml)
        self._sso_protocol_note.setVisible(saml)
        if saml:
            self._psk.setPlaceholderText("IPsec tunnel key. Not used for SAML user authentication.")
            self._ipsec_note.setText(
                "Sign-in opens your system browser. Save the IPsec tunnel "
                "pre-shared key; it is not the SAML password."
            )
        else:
            self._psk.setPlaceholderText("IPsec tunnel key; not the user password")
            self._ipsec_note.setText(
                "This release connects IKEv1 Aggressive + PSK + username/password. "
                "Other stored combinations are not started."
            )
        self._sync_pfs_dh()

    def _sync_pfs_dh(self) -> None:
        self._pfs_dh.setEnabled(self._pfs.isChecked())

    def _place_username_row(self, *, ipsec: bool) -> None:
        parent = self._username_row.parentWidget()
        if parent is not None and parent.layout() is not None:
            parent.layout().removeWidget(self._username_row)
        remember_parent = self._remember_username.parentWidget()
        if remember_parent is not None and remember_parent.layout() is not None:
            remember_parent.layout().removeWidget(self._remember_username)
        for extra in (self._password_status, self._forget_password):
            extra_parent = extra.parentWidget()
            if extra_parent is not None and extra_parent.layout() is not None:
                extra_parent.layout().removeWidget(extra)
        if ipsec:
            index = self._ipsec_layout.indexOf(self._xauth_note)
            widgets = (
                self._username_row,
                self._remember_username,
                self._password_status,
                self._forget_password,
            )
            if index < 0:
                for widget in widgets:
                    self._ipsec_layout.addWidget(widget)
            else:
                for offset, widget in enumerate(widgets):
                    self._ipsec_layout.insertWidget(index + 1 + offset, widget)
            return
        self._remember_username.hide()
        self._password_status.hide()
        self._forget_password.hide()
        self._ssl_auth_layout.addWidget(self._username_row)

    def _stored_username_hint(self) -> str:
        if self._family() == PROFILE_FAMILY_IKEV1:
            if not self._remember_username.isChecked():
                return ""
            return self._username_hint.text()
        if self._is_saml_user_auth():
            return self._username_hint.text() if self._remember_username.isChecked() else ""
        return self._username_hint.text()

    def _sync_psk_storage_ui(self) -> None:
        ipsec = self._is_ipsec_family()
        if not ipsec:
            return
        store = self._manager.psk_store
        self._psk_has_stored = False
        self._password_has_stored = False
        typed = self._psk.text()
        if not store.is_available():
            self._save_psk.setChecked(False)
            self._save_psk.setEnabled(False)
            self._psk_status.setText("Secure storage unavailable. " + store.unavailable_message())
            self._psk_status.show()
            self._forget_psk.setEnabled(False)
            self._password_status.setText(
                "Secure storage unavailable. " + store.password_unavailable_message()
            )
            self._password_status.show()
            self._forget_password.setEnabled(False)
            if not typed:
                self._psk.setPlaceholderText(
                    "Not stored. This key is not the user password and will be asked at connect."
                )
            return
        self._save_psk.setEnabled(True)
        stored = False
        stored_password = False
        if self._existing is not None:
            stored = store.contains(self._existing.id)
            stored_password = store.contains_xauth_password(self._existing.id)
        if stored:
            self._save_psk.setChecked(True)
            self._psk_has_stored = True
            if not typed:
                self._psk.setPlaceholderText("Saved securely — leave blank to keep")
            self._psk_status.setText("Pre-shared key: stored securely")
            self._psk_status.show()
            self._forget_psk.setEnabled(True)
        else:
            if self._existing is None:
                self._save_psk.setChecked(False)
            if not typed:
                self._psk.setPlaceholderText("IPsec tunnel key; not the user password")
            self._psk_status.setText("Pre-shared key: not stored")
            self._psk_status.show()
            self._forget_psk.setEnabled(False)
        if stored_password:
            self._password_has_stored = True
            self._password_status.setText("XAuth password: stored securely")
            self._password_status.show()
            self._forget_password.setEnabled(True)
        else:
            self._password_status.setText("XAuth password: not stored")
            self._password_status.show()
            self._forget_password.setEnabled(False)

    def _on_forget_psk(self) -> None:
        if self._existing is None:
            self._psk.clear()
            self._psk_has_stored = False
            self._save_psk.setChecked(False)
            self._sync_psk_storage_ui()
            return
        store = self._manager.psk_store
        store.delete(self._existing.id)
        self._psk.clear()
        self._psk_has_stored = False
        self._save_psk.setChecked(False)
        self._sync_psk_storage_ui()

    def _on_forget_password(self) -> None:
        if self._existing is None:
            self._password_has_stored = False
            self._sync_psk_storage_ui()
            return
        store = self._manager.psk_store
        store.delete_xauth_password(self._existing.id)
        self._password_has_stored = False
        self._sync_psk_storage_ui()

    def _sync_psk_reveal_button(self) -> None:
        """Show/Hide only the newly typed PSK. Never fetch a stored secret."""
        if self._psk.text():
            self._psk_toggle.setEnabled(True)
            return
        self._psk_toggle.blockSignals(True)
        self._psk_toggle.setChecked(False)
        self._psk_toggle.blockSignals(False)
        self._psk.setEchoMode(QLineEdit.EchoMode.Password)
        self._psk_toggle.setText("Show")
        self._psk_toggle.setEnabled(False)

    def _on_psk_reveal(self, checked: bool) -> None:
        if not self._psk.text():
            self._sync_psk_reveal_button()
            return
        if checked:
            self._psk.setEchoMode(QLineEdit.EchoMode.Normal)
            self._psk_toggle.setText("Hide")
            return
        self._psk.setEchoMode(QLineEdit.EchoMode.Password)
        self._psk_toggle.setText("Show")

    def _persist_psk(self, profile: ConnectionProfile) -> None:
        store = self._manager.psk_store
        typed = self._psk.text()
        if not profile.is_ipsec():
            store.delete_all(profile.id)
            return
        if not store.is_available():
            if typed:
                QMessageBox.information(self, "Pre-shared key not saved", PSK_NOT_STORED_MESSAGE)
            return
        save = self._save_psk.isEnabled() and self._save_psk.isChecked()
        if not save:
            store.delete(profile.id)
            return
        if typed:
            try:
                store.set(profile.id, typed)
            except PskStoreError as exc:
                QMessageBox.warning(self, "Pre-shared key not saved", str(exc))
            return
        if self._psk_has_stored:
            return
        # Blank PSK while editing means keep the existing stored PSK.
        # XAuth passwords are never written or deleted here.

    def _ipsec_values(self) -> dict[str, object]:
        saml = self._is_saml_user_auth()
        ike_proposals = self._ike_proposals.selected()
        child_proposals = self._child_proposals.selected()
        ike_dh = self._ike_dh.selected()
        pfs_dh = self._pfs_dh.currentData()
        return {
            "ike_version": IKE_V2 if saml else self._ike_version.currentData(),
            "ike_mode": IKE_MODE_MAIN if saml else self._ike_mode.currentData(),
            "auth_method": AUTH_EAP if saml else AUTH_PSK_XAUTH,
            "address_assignment": self._addr_assign.currentData(),
            "local_id": self._local_id.text(),
            "peer_id": self._peer_id.text(),
            "ike_proposals": [item.to_json() for item in ike_proposals],
            "ike_dh_groups": list(ike_dh),
            "phase1_lifetime": self._p1_life.value(),
            "child_proposals": [item.to_json() for item in child_proposals],
            "pfs": self._pfs.isChecked(),
            "pfs_dh_group": pfs_dh,
            "pfs_dh_groups": [pfs_dh],
            "phase2_lifetime": self._p2_life.value(),
            "nat_traversal": self._natt.isChecked(),
            "dpd": self._dpd.isChecked(),
            "dpd_interval": self._dpd_interval.value(),
            "replay_detection": self._replay.isChecked(),
            "local_lan_access": self._local_lan.isChecked(),
            "saml_port": self._saml_port.value(),
        }

    def _apply_ipsec(self, settings) -> None:
        self._updating_ipsec = True
        try:
            self._local_id.setText(settings.local_id)
            self._peer_id.setText(settings.peer_id)
            self._set_combo(self._ike_version, settings.ike_version)
            self._set_combo(self._ike_mode, settings.ike_mode)
            self._set_combo(self._user_auth, settings.user_auth_mode())
            self._set_combo(self._addr_assign, settings.address_assignment)
            self._ike_proposals.set_selected(settings.ike_proposals)
            self._ike_dh.set_selected(settings.ike_dh_groups)
            self._p1_life.setValue(settings.phase1_lifetime)
            self._child_proposals.set_selected(settings.child_proposals)
            self._pfs.setChecked(settings.pfs)
            self._set_combo(self._pfs_dh, settings.pfs_dh_group)
            self._p2_life.setValue(settings.phase2_lifetime)
            self._natt.setChecked(settings.nat_traversal)
            self._dpd.setChecked(settings.dpd)
            self._dpd_interval.setValue(settings.dpd_interval)
            self._replay.setChecked(settings.replay_detection)
            self._local_lan.setChecked(settings.local_lan_access)
            self._saml_port.setValue(settings.saml_port)
        finally:
            self._updating_ipsec = False

    def _fit_to_screen(self) -> None:
        screen = self.screen()
        if screen is None:
            screen = QApplication.primaryScreen()
        if screen is None:
            self.resize(560, 520)
            return
        geo = screen.availableGeometry()
        max_w = max(420, geo.width() - 80)
        max_h = max(320, geo.height() - 80)
        self.setMaximumSize(max_w, max_h)
        self.resize(min(640, max_w), min(520, max_h))

    @staticmethod
    def _section(title: str, object_name: str) -> QGroupBox:
        box = QGroupBox(title)
        box.setObjectName(object_name)
        return box

    @staticmethod
    def _apply_form_metrics(form: QFormLayout) -> None:
        form.setContentsMargins(0, 0, 0, 0)
        form.setVerticalSpacing(6)
        form.setHorizontalSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

    @classmethod
    def _compact_form(cls, host: QWidget) -> QFormLayout:
        form = QFormLayout(host)
        form.setContentsMargins(10, 8, 10, 8)
        form.setVerticalSpacing(6)
        form.setHorizontalSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return form

    @staticmethod
    def _labeled_combo(
        object_name: str, choices: tuple[tuple[str, str], ...], current: str
    ) -> QComboBox:
        combo = QComboBox()
        combo.setObjectName(object_name)
        for value, label in choices:
            combo.addItem(label, value)
        ProfileEditorDialog._set_combo(combo, current)
        return combo

    @staticmethod
    def _int_combo(object_name: str, values, current: int) -> QComboBox:
        combo = QComboBox()
        combo.setObjectName(object_name)
        for value in values:
            combo.addItem(str(value), value)
        ProfileEditorDialog._set_combo(combo, current)
        return combo

    @staticmethod
    def _set_combo(combo: QComboBox, value: object) -> None:
        index = combo.findData(value)
        if index >= 0:
            combo.setCurrentIndex(index)

    def _on_reset_cert(self) -> None:
        self._clear_trust = True
        self._refresh_cert_status(None)
        self._reset_cert.setEnabled(False)

    def _refresh_cert_status(self, fingerprint: str | None) -> None:
        if fingerprint:
            shown = format_sha256_fingerprint(fingerprint)
            self._cert_status.setText(f"Pinned SHA-256:\n{shown}")
            self._reset_cert.setEnabled(True)
        else:
            self._cert_status.setText("No certificate pinned")
            self._reset_cert.setEnabled(False)

    @staticmethod
    def _field_error(object_name: str) -> QLabel:
        label = QLabel()
        label.setObjectName(object_name)
        label.setWordWrap(True)
        label.setStyleSheet(_ERROR_STYLE)
        label.hide()
        return label

    @staticmethod
    def _stack_field(widget: QWidget, error: QLabel) -> QWidget:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        layout.addWidget(widget)
        layout.addWidget(error)
        return wrap
