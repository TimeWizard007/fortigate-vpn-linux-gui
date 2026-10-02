# SPDX-License-Identifier: GPL-3.0-or-later
"""Log redaction tests. No network, sudo, or VPN processes."""

from __future__ import annotations

from fortigate_vpn_gui.vpn.log_redaction import redact_log_line


def test_redact_password() -> None:
    assert redact_log_line("password=supersecret") == "password=***"
    assert redact_log_line("PASSWORD: hunter2") == "PASSWORD: ***"


def test_redact_svpncookie() -> None:
    assert redact_log_line("SVPNCOOKIE=abc123") == "SVPNCOOKIE=***"
    assert redact_log_line("svpncookie=abc123") == "svpncookie=***"


def test_redact_authorization_bearer() -> None:
    line = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
    assert redact_log_line(line) == "Authorization: Bearer ***"
    assert redact_log_line("authorization: bearer abc") == "authorization: bearer ***"


def test_redact_cookie() -> None:
    assert redact_log_line("Cookie: SVPNCOOKIE=xyz") == "Cookie: ***"
    assert redact_log_line("Set-Cookie: sid=123") == "Set-Cookie: ***"
    assert redact_log_line("cookie=xyz") == "cookie=***"


def test_redact_saml_response_and_relay_state() -> None:
    assert "abc" not in redact_log_line("SAMLResponse=abc123")
    assert redact_log_line("SAMLResponse=abc123") == "SAMLResponse=***"
    assert "xyz" not in redact_log_line("RelayState=xyz")
    assert redact_log_line("RelayState=xyz") == "RelayState=***"


def test_redact_id_and_session_identifiers() -> None:
    assert "secret" not in redact_log_line("http://127.0.0.1:8020/?id=secret")
    assert "id=***" in redact_log_line("callback id=secretid")
    assert redact_log_line("session_id=sess-99") == "session_id=***"


def test_redact_token_query_parameters() -> None:
    line = "https://login.example.com/cb?access_token=aaa&refresh_token=bbb&id_token=ccc"
    redacted = redact_log_line(line)
    assert "aaa" not in redacted
    assert "bbb" not in redacted
    assert "ccc" not in redacted
    assert "access_token=***" in redacted


def test_redact_id_token_and_client_secret() -> None:
    assert redact_log_line("id_token=hunter2") == "id_token=***"
    assert redact_log_line("client_secret=shh") == "client_secret=***"


def test_redact_tokenid_and_fct_token_id() -> None:
    token = "cafebabefacefeedcafebabefacefeed"
    assert redact_log_line(f"tokenid={token}") == "tokenid=***"
    assert token not in redact_log_line(f"Received request: GET /?tokenid={token}&username=ada")
    assert redact_log_line("FCT_TOKEN_ID=not-a-real-token") == "FCT_TOKEN_ID=***"


def test_redact_eap_identity_and_fct_uid() -> None:
    uid = "0123456789abcdef0123456789abcdef"
    assert uid not in redact_log_line(f"FCT_UID={uid}")
    assert uid not in redact_log_line(f"eap_id={uid}")
    assert uid not in redact_log_line(f"received EAP identity '{uid}'")
    loaded = redact_log_line(f"loaded EAP shared key 'eap' for '{uid}'")
    assert uid not in loaded
    assert "eap" in loaded.lower()
    vici = redact_log_line(f"loaded EAP shared key with id 'eap' for: '{uid}'")
    assert uid not in vici
    assert "eap" in vici.lower()
    assert "for:" in vici
    compat = redact_log_line("FortiClient compatibility: removed EAP_ONLY from first IKE_AUTH")
    assert compat == "FortiClient compatibility: removed EAP_ONLY from first IKE_AUTH"
    assert uid not in compat
    msgid = redact_log_line("FortiClient compatibility: removed MSG_ID_SYN_SUP from first IKE_AUTH")
    assert msgid == "FortiClient compatibility: removed MSG_ID_SYN_SUP from first IKE_AUTH"
    assert uid not in msgid
    initc = redact_log_line("FortiClient compatibility: added INITIAL_CONTACT to first IKE_AUTH")
    assert initc == "FortiClient compatibility: added INITIAL_CONTACT to first IKE_AUTH"
    assert uid not in initc
    license_log = redact_log_line("FortiClient compatibility: added private Notify 0xF100")
    assert license_log == "FortiClient compatibility: added private Notify 0xF100"
    length_log = redact_log_line("FortiClient compatibility: license-info payload length: 128")
    assert length_log == "FortiClient compatibility: license-info payload length: 128"
    pos_log = redact_log_line(
        "FortiClient compatibility: repositioned Notify 0xF100 before CFG_REQUEST"
    )
    assert pos_log == "FortiClient compatibility: repositioned Notify 0xF100 before CFG_REQUEST"
    cp_log = redact_log_line(
        "FortiClient compatibility: first IKE_AUTH CP request attributes: "
        "16 types 1,2,7,3,4,13,8,10,11,15,25,21516,28678,21514,21515,28673"
    )
    assert cp_log == (
        "FortiClient compatibility: first IKE_AUTH CP request attributes: "
        "16 types 1,2,7,3,4,13,8,10,11,15,25,21516,28678,21514,21515,28673"
    )
    assert uid not in cp_log
    assert uid not in redact_log_line(f"UID={uid}")
    secret = redact_log_line(f"loaded EAP secret for '{uid}'")
    assert uid not in secret
    redacted = redact_log_line(
        "http://127.0.0.1:9/?tokenid=TEST_ONLY_TOKEN_DO_NOT_USE&username=test-user"
    )
    assert "TEST_ONLY_TOKEN_DO_NOT_USE" not in redacted
    assert "test-user" not in redacted
    assert "tokenid=***" in redacted


def test_redact_mixed_capitalization() -> None:
    text = "PaSsWoRd=abc SVPNCOOKIE=tok Authorization: BeArEr jwt"
    redacted = redact_log_line(text)
    assert "abc" not in redacted
    assert "tok" not in redacted
    assert "jwt" not in redacted
    assert "***" in redacted


def test_saml_auth_url_strips_query_and_fragment() -> None:
    line = (
        "INFO:   Authenticate at "
        "'https://vpnbiuro.itsolution.pl:17414/remote/saml/start?redirect=1'"
    )
    redacted = redact_log_line(line)
    assert redacted == (
        "INFO:   Authenticate at 'https://vpnbiuro.itsolution.pl:17414/remote/saml/start'"
    )
    assert "redirect" not in redacted
    assert "?" not in redacted


def test_saml_auth_url_strips_fragment() -> None:
    line = (
        "INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1#session'"
    )
    redacted = redact_log_line(line)
    assert redacted == ("INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start'")
    assert "session" not in redacted
    assert "redirect" not in redacted


def test_redact_strongswan_eap_identity_sending_fct_uid() -> None:
    uid = "0123456789abcdef0123456789abcdef"
    mixed = "0123456789ABCDEF0123456789abcdef"
    quoted = redact_log_line(f"server requested EAP_IDENTITY (id 0x01), sending '{uid}'")
    assert uid not in quoted
    assert "sending '***'" in quoted
    assert "EAP_IDENTITY" in quoted
    unquoted = redact_log_line(f"server requested EAP_IDENTITY (id 0x01), sending {uid}")
    assert uid not in unquoted
    assert "***" in unquoted
    upper = redact_log_line(f"server requested EAP_IDENTITY (id 0x01), sending '{mixed}'")
    assert mixed not in upper
    assert mixed.lower() not in upper.lower() or "***" in upper
    assert "sending '***'" in upper
    bare = redact_log_line(f"sending '{uid}'")
    assert uid not in bare
    assert "sending '***'" in bare
    auth = redact_log_line(f"authentication of '{uid}' (with EAP_MSCHAPV2) successful")
    assert uid not in auth
    assert "authentication of '***'" in auth
    keyid = redact_log_line(f"IDi payload: ID_KEY_ID '{uid}'")
    assert uid not in keyid
    assert "ID_KEY_ID '***'" in keyid


def test_redact_helper_json_and_tokenid_secret_fields() -> None:
    token = "cafebabefacefeedcafebabefacefeed"
    psk = "TEST_ONLY_PSK_DO_NOT_USE"
    payload = (
        '{"operation":"connect","psk":"'
        + psk
        + '","password":"'
        + token
        + '","tokenid":"'
        + token
        + '"}'
    )
    redacted = redact_log_line(payload)
    assert psk not in redacted
    assert token not in redacted
    assert '"psk":"***"' in redacted
    assert '"password":"***"' in redacted
    assert '"tokenid":"***"' in redacted
    uid = "0123456789abcdef0123456789abcdef"
    identity = redact_log_line('{"username":"' + uid + '","eap_id":"' + uid + '"}')
    assert uid not in identity
    assert '"username":"***"' in identity
    assert '"eap_id":"***"' in identity
    spaced = redact_log_line(f"eap_id = {uid}")
    assert uid not in spaced
    assert "eap_id = ***" in spaced
    assert redact_log_line(f"tokenid={token}") == "tokenid=***"


def test_redact_preserves_split_include_and_ordinary_ike_lines() -> None:
    split = (
        "FortiClient compatibility: CFG_REPLY split-include "
        "count=7 prefixes=192.0.2.0/24,198.51.100.0/24,203.0.113.0/24,"
        "10.0.0.0/8,172.16.0.0/12,192.168.10.0/24,100.64.0.0/10 "
        "source=INTERNAL_IP4_SUBNET"
    )
    dns = "FortiClient compatibility: CFG_REPLY dns servers=192.0.2.53 domains=(none)"
    ike = "13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2"
    vip = "installing virtual IP 192.0.2.8"
    assert redact_log_line(split) == split
    assert redact_log_line(dns) == dns
    assert redact_log_line(ike) == ike
    assert redact_log_line(vip) == vip
    ordinary = "selecting traffic selectors for other: config: 0.0.0.0/0, received: 0.0.0.0/0"
    assert redact_log_line(ordinary) == ordinary


def test_saml_auth_url_strips_id_query_not_just_value() -> None:
    line = "INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?id=secret'"
    redacted = redact_log_line(line)
    assert redacted == ("INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start'")
    assert "secret" not in redacted
    assert "id=" not in redacted
