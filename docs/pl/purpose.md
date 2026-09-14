# Cel projektu

FortiGate VPN Linux GUI ma być utrzymywalnym, natywnym klientem pulpitu Linux
dla FortiGate SSL VPN i IPsec.

Użytkownicy FortiGate SSL VPN na Linuxie często korzystają z oficjalnego
FortiClient, sesji `openfortivpn` z linii poleceń albo opakowań dystrybucji.
Ten projekt ma dać jasne, nowoczesne GUI, które:

- pasuje do pulpitu Linux (najpierw Ubuntu)
- trzyma uprawnienia poza procesem GUI (pomocnik polkit)
- używa SAML/SSO z Microsoft Entra ID przez systemową przeglądarkę
- pozostaje niezależne od Fortinet

Aplikacja używa [openfortivpn](https://github.com/adrienverge/openfortivpn)
dla SSL VPN i dystrybucyjnego strongSwan dla IPsec. Oba uruchamia minimalny
pomocnik uprzywilejowany (protokół 0.8.0 w v1.1.0). GUI pozostaje
nieuprzywilejowane. SSL SAML otwiera systemową przeglądarkę. Opcjonalne
ponawianie po utracie tunelu jest domyślnie wyłączone i nigdy nie pomija
zatwierdzenia certyfikatu ani SAML.

Ten projekt **nie** jest powiązany, wspierany ani sponsorowany przez Fortinet.
Fortinet, FortiGate i FortiClient są znakami towarowymi odpowiednich
właścicieli.
