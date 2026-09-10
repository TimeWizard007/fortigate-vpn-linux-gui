# Cel projektu

FortiGate VPN Linux GUI ma być utrzymywalnym, natywnym klientem pulpitu Linux
dla FortiGate SSL VPN.

Użytkownicy FortiGate SSL VPN na Linuxie często korzystają z oficjalnego
FortiClient, sesji `openfortivpn` z linii poleceń albo opakowań dystrybucji.
Ten projekt ma dać jasne, nowoczesne GUI, które:

- pasuje do pulpitu Linux (najpierw Ubuntu)
- trzyma uprawnienia poza procesem GUI (pomocnik polkit)
- używa SAML/SSO z Microsoft Entra ID przez systemową przeglądarkę
- pozostaje niezależne od Fortinet

Aplikacja używa [openfortivpn](https://github.com/adrienverge/openfortivpn)
jako zaplecza VPN. v0.6.x nadal uruchamia go przez minimalny pomocnik
uprzywilejowany. GUI pozostaje nieuprzywilejowane, otwiera systemową
przeglądarkę dla SAML i nie ponawia połączenia automatycznie po utracie tunelu.

Ten projekt **nie** jest powiązany, wspierany ani sponsorowany przez Fortinet.
Fortinet, FortiGate i FortiClient są znakami towarowymi odpowiednich
właścicieli.
