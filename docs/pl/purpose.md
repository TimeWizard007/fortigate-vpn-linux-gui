# Cel projektu

FortiGate VPN Linux GUI ma być utrzymywalnym, natywnym klientem pulpitu Linux
dla FortiGate SSL VPN.

Użytkownicy FortiGate SSL VPN na Linuksie często korzystają z oficjalnego
FortiClient, sesji `openfortivpn` w terminalu albo opakowań specyficznych dla
dystrybucji. Ten projekt ma dostarczyć przejrzysty, nowoczesny interfejs, który:

- pasuje do pulpitu Linux (w pierwszej kolejności Ubuntu)
- trzyma operacje uprzywilejowane poza procesem GUI
- planuje SAML/SSO z Microsoft Entra ID przez systemową przeglądarkę
- pozostaje niezależny od Fortinet

Aplikacja będzie w przyszłości używać [openfortivpn](https://github.com/adrienverge/openfortivpn)
jako zaplecza VPN. Ta integracja **nie** wchodzi w zakres v0.2.x.

Wersja v0.2.x dodaje trwałe profile połączeń per-użytkownik na fundamencie GUI.
Nadal nie jest to działający klient VPN.

Ten projekt **nie** jest powiązany, wspierany ani sponsorowany przez Fortinet.
Fortinet, FortiGate i FortiClient są znakami towarowymi odpowiednich
właścicieli.
