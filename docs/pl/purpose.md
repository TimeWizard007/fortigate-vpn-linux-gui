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
jako zaplecza VPN. Ta integracja **nie** wchodzi w zakres v0.1.x.

Wersja v0.1.x dostarcza strukturę repozytorium, pakietowanie, powłokę GUI bez
łączenia z VPN, dokumentację po angielsku i polsku, testy oraz CI. To punkt
wyjścia dla poważnej aplikacji open source, a nie działający klient VPN.

Ten projekt **nie** jest powiązany, wspierany ani sponsorowany przez Fortinet.
Fortinet, FortiGate i FortiClient są znakami towarowymi odpowiednich
właścicieli.
