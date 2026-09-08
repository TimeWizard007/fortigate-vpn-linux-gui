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

Aplikacja używa [openfortivpn](https://github.com/adrienverge/openfortivpn)
jako zaplecza VPN. v0.3.x uruchamia go jako bieżący użytkownik. SAML/SSO i
pomocnik uprzywilejowany **nie** wchodzą w zakres tej wersji.

Wersja v0.3.x dodaje cykl życia procesu, Connect/Disconnect, ocenzurowane
logi i wykrywanie openfortivpn na fundamencie trwałych profili. Nadal nie
jest to kompletny klient VPN.

Ten projekt **nie** jest powiązany, wspierany ani sponsorowany przez Fortinet.
Fortinet, FortiGate i FortiClient są znakami towarowymi odpowiednich
właścicieli.
