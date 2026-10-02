# FortiGate VPN Linux GUI

Natywny klient pulpitu Linux dla FortiGate SSL VPN i IPsec. SAML/SSO używa
systemowej przeglądarki (na przykład Microsoft Entra ID przez FortiGate).
GUI nigdy nie działa jako root.

**Ten projekt jest niezależny i nie jest powiązany, wspierany ani sponsorowany
przez Fortinet.** Fortinet, FortiGate i FortiClient są znakami towarowymi
odpowiednich właścicieli.

## Wspierana platforma

Główny cel wydania: **Ubuntu 24.04 LTS, amd64**. Inne dystrybucje z rodziny
Debian nie były testowane.

Aktualna wersja to **1.3.0**. Wersja możliwości pomocnika to **0.9.0**
(`protocol_version` pozostaje **1**).

## Funkcje

- Trwałe profile połączeń (tworzenie, edycja, duplikowanie, usuwanie, domyślny)
- Łączenie ze strony Profiles lub Connection
- SAML/SSO przez `openfortivpn --saml-login` i systemową przeglądarkę
- Profile SSL z hasłem, gdy SSO nie jest używane
- IPsec przez dystrybucyjny strongSwan (nie dołączany do paczki):
  - IKEv1 Aggressive Mode, PSK, XAuth, Mode Config, NAT-T, FortiGate/Cisco Unity split include
  - IKEv2 + SAML/SSO z kompatybilnym EAP-MSCHAPv2 FortiClient, negocjowanym split-tunnel i split DNS
- Jawne przypinanie certyfikatu FortiGate dla SSL (nigdy automatycznie)
- Pomocnik uprzywilejowany przez polkit (`pkexec` uruchamia tylko pomocnika)
- Opcjonalny zapis PSK IPsec i hasła XAuth w Secret Service (nigdy w
  `profiles.json`; bez zapisu jawnego)
- Zasobnik systemowy, opcjonalne zamykanie do zasobnika, opcjonalny autostart
- Opcjonalne ponawianie po nieoczekiwanej utracie tunelu (domyślnie wyłączone)
- Diagnostyka: DNS, routing, TCP, tunel, pomocnik, IPsec, polkit
- Kopiowanie i eksport diagnostyki (ocenzurowany tekst lub ZIP do zgłoszenia)

## Instalacja (Ubuntu 24.04)

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.3.0-1_amd64.deb
```

`apt` dociąga biblioteki runtime, `pkexec`, `ppp`, `iproute2` oraz pakiety
strongSwan używane do IPsec. Środowisko wirtualne Pythona nie jest potrzebne.
Paczka zawiera prywatny `openfortivpn` **1.24.1** z obsługą SAML i nie
zastępuje `/usr/bin/openfortivpn`. Zależności Pythona, w tym `keyring`, są w
prywatnym venv paczki. Po instalacji `.deb` nie uruchamiaj `pip install`.

Uruchom z menu GNOME jako **FortiGate VPN Linux GUI** albo:

```bash
fortigate-vpn-linux-gui
```

Nie uruchamiaj GUI jako root. Przy łączeniu może pojawić się standardowe
okno polkit. SSO kończy się w systemowej przeglądarce.

### openfortivpn i SAML

SAML/SSO wymaga `openfortivpn --saml-login`. Paczka Ubuntu 24.04
`openfortivpn` to **1.21.0** i **nie** ma tej opcji. Nasza paczka instaluje
własny **1.24.1** w
`/usr/libexec/fortigate-vpn-linux-gui/openfortivpn`. Pomocnik preferuje to
binarium, potem `/usr/local/bin/openfortivpn`, potem `/usr/bin/openfortivpn`.
Diagnostyka zgłasza to samo skuteczne binarium. Profile z hasłem mogą użyć
kompilacji bez SAML, jeśli to jedyne zatwierdzone binarium.

### Usuwanie

```bash
sudo apt remove fortigate-vpn-linux-gui
```

Profile użytkownika w `~/.config/fortigate-vpn-linux-gui/` zostają.
`apt purge` też ich nie kasuje; usuń je ręcznie, jeśli chcesz.

## Użytkowanie

1. Uruchom aplikację.
2. Dodaj profil (brama, port, SAML/SSO albo nazwa użytkownika/hasło).
3. Połącz. W razie potrzeby zatwierdź pomocnika w oknie polkit.
4. Przy SSO dokończ logowanie w przeglądarce.
5. Nieznany certyfikat FortiGate trzeba jawnie przypiąć do profilu albo
   anulować.
6. Gdy połączenie nie działa, otwórz Diagnostykę, kliknij **Uruchom
   diagnostykę**, potem **Kopiuj diagnostykę** albo **Eksportuj diagnostykę**.
   Eksport jest ocenzurowany i nie może zawierać haseł, PSK, ciasteczek ani
   tokenów SAML. Sprawdź plik przed załączeniem.
7. Rozłącz ze strony Connection lub z zasobnika. Quit z zasobnika zawsze
   kończy aplikację (czeka na sprzątnięcie pomocnika/openfortivpn).

Zamknięcie okna domyślnie kończy program. W ustawieniach można zmienić to na
minimalizację do zasobnika. Autostart tylko uruchamia GUI po zalogowaniu; nie
łączy VPN.

## Profile

Profile są w JSON-ie użytkownika:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Plik nie przechowuje haseł, tokenów SAML, ciasteczek ani innych sekretów.
`trusted_cert_sha256` to publiczny pin certyfikatu.

## Model bezpieczeństwa

```text
GUI                          widżety PySide6 (bez uprawnień root)
  ↓ ustrukturyzowane żądanie
Pomocnik uprzywilejowany     root przez polkit (pkexec)
  ├── openfortivpn           SSL VPN (SAML albo użytkownik/hasło)
  └── strongSwan charon      IPsec (pakiety dystrybucji; nie w paczce)
```

`pkexec` uruchamia tylko `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`.
Nie ma reguł sudoers, setuid pomocnika ani polityki polkit bez hasła.
Hasła SSL, ciasteczka SAML, PSK IPsec i hasła XAuth nie są zapisywane w
`profiles.json` i nie trafiają do linii poleceń. Opcjonalne sekrety IPsec
używają Secret Service tylko po zgodzie użytkownika. Kopiowane i eksportowane
raporty diagnostyczne są ocenzurowane.

## Obsługiwane typy połączeń

**SSL-VPN** (openfortivpn): hasło albo SAML/SSO w przeglądarce, z jawnym
pinowaniem certyfikatu.

**IPsec** (dystrybucyjny strongSwan): IKEv1 Aggressive Mode, PSK + XAuth,
Mode Config / VIP, NAT-T, CHILD_SA/XFRM, FortiGate/Cisco Unity split include
oraz DNS VPN; oraz IKEv2 + SAML/SSO z kompatybilnym EAP-MSCHAPv2 FortiClient,
negocjowanym split-tunnel `INTERNAL_IP4_SUBNET` i split DNS. Main Mode,
certyfikat IPsec i adresacja ręczna mogą być zapisane w profilu, ale nie są
uruchamiane.

IPsec aplikacji używa **prywatnego** charon (`/run/charon.fvl.conf` i
`/run/charon.fvl.vici`). Nie zatrzymuje `strongswan-starter`, nie zabija
obcego charon i nie przejmuje `/run/charon.vici`. Dwa demony IKE nie mogą
jednocześnie zająć UDP/500 i UDP/4500. Gdy inna usługa IKE już ma te porty,
IPsec kończy się przed załadowaniem sekretów komunikatem **IKE ports in use**;
Diagnostyka pokazuje zajętość. SSL VPN działa przy działającym systemowym
strongSwan. Paczka nigdy nie wyłącza systemowego strongSwan automatycznie.

### Przetestowane

- Ubuntu 24.04 LTS amd64
- Środowisko FortiGate / FortiOS użyte do walidacji SSL, IPsec IKEv1 oraz
  v1.3.0 IKEv2 + SAML/SSO (Connect → Disconnect → Connect, trzy udane cykle)
- Test zainstalowanej paczki v1.2.0: odmowa IPsec gdy systemowy charon miał
  UDP/500/4500; prywatny IPsec po zatrzymaniu tego IKE; SSL/SAML po sprzątaniu
  IPsec z przywróconym systemowym strongSwan

### Potencjalnie zgodne, jeszcze nie testowane

- Inne pulpity z rodziny Debian amd64
- Inne wersje FortiGate / FortiOS i propozycje IPsec

## Rozwiązywanie problemów

Najpierw otwórz **Diagnostykę**. Sprawdza instalację pomocnika/polkit, DNS,
trasę do bramy, TCP, pozostałości IPsec i stan tunelu. Samo otwarcie
Diagnostyki nie pokazuje okna polkit.

Gdy połączenie nie działa, strona Connection pokazuje ostrożny, czytelny
powód, jeśli wyjście backendu go udowadnia. Szczegóły zostają w Logs i
Diagnostyce.

**Eksportuj diagnostykę** zapisuje ocenzurowany tekst lub ZIP do zgłoszenia
GitHub. **Kopiuj diagnostykę** wkleja ten sam tekst. Sprawdź plik przed
załączeniem: nie może zawierać PSK, haseł, ciasteczek, tokenów SAML ani
kluczy prywatnych.

Gdy IPsec zgłasza **IKE ports in use**, inny demon IKE (często
`strongswan-starter` / systemowy charon) już zajmuje UDP/500 lub UDP/4500.
Aplikacja nie zatrzymuje tej usługi. SSL VPN nadal może się połączyć.
IPsec aplikacji ruszy dopiero, gdy te porty będą wolne.

Gdy SSO nie działa, sprawdź, czy używany `openfortivpn` obsługuje `--saml-login`.

## Rozwój

Środowisko deweloperskie jest oddzielne od zainstalowanej aplikacji.
Polecenie `fortigate-vpn-linux-gui` nie może wymagać tego repozytorium ani
`.venv`.

```bash
sudo apt install python3.12-venv libxcb-cursor0
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m fortigate_vpn_gui
```

```bash
ruff check src tests
python -m pytest
./scripts/build-deb.sh
```

Instalacja pomocnika na czas rozwoju (niepotrzebna po instalacji `.deb`):
[`packaging/README.md`](packaging/README.md).

## Dokumentacja

- Angielski: [`docs/en/`](docs/en/)
- Polski: [`docs/pl/`](docs/pl/) oraz [`README.pl.md`](README.pl.md)
- Bezpieczeństwo: [`SECURITY.md`](SECURITY.md)
- Współpraca: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Dziennik zmian: [`CHANGELOG.md`](CHANGELOG.md)

## Licencja

GNU General Public License v3.0 lub nowsza. Zobacz [`LICENSE`](LICENSE).
