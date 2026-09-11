# FortiGate VPN Linux GUI

Natywny klient pulpitu Linux dla FortiGate SSL VPN. SAML/SSO używa
systemowej przeglądarki (na przykład Microsoft Entra ID przez FortiGate).
GUI nigdy nie działa jako root.

**Ten projekt jest niezależny i nie jest powiązany, wspierany ani sponsorowany
przez Fortinet.** Fortinet, FortiGate i FortiClient są znakami towarowymi
odpowiednich właścicieli.

## Wspierana platforma

Główny cel wydania: **Ubuntu 24.04 LTS, amd64**. Inne dystrybucje z rodziny
Debian nie były testowane.

Aktualna wersja to **1.0.0**. Protokół pomocnika pozostaje **0.7.0**.

## Funkcje

- Trwałe profile połączeń (tworzenie, edycja, duplikowanie, usuwanie, domyślny)
- Łączenie ze strony Profiles lub Connection
- SAML/SSO przez `openfortivpn --saml-login` i systemową przeglądarkę
- Profile z hasłem, gdy SSO nie jest używane
- Jawne przypinanie certyfikatu FortiGate (nigdy automatycznie)
- Pomocnik uprzywilejowany przez polkit (`pkexec` uruchamia tylko pomocnika)
- Zasobnik systemowy, opcjonalne zamykanie do zasobnika, opcjonalny autostart
- Opcjonalne ponawianie po nieoczekiwanej utracie tunelu (domyślnie wyłączone)
- Diagnostyka: DNS, routing, TCP, tunel, pomocnik, polkit
- Kopiowalny, ocenzurowany raport diagnostyczny

## Instalacja (Ubuntu 24.04)

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.0.0-2_amd64.deb
```

`apt` dociąga biblioteki runtime, `pkexec`, `ppp` i `iproute2`. Środowisko
wirtualne Pythona nie jest potrzebne. Paczka zawiera prywatny `openfortivpn`
**1.24.1** z obsługą SAML i nie zastępuje `/usr/bin/openfortivpn`.

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
   diagnostykę**, potem **Kopiuj raport**.
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
  ↓ kontrolowane argv
openfortivpn                 PPP / trasy / DNS
  ↓ zdarzenie URL SAML
Przeglądarka systemowa       sesja użytkownika pulpitu
```

`pkexec` uruchamia tylko `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`.
Nie ma reguł sudoers, setuid pomocnika ani polityki polkit bez hasła.
Hasła i ciasteczka SAML nie są zapisywane i nie trafiają do linii poleceń.
Kopiowane raporty diagnostyczne są ocenzurowane.

## Rozwiązywanie problemów

Najpierw otwórz **Diagnostykę**. Sprawdza instalację pomocnika/polkit, DNS,
trasę do bramy, TCP i stan tunelu. Samo otwarcie Diagnostyki nie pokazuje
okna polkit.

Gdy SSO nie działa, sprawdź, czy `openfortivpn --help` zawiera `--saml-login`.

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
