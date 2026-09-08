# FortiGate VPN Linux GUI

Nowoczesny, natywny klient pulpitu Linux dla FortiGate SSL VPN, z planowanym
wsparciem uwierzytelniania SAML/SSO przez Microsoft Entra ID.

**Ten projekt jest niezależny i nie jest powiązany, wspierany ani sponsorowany
przez Fortinet.** Fortinet, FortiGate i FortiClient są znakami towarowymi
odpowiednich właścicieli.

## Status

Aktualna wersja to **0.3.0**. Trwałe profile oraz nieuprzywilejowane zaplecze
procesu `openfortivpn` są zaimplementowane. SAML/SSO i pomocnik
uprzywilejowany/polkit **nie**.

| Funkcja | Status |
| ------- | ------ |
| Okno aplikacji i nawigacja | Zaimplementowane |
| Trwałe profile połączeń | Zaimplementowane |
| Cykl życia procesu openfortivpn | Zaimplementowany |
| Połączenie / rozłączenie (profile bez SSO) | Zaimplementowane |
| Logi (w pamięci, ocenzurowane) | Zaimplementowane |
| Wykrywanie openfortivpn w czasie działania | Zaimplementowane |
| SAML / SSO (Microsoft Entra ID) | **Niezaimplementowane** |
| Pomocnik uprzywilejowany / polkit | **Niezaimplementowany** |

Profile bez SSO uruchamiają `openfortivpn <brama>:<port>` jako bieżący
użytkownik. Hasła nie są przechowywane, więc uwierzytelnianie może się nie
powieść. W v0.3.0 to oczekiwane: celem jest cykl życia procesu, a nie pełny
przepływ logowania.

Profile SSO **nie** uruchamiają VPN. GUI pokazuje:
`SAML/SSO connection support is planned for v0.4.0.`

GUI nigdy nie otwiera przeglądarki i nigdy nie działa jako root.

## Profile połączeń

Profile są przechowywane per-użytkownik jako JSON UTF-8:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Typowa ścieżka na Ubuntu: `~/.config/fortigate-vpn-linux-gui/profiles.json`.

Każdy profil ma stały identyfikator, nazwę, bramę, port (domyślnie 443),
opcjonalny opis, opcjonalną podpowiedź nazwy użytkownika oraz flagę Use SSO
(domyślnie włączona).

**Plik profili nie przechowuje haseł, tokenów SAML, ciasteczek, sekretów
klienta ani danych MFA.** Aplikacja nigdy nie zapisuje tych pól.

Dodawanie, edycja i usuwanie są na stronie Profiles. Selektor na stronie
Connection odświeża się od razu. Strony Settings i Diagnostics pokazują ścieżkę
pliku konfiguracyjnego tylko do odczytu.

## openfortivpn

`openfortivpn` jest rzeczywistą zależnością uruchomieniową dla łączności VPN.
GUI i tak startuje, gdy go brakuje; strona Connection wyjaśnia, że łączność
VPN jest niedostępna.

Na Ubuntu:

```bash
sudo apt install openfortivpn
```

Aplikacja nigdy nie instaluje pakietów automatycznie. Nigdy nie uruchamia
`sudo`, `pkexec` ani `apt`.

Ponieważ `openfortivpn` może wymagać dodatkowych uprawnień do PPP, tras lub
DNS, błąd uprawnień jest zgłaszany wprost. Wsparcie pomocnika/polkit jest
planowane na późniejszą wersję. Nie uruchamiaj tego GUI jako root, żeby to
obejść.

## Architektura (obecna)

```text
GUI                          Widżety PySide6 (nieuprzywilejowane)
  ↓
Warstwa aplikacji / usług    VpnBackend, profile, ocenzurowane logi
  ↓
openfortivpn                 uruchamiany jako bieżący użytkownik
  ↓
FortiGate SSL VPN            brama
```

W późniejszej wersji między warstwą usług a `openfortivpn` pojawi się
pomocnik uprzywilejowany. Uwierzytelnianie SAML ma korzystać z systemowej
przeglądarki i Microsoft Entra ID; ta ścieżka nie jest jeszcze
zaimplementowana.

## Wymagania

- Linux (Ubuntu jest główną wspieraną dystrybucją)
- Python 3.10 lub nowszy
- Qt 6 przez PySide6
- Sesja pulpitu (X11 lub Wayland)
- `openfortivpn`, aby faktycznie uruchomić tunel (opcjonalny do startu GUI)

Na Ubuntu 24.04 z Pythonem 3.12 zainstaluj pakiety środowiska wirtualnego
i bibliotekę Qt przed utworzeniem venv:

```bash
sudo apt install python3.12-venv libxcb-cursor0
```

Nazwa pakietu `python3.x-venv` zależy od zainstalowanej wersji Pythona
(`python3.12-venv` na Ubuntu 24.04, `python3.10-venv` na Ubuntu 22.04 z
domyślnym Pythonem). `python3-venv` to metapakiet, który wciąga właściwą
wersję.

`libxcb-cursor0` dostarcza `libxcb-cursor.so.0`. PySide6/Qt potrzebuje tej
biblioteki do tworzenia okien. Aplikacja **nie** instaluje tego pakietu
(ani żadnego innego pakietu systemowego) automatycznie. Przy starcie sprawdza,
czy bibliotekę da się załadować; jeśli jej brakuje, pokazuje okno z komendą

`sudo apt install libxcb-cursor0`

do skopiowania i kończy działanie. Nigdy nie uruchamia `sudo`, `pkexec` ani
`apt`.

## Środowisko deweloperskie

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Uruchomienie aplikacji (nigdy jako root):

```bash
python -m fortigate_vpn_gui
```

Lint i testy:

```bash
ruff check src tests
ruff format src tests
python -m pytest
```

## Dokumentacja

- Angielski: [`docs/en/`](docs/en/)
- Polski: [`docs/pl/`](docs/pl/) oraz [`README.pl.md`](README.pl.md)
- Bezpieczeństwo: [`SECURITY.md`](SECURITY.md)
- Współpraca: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Dziennik zmian: [`CHANGELOG.md`](CHANGELOG.md)

## Licencja

GNU General Public License v3.0 lub nowsza. Zobacz [`LICENSE`](LICENSE).
