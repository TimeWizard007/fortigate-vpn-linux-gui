# FortiGate VPN Linux GUI

Nowoczesny, natywny klient pulpitu Linux dla FortiGate SSL VPN, z planowanym
wsparciem uwierzytelniania SAML/SSO przez Microsoft Entra ID.

**Ten projekt jest niezależny i nie jest powiązany, wspierany ani sponsorowany
przez Fortinet.** Fortinet, FortiGate i FortiClient są znakami towarowymi
odpowiednich właścicieli.

## Status

Aktualna wersja to **0.1.0** (wyłącznie fundament projektu).

| Funkcja | Status |
| ------- | ------ |
| Okno aplikacji i nawigacja | Zaimplementowane (interfejs zastępczy) |
| Połączenie / rozłączenie VPN | **Niezaimplementowane** |
| SAML / SSO (Microsoft Entra ID) | **Niezaimplementowane** |
| Integracja z openfortivpn | **Niezaimplementowana** |
| Pomocnik uprzywilejowany / polkit | **Niezaimplementowany** |

Przycisk **Connect with SSO** jest zastępczy. Nie otwiera przeglądarki, nie
uwierzytelnia i nie zmienia konfiguracji sieci.

## Zamierzona architektura (planowana)

Uwierzytelnianie SAML ma korzystać z systemowej przeglądarki użytkownika oraz
Microsoft Entra ID. Poniższy stos jest celem projektowym; **żadna warstwa
poniżej GUI jeszcze nie istnieje**:

```text
GUI
  ↓
Warstwa aplikacji / usług
  ↓
Pomocnik uprzywilejowany
  ↓
openfortivpn
  ↓
FortiGate SSL VPN
```

GUI pozostanie nieuprzywilejowane. Operacje wymagające uprawnień (uruchomienie
procesu VPN, trasy, DNS) przejdą przez minimalny pomocnik, a nie przez `sudo`
z aplikacji pulpitu.

## Wymagania

- Linux (Ubuntu jest główną wspieraną dystrybucją)
- Python 3.10 lub nowszy
- Qt 6 przez PySide6
- Sesja pulpitu (X11 lub Wayland)

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

`openfortivpn` **nie** jest wymagany w wersji v0.1.x.

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
