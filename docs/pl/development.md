# Środowisko deweloperskie

Ubuntu jest główną wspieraną dystrybucją. Wymagany jest Python 3.10+.
GUI zostało zweryfikowane na Ubuntu 24.04 z Pythonem 3.12.

## Wymagania uruchomieniowe Ubuntu

Zainstaluj je **zanim** utworzysz wirtualne środowisko lub uruchomisz GUI.

Na Ubuntu 24.04 / Python 3.12:

```bash
sudo apt install python3.12-venv libxcb-cursor0
```

- `python3.12-venv` — moduł `venv` dla tej wersji Pythona. Dokładna nazwa
  pakietu `python3.x-venv` zależy od zainstalowanego Pythona. Domyślny
  interpreter Ubuntu 22.04 wymaga `python3.10-venv`. `python3-venv` to
  metapakiet, który wciąga właściwą wersję.
- `libxcb-cursor0` — dostarcza `libxcb-cursor.so.0`. PySide6/Qt 6 potrzebuje
  tej biblioteki do tworzenia okien. Bez niej wtyczka platformy Qt xcb nie
  wczyta się.

W wersji v0.2.x **nie** potrzebujesz `openfortivpn`.

Aplikacja **nie** instaluje pakietów systemowych automatycznie. Nigdy nie
uruchamia `sudo`, `pkexec` ani `apt`. Te polecenia są podane do ręcznego
wykonania.

## Przechowywanie profili

Profile połączeń to JSON UTF-8 per-użytkownik:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Gdy `XDG_CONFIG_HOME` nie jest ustawione, plik to
`~/.config/fortigate-vpn-linux-gui/profiles.json`.

Katalog powstaje dopiero przy zapisie. Zapis jest atomowy (plik tymczasowy +
replace). Uszkodzony JSON jest traktowany jako pusta lista i nie powoduje
awarii GUI.

Pola: `id`, `name`, `gateway`, `port`, `description`, `username_hint`,
`use_sso`. Hasła, tokeny SAML, ciasteczka i inne sekrety nigdy nie są
zapisywane.

Pytest ustawia tymczasowe `XDG_CONFIG_HOME`, więc testy nie ruszają prawdziwego
`~/.config`.

## Sprawdzenie zależności przy starcie

Zanim powstanie okno główne, proces:

1. Rozpoznaje dystrybucję z `/etc/os-release`, jeśli plik istnieje.
2. Sprawdza, czy da się załadować `libxcb-cursor.so.0` (dynamiczny linker),
   a nie to, czy `dpkg` zgłasza pakiet.
3. Jeśli biblioteki brakuje, wypisuje wyjaśnienie na stderr i pokazuje okno
   Qt z nazwą zależności, powodem oraz zaufaną komendą Ubuntu
   `sudo apt install libxcb-cursor0`.
4. Oferuje **Copy command** i **Exit**. Komenda nigdy nie jest uruchamiana.

Ten sam mechanizm jest przygotowany na późniejsze etapy (`openfortivpn`,
`ppp`, polkit, przeglądarka systemowa), które dziś nie są wymagane.

## Wirtualne środowisko

Z katalogu głównego repozytorium:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Uruchomienie aplikacji

```bash
python -m fortigate_vpn_gui
```

Nie uruchamiaj tego jako root. Proces kończy się błędem, gdy efektywny UID
wynosi 0.

## Lint

```bash
ruff check src tests
ruff format src tests
```

## Testy

```bash
python -m pytest
```

Testy widżetów ustawiają `QT_QPA_PLATFORM=offscreen` i nie korzystają z sieci.
Ta sama zmienna środowiskowa jest używana w GitHub Actions. Testy preflight
wstrzykują fałszywe sondy bibliotek/plików wykonywalnych i nigdy nie wołają
apt ani sudo.

## Układ projektu

```text
src/fortigate_vpn_gui/   pakiet aplikacji
tests/                   zestaw pytest
docs/en/                 dokumentacja angielska
docs/pl/                 dokumentacja polska
assets/                  przyszłe ikony i identyfikacja wizualna
packaging/               przyszłe pakietowanie dystrybucyjne
scripts/                 przyszłe skrypty utrzymaniowe
.github/workflows/       CI
```
