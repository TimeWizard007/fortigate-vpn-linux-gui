# FortiGate VPN Linux GUI

Nowoczesny, natywny klient pulpitu Linux dla FortiGate SSL VPN, z
uwierzytelnianiem SAML/SSO przez Microsoft Entra ID w systemowej przeglądarce.

**Ten projekt jest niezależny i nie jest powiązany, wspierany ani sponsorowany
przez Fortinet.** Fortinet, FortiGate i FortiClient są znakami towarowymi
odpowiednich właścicieli.

## Status

Aktualna wersja to **0.6.0**. Trwałe profile, SAML/SSO przez `--saml-login`
i systemową przeglądarkę, pomocnik uprzywilejowany polkit oraz jawne
przypinanie certyfikatu FortiGate są zaimplementowane. Cykl życia połączenia,
oczekiwanie na zaufanie certyfikatu i utrata tunelu są utwardzone; GUI nadal
nie ponawia połączenia automatycznie.

| Funkcja | Status |
| ------- | ------ |
| Okno aplikacji i nawigacja | Zaimplementowane |
| Trwałe profile połączeń | Zaimplementowane |
| Cykl życia procesu openfortivpn | Zaimplementowany |
| Połączenie / rozłączenie (profile bez SSO) | Zaimplementowane |
| Logi (w pamięci, ocenzurowane) | Zaimplementowane |
| Wykrywanie openfortivpn w czasie działania | Zaimplementowane |
| SAML / SSO (Microsoft Entra ID, przeglądarka systemowa) | Zaimplementowane |
| Pomocnik uprzywilejowany / polkit | Zaimplementowany |
| Jawne przypinanie certyfikatu bramy | Zaimplementowane |

Profile SSO wysyłają strukturalne żądanie do minimalnego pomocnika
uprzywilejowanego. Pomocnik sam buduje
`[openfortivpn, brama:port, --saml-login]` (lista argumentów, `shell=False`)
wyłącznie ze ścieżek z listy dozwolonych. GUI pozostaje nieuprzywilejowane,
odbiera zweryfikowany URL SAML i otwiera go raz w systemowej przeglądarce.
FortiGate przekierowuje do Microsoft Entra ID. Lokalny listener callback
należy do openfortivpn; to GUI nie otwiera dodatkowego portu.

Pakiet Ubuntu 24.04 (`/usr/bin/openfortivpn` 1.21.0) może **nie** mieć
`--saml-login`. Do SSO potrzebna jest nowsza kompilacja, np. **openfortivpn
1.24.1** (`/usr/local/bin/openfortivpn`). Pomocnik odkrywa zatwierdzonych
kandydatów i wybiera binarium z SAML. Nie spada na niebezpieczne
uwierzytelnianie.

GUI nigdy nie działa jako root i nie używa sudo. Połączenie prosi polkit o
autoryzację pomocnika (`pkexec` uruchamia tylko pomocnika, nie GUI). Hasła,
tokeny SAML i SVPNCOOKIE nie są przechowywane i nie trafiają na linię poleceń.
Certyfikaty bramy nigdy nie są zaufane automatycznie.

## Profile połączeń

Profile są przechowywane per-użytkownik jako JSON UTF-8:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Typowa ścieżka na Ubuntu: `~/.config/fortigate-vpn-linux-gui/profiles.json`.

Każdy profil ma stały identyfikator, nazwę, bramę, port (domyślnie 443),
opcjonalny opis, opcjonalną podpowiedź nazwy użytkownika, flagę Use SSO
(domyślnie włączona) oraz opcjonalny pin `trusted_cert_sha256`. Pin to
odcisk SHA-256, nie sekret.

**Plik profili nie przechowuje haseł, tokenów SAML, ciasteczek, sekretów
klienta ani danych MFA.** Aplikacja nigdy nie zapisuje tych pól.

Dodawanie, edycja i usuwanie są na stronie Profiles. Selektor na stronie
Connection odświeża się od razu. Strony Settings i Diagnostics pokazują ścieżkę
pliku konfiguracyjnego tylko do odczytu.

## openfortivpn

`openfortivpn` jest rzeczywistą zależnością uruchomieniową dla łączności VPN.
GUI i tak startuje, gdy go brakuje; strona Connection wyjaśnia, że łączność
VPN jest niedostępna.

Na Ubuntu paczkowany klient bywa za stary dla SAML:

```bash
sudo apt install openfortivpn
```

To zwykle instaluje **1.21.0** w `/usr/bin/openfortivpn` bez `--saml-login`.
SSO wymaga kompilacji z `--saml-login` (przetestowano: **1.24.1** w
`/usr/local/bin/openfortivpn`). GUI wybierze binarium z SAML dla profilu SSO.

Aplikacja nigdy nie instaluje pakietów automatycznie. Nigdy nie uruchamia
`sudo` ani `apt`. Łączenie używa `pkexec` wyłącznie do startu pomocnika.

Ponieważ `openfortivpn` wymaga dodatkowych uprawnień do PPP, tras lub DNS,
działa przez pomocnika po zwykłym oknie uwierzytelniania Linux. Nie
uruchamiaj tego GUI jako root.

## Architektura (obecna)

```text
GUI                          Widżety PySide6 (nieuprzywilejowane)
  ↓ strukturalne żądanie
Pomocnik uprzywilejowany     root przez polkit (pkexec)
  ↓ kontrolowane argv
openfortivpn                 PPP / trasy / DNS
  ↓ zdarzenie URL SAML
Przeglądarka systemowa       nieuprzywilejowana sesja pulpitu
  ↓
FortiGate SSL VPN            brama
```

Pomocnik udostępnia tylko connect, disconnect i status. Sam buduje polecenie
openfortivpn. GUI nigdy nie wysyła ciągu powłoki ani dowolnej ścieżki
wykonywalnej.

Gdy walidacja certyfikatu FortiGate zawiedzie, GUI pokazuje okno pinowania.
Zaufanie zapisuje odcisk SHA-256 tylko w tym profilu. Późniejszy inny odcisk
to ostrzeżenie o zmianie certyfikatu i nigdy nie jest przyjmowany sam.

## Instalacja pomocnika (rozwój)

```bash
sudo install -D -m 0755 packaging/libexec/vpn-helper \
  /usr/libexec/fortigate-vpn-linux-gui/vpn-helper
sudo install -D -m 0644 packaging/polkit/com.fortigate-vpn-linux-gui.policy \
  /usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

Pomocnik musi importować `fortigate_vpn_gui`. Szczegóły:
[`packaging/README.md`](packaging/README.md).

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

do skopiowania i kończy działanie. Nigdy nie uruchamia `sudo` ani `apt` w
celu instalacji. `pkexec` jest później używany tylko do startu pomocnika VPN,
nigdy do uruchomienia tego GUI.

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
