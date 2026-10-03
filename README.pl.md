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

Aktualna wersja to **1.5.0**. Wersja możliwości pomocnika to **0.9.0**
(`protocol_version` pozostaje **1**). Zachowanie protokołu VPN to zamrożony
backend v1.3.0 (jak w potwierdzonym live v1.4.0). v1.5.0 dodaje sprawdzanie
aktualizacji, wersje komponentów w About, automatyzację wydań i ścieżkę
publikacji APT.

## Funkcje

- Trwałe profile połączeń (tworzenie, edycja, duplikowanie, usuwanie, import, eksport, domyślny)
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
- Diagnostyka: DNS, routing, TCP, usługa SAML, tunel, pomocnik, IPsec, polkit
- Kopiowanie raportu diagnostycznego i eksport diagnostyki (ocenzurowany tekst lub ZIP do zgłoszenia)
- About: wersje komponentów i sprawdzenie aktualizacji z GitHub Releases (bez telemetrii; GUI samo się nie aktualizuje)

## Instalacja (Ubuntu 24.04)

Pełne instrukcje instalacji, aktualizacji, zaufania i rollback:
[`docs/pl/distribution.md`](docs/pl/distribution.md).

### A. Bezpośredni `.deb` z GitHub Releases

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.5.0-1_amd64.deb
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

### B. Repozytorium APT (nie jest live, dopóki pierwszy podpisany deployment nie zostanie zweryfikowany)

GitHub Pages jest skonfigurowane na GitHub Actions. Produkcyjna publikacja APT
jeszcze się nie odbyła. Po weryfikacji pierwszego podpisanego deploymentu
zamierzone polecenia to `sudo apt update` oraz
`sudo apt install fortigate-vpn-linux-gui`. Użyj osobnego keyringu i
`Signed-By`; nie używaj `apt-key add`.

To repozytorium APT **nie** jest tu deklarowane jako live. Do czasu
przetestowanego podpisanego deploymentu Pages stosuj metodę A. Zobacz
[`docs/pl/distribution.md`](docs/pl/distribution.md).

## Użytkowanie

1. Uruchom aplikację.
2. Otwórz **Profiles** → **New profile**.
3. Wybierz obsługiwany typ VPN:
   - **SSL VPN** (hasło albo SAML/SSO)
   - **IPsec IKEv1** (klucz wstępny + nazwa użytkownika/hasło)
   - **IPsec IKEv2 SAML/SSO** (klucz wstępny + logowanie w przeglądarce)
4. Wpisz bramę i wymagane ustawienia, potem zapisz. Hasła i klucz wstępny
   IPsec nigdy nie trafiają do `profiles.json`.
5. Połącz ze strony Profiles albo Connection. W razie potrzeby zatwierdź
   pomocnika w oknie polkit.
6. Przy SAML/SSO dokończ logowanie w przeglądarce.
7. Nieznany certyfikat FortiGate trzeba jawnie przypiąć do profilu SSL albo
   anulować.
8. Gdy połączenie nie działa, otwórz Diagnostykę, kliknij **Run diagnostics**,
   potem **Copy diagnostic report** albo **Export diagnostics**. Eksport jest
   ocenzurowany i nie może zawierać haseł, PSK, ciasteczek ani tokenów SAML.
   Sprawdź plik przed załączeniem.
9. Rozłącz ze strony Connection lub z zasobnika. Quit z zasobnika zawsze
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

**Export** zapisuje wersjonowany JSON aplikacji tylko z przenośnymi polami
bez sekretów. Nigdy nie zawiera klucza wstępnego IPsec, hasła, tokenid,
FCT UID, ciasteczek ani zawartości keyringa. **Import** sprawdza format i
typ VPN, nie przyjmuje haseł jawnym tekstem i nie zapisuje fragmentów
konfiguracji strongSwan ani openfortivpn. Duplikat i import dostają własną
tożsamość; zapisane sekrety nie są kopiowane. Przed połączeniem uzupełnij
wymagane sekrety.

Profile SSL, IKEv1 i IKEv2 SAML/SSO z v1.3.0 nadal się wczytują.

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
  v1.3.0 IKEv2 + SAML/SSO (Connect → Disconnect → Connect, trzy udane cykle).
  v1.4.0 zachowuje to zachowanie VPN i dodaje zarządzanie profilami w GUI.
  v1.5.0 nie zmienia zachowania protokołu VPN.
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
