# Architektura

Projekt oddziela interfejs pulpitu od sterowania procesem VPN i od uprawnień.

```text
GUI                          Widżety PySide6 (nieuprzywilejowane)
  ↓ strukturalne żądanie JSON
Pomocnik uprzywilejowany     root przez polkit (pkexec)
  ├── openfortivpn           FortiGate SSL VPN (SAML lub użytkownik/hasło)
  └── strongSwan charon      FortiGate IPsec (pakiety dystrybucji; nie w paczce)
```

GUI nigdy nie może stać się pomocnikiem i nigdy nie może działać jako root.
`pkexec` uruchamia tylko `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`.
Aplikacja pulpitu nie jest uruchamiana przez pkexec ani sudo.

## Warstwy

### GUI

Widżety Qt w `src/fortigate_vpn_gui/gui/`. GUI pokazuje stan i zbiera intencje
użytkownika. Nie może działać jako root, wywoływać `sudo` ani zmieniać tras,
DNS albo reguł zapory. Connect/Disconnect woła `VpnBackend`.

Gdy certyfikatu bramy nie da się zweryfikować, strona Connection pokazuje
jawne okno pinowania. Przeglądarka systemowa otwiera się w sesji
nieuprzywilejowanej po zweryfikowanym zdarzeniu URL SAML.

### Warstwa aplikacji / usług

Pakiety bez Qt (`vpn`, `profiles`, `helper`, `diagnostics`).

`fortigate_vpn_gui.vpn` trzyma stan po stronie GUI. `fortigate_vpn_gui.helper`
właściwie uruchamia openfortivpn.

| Moduł | Rola |
| ----- | ---- |
| `vpn/backend.py` | `connect`, `disconnect`, timeout/cancel SAML, migawki |
| `system/helper_client.py` | Nieuprzywilejowany klient JSON-lines; pkexec |
| `helper/service.py` | Connect/disconnect/status; właściciel grupy procesów |
| `helper/validation.py` | Brama, port, odcisk, operacja |
| `vpn/command.py` | Lista `[openfortivpn, brama:port]` i opcjonalne flagi |
| `helper/executables.py` | `/usr/libexec/.../openfortivpn`, `/usr/local/bin`, `/usr/bin` |
| `vpn/browser.py` | `xdg-open` po walidacji URL |
| `helper/certificate.py` | Metadane nieudanej walidacji certyfikatu |
| `vpn/log_redaction.py` | Hasła, ciasteczka, SAMLResponse, tokeny |

### Pomocnik uprzywilejowany

Mały pomocnik z akcją polkit `com.fortigate-vpn-linux-gui.manage-vpn`. To nie
jest ogólny executor poleceń. Operacje: `hello`, `connect`, `credentials`,
`disconnect`, `status`.

Lokalizacje instalacji:

```text
/usr/libexec/fortigate-vpn-linux-gui/vpn-helper
/usr/libexec/fortigate-vpn-linux-gui/openfortivpn
/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

Pomocnik ponownie waliduje każde pole, wybiera zatwierdzone binarium
openfortivpn i sam buduje argv. Nie przyjmuje ciągu polecenia, listy argv ani
ścieżki wykonywalnej z GUI.

### openfortivpn

Bez SSO: `openfortivpn <brama>:<port>`. SSO:
`openfortivpn <brama>:<port> --saml-login`. Z pinem:
`--trusted-cert <sha256>` jako osobny argument. Walidacja TLS nigdy nie jest
wyłączana.

Kandydaci pomocnika, w kolejności:
`/usr/libexec/fortigate-vpn-linux-gui/openfortivpn`,
`/usr/local/bin/openfortivpn`, `/usr/bin/openfortivpn`.
Zdolności z `--help`. Paczka Ubuntu 24.04 (**1.21.0**) nie ma SAML; nasza
paczka dostarcza prywatny **1.24.1**.

### IPsec / strongSwan

IPsec to drugi backend pomocnika. GUI nie uruchamia charon ani swanctl.
Prywatny charon dostaje wygenerowany `strongswan.conf` przez `STRONGSWAN_CONF`
(Ubuntu charon nie przyjmuje `--conf`; AppArmor czyta ten plik z
`/run/charon.fvl.conf`, gniazdo vici to `/run/charon.vici`). Ubuntu 5.9.13
`swanctl` nie ma `--unix`; ładuje
`/etc/swanctl/fortigate-vpn-linux-gui/swanctl.conf` przez `--load-all --file`
i łączy się z domyślnym gniazdem VICI `/run/charon.vici`. strongSwan pochodzi
z dystrybucji (`Depends`: `strongswan`, `strongswan-swanctl`,
`libcharon-extra-plugins`, `libcharon-extauth-plugins`) i nie jest
dołączany do paczki. `/etc/strongswan.conf` nie jest zmieniany. v1.1.0 łączy
IKEv1 Aggressive + PSK + XAuth + Mode Config + NAT-T z FortiGate/Cisco Unity
split include. Sekrety idą
osobną operacją `credentials` i plikiem 0600, nigdy przez argv. PSK i hasło
XAuth mogą być zapisane w Secret Service tylko po zgodzie użytkownika; nigdy
w `profiles.json`. DNS VPN jest nakładką tymczasową: pomocnik zapisuje stan
przed VPN, nakłada DNS FortiGate i `~.`, a przy Disconnect przywraca migawkę
i woła `nmcli device reapply`. Nie używa `resolvectl revert` na łączu
zarządzanym przez NetworkManager.

## Stany połączenia

Tylko jedna próba połączenia na instancję GUI. Ponowny Connect w trakcie
zajętej sesji jest ignorowany. Ponowienie po zaufaniu certyfikatu czeka na
zakończenie poprzedniego procesu.

Bez SSO: `DISCONNECTED → STARTING → CONNECTING → CONNECTED`.

IPsec (PSK tunelu i osobne poświadczenia XAuth; zapisany PSK z Secret Service):
to samo co bez SSO.

SSO: `DISCONNECTED → STARTING → WAITING_FOR_AUTH → CONNECTING → CONNECTED`.

Certyfikat: `STARTING` / `WAITING_FOR_AUTH` / `CONNECTING` →
`WAITING_FOR_CERTIFICATE_TRUST` → sprzątanie → jedno ponowienie → `STARTING`.

`WAITING_FOR_CERTIFICATE_TRUST` nie jest stanem Connected. Anulowanie nie
zapisuje pinu. Zmiana odcisku nigdy nie nadpisuje pinu automatycznie.
Nieoczekiwane wyjście procesu w `CONNECTED` przechodzi do `FAILED`
(`VPN connection was lost.`). Opcjonalne auto-ponawianie (domyślnie
wyłączone) dotyczy tylko tej utraty, nie Disconnect, Quit ani odrzucenia
certyfikatu.

Disconnect/Cancel kończy własny proces uprzywilejowany w fazach STARTING,
WAITING_FOR_AUTH, WAITING_FOR_CERTIFICATE_TRUST, CONNECTING i CONNECTED.
Listener SAML znika razem z procesem; przeglądarka nie jest zamykana na siłę.

Powody błędu przy FAILED obejmują m.in. `PRIVILEGE_DENIED`,
`HELPER_NOT_AVAILABLE`, `CERTIFICATE_UNTRUSTED`, `CERTIFICATE_CHANGED`,
`SAML_FAILED`, `VPN_PROCESS_FAILED`, `CONNECTION_LOST`, `PPP_FAILED`,
`ROUTE_FAILED` i `DNS_FAILED`.

Przeglądarka otwierana jest tylko raz, w nieuprzywilejowanym procesie GUI.
Timeout SAML jest anulowany po udanym logowaniu, Disconnect i oczekiwaniu na
zaufanie certyfikatu.

## Profile połączeń

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Schemat (wersja 1): `id`, `name`, `gateway`, `port`, `description`,
`username_hint`, `use_sso`, opcjonalne `trusted_cert_sha256`, opcjonalne
`vpn_type` (brak = SSL), opcjonalne zagnieżdżone `ipsec` bez sekretów.
Dokument może
zawierać `default_profile_id` (dokładnie jeden profil domyślny albo żaden).
Pliki v0.7.1 bez tego klucza wczytują się bez profilu domyślnego.

Hasła, tokeny SAML, ciasteczka, PSK IPsec, hasła XAuth i dane MFA nie są
przechowywane. Duplikowanie kopiuje bezpieczne metadane i pin certyfikatu,
nie sekrety z Secret Service.

## Cenzura logów

Każda linia przechodzi przez `redact_log_line`. Odciski certyfikatów nie są
sekretami i mogą być pokazywane w Diagnostics. Logi zostają w pamięci.

## SAML / SSO

SAML używa **systemowej przeglądarki** użytkownika i **Microsoft Entra ID**.
`openfortivpn` (własność pomocnika) trzyma listener callback. GUI nie
uruchamia przeglądarki jako root.

## Dlaczego GUI nigdy nie działa jako root

Konfiguracja PPP, tras i DNS wymaga dodatkowych praw. Cała aplikacja Qt jako
root powiększałaby powierzchnię ataku. Te prawa należą do minimalnego
pomocnika.

## Mapa pakietów

| Pakiet | Rola |
| ------ | ---- |
| `fortigate_vpn_gui.gui` | Okna, strony Qt i zasobnik |
| `fortigate_vpn_gui.desktop` | Autostart użytkownika i preferencje pulpitu |
| `fortigate_vpn_gui.runtime` | GUI odmawia startu jako root |
| `fortigate_vpn_gui.vpn` | Stan VPN po stronie GUI, SAML, przeglądarka |
| `fortigate_vpn_gui.helper` | Protokół uprzywilejowany i właściciel procesu |
| `fortigate_vpn_gui.profiles` | Model i zapis JSON XDG |
| `fortigate_vpn_gui.system` | Preflight i klient polkit |
| `fortigate_vpn_gui.diagnostics` | Nieuprzywilejowane testy i ocenzurowane raporty |
