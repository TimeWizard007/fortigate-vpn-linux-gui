# Architektura

Projekt oddziela interfejs pulpitu od sterowania procesem VPN i od uprawnień.

```text
GUI                          Widżety PySide6 (nieuprzywilejowane)
  ↓
Warstwa aplikacji / usług    VpnBackend, profile, ocenzurowane logi
  ↓
openfortivpn                 uruchamiany jako bieżący użytkownik (v0.3)
  ↓
FortiGate SSL VPN            brama
```

Między warstwą usług a `openfortivpn` planowany jest pomocnik uprzywilejowany
(polkit). W v0.3.x go nie ma. GUI nigdy nie może stać się tym pomocnikiem i
nigdy nie może działać jako root.

## Warstwy

### GUI

Widżety Qt w `src/fortigate_vpn_gui/gui/`. GUI pokazuje stan i zbiera intencje
użytkownika. Nie może działać jako root, wywoływać `sudo`/`pkexec` ani zmieniać
tras, DNS albo reguł zapory. Connect/Disconnect woła `VpnBackend`; widżety
same nie budują podprocesów. Dodawanie, edycja i usuwanie profili idzie przez
`ProfileManager`; widżety same nie czytają i nie zapisują JSON.

### Warstwa aplikacji / usług

Pakiety bez Qt (`vpn`, `profiles`, `diagnostics`).

`fortigate_vpn_gui.vpn` odpowiada za proces openfortivpn:

| Moduł | Rola |
| ----- | ---- |
| `backend.py` | `connect`, `disconnect`, `is_running`, `current_state`, `process_info` |
| `process.py` | `subprocess.Popen` z listą argumentów i `shell=False` |
| `command.py` | Buduje `[openfortivpn, brama:port]` bez sekretów |
| `models.py` | `ConnectionState` i migawki stanu |
| `log_redaction.py` | Centralna cenzura haseł, ciasteczek, tokenów |
| `detect.py` | Szukanie na PATH; `--version` tylko dla Diagnostics |

GUI może wystartować, gdy brakuje `openfortivpn`. Wersja nie jest odpytywana
przy starcie aplikacji.

### Pomocnik uprzywilejowany

Przyszły mały pomocnik (pakiet `system` / artefakty pakietowania) uruchamiany
przez polkit. Powinien wykonywać wyłącznie operacje, które naprawdę wymagają
dodatkowych uprawnień. v0.3.x uruchamia `openfortivpn` jako bieżący użytkownik
i zgłasza błędy uprawnień zamiast eskalować.

### openfortivpn

Silnik VPN. v0.3.x uruchamia go jako bieżący użytkownik poleceniem:

```text
openfortivpn <brama>:<port>
```

Nie dodaje argumentów z hasłem, ciasteczkiem, tokenem ani `--trusted-cert`.

### FortiGate SSL VPN

Zdalna brama. Ten projekt nie implementuje protokołu VPN samodzielnie.

## Stany połączenia

`ConnectionState` to enumeracja z deterministycznymi przejściami:

```text
DISCONNECTED → STARTING → CONNECTING → CONNECTED
CONNECTED → DISCONNECTING → DISCONNECTED
nieodwracalny błąd procesu → FAILED
FAILED → DISCONNECTED (po posprzątaniu) albo STARTING (ponowienie)
```

`WAITING_FOR_AUTH` istnieje pod przyszły przepływ SAML. v0.3.x nie otwiera
przeglądarki i nie wchodzi w ten stan dla SSO.

Profile SSO (`use_sso=True`) są odrzucane, zanim powstanie jakikolwiek proces.

## Profile połączeń

Profile to lokalna konfiguracja per-użytkownik:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Schemat JSON (wersja 1): `id`, `name`, `gateway`, `port` (domyślnie 443),
`description`, `username_hint`, `use_sso` (domyślnie true).

Hasła, tokeny SAML, ciasteczka, sekrety klienta i dane MFA nie są
przechowywane. Nieznane pola JSON są ignorowane. Uszkodzony plik nie powoduje
awarii aplikacji.

`ProfileManager` powiadamia słuchaczy po add/update/delete, więc strona
Connection odświeża się bez restartu.

## Cenzura logów

Każda linia logu zaplecza przechodzi przez `redact_log_line` zanim trafi do
pamięci albo na ekran. Dopasowanie nie zależy od wielkości liter. Typowe
zamiany:

- `password=***`
- `SVPNCOOKIE=***`
- `Authorization: Bearer ***`
- `Cookie: ***`

Logi zostają w pamięci na czas sesji. W v0.3.x nie są zapisywane na dysk.

## SAML / SSO (planowane)

Uwierzytelnianie SAML ma korzystać z **systemowej przeglądarki użytkownika**
oraz **Microsoft Entra ID**. Tokeny i ciasteczka z tego przepływu nie mogą
trafiać do logów ani do plików profili. Ta ścieżka jest planowana na v0.4.0
i nie jest zaimplementowana.

## Dlaczego GUI nigdy nie działa jako root

Konfiguracja PPP, tras i DNS wymaga dodatkowych uprawnień. Uruchomienie całego
programu Qt jako root powiększałoby powierzchnię ataku (interfejs, schowek,
okna plików, wtyczki). Dodatkowe prawa należą do przyszłego minimalnego
pomocnika, nie do procesu pulpitu. Dlatego v0.3.x uruchamia `openfortivpn`
bez uprawnień i wyjaśnia błędy permission denied zamiast prosić o `sudo`
dla całego GUI.

## Mapa pakietów

| Pakiet | Rola |
| ------ | ---- |
| `fortigate_vpn_gui.gui` | Okna i strony Qt |
| `fortigate_vpn_gui.runtime` | Kontrole procesu (GUI odmawia uruchomienia jako root) |
| `fortigate_vpn_gui.vpn` | Zaplecze openfortivpn, stany, ocenzurowane logi |
| `fortigate_vpn_gui.profiles` | Model profilu, magazyn JSON XDG, menedżer |
| `fortigate_vpn_gui.system` | Sprawdzenie zależności przy starcie; przyszła integracja pomocnika / polkit |
| `fortigate_vpn_gui.diagnostics` | Ocenzurowane migawki diagnostyczne |
