# Instalacja, aktualizacje i repozytorium APT

v1.6.0 zachowuje produkcyjne repozytorium APT wprowadzone w v1.5.0 i dodaje
kontekst About świadomy APT. SSL VPN, IPsec, SAML i protokół pomocnika
pozostają zamrożonym baseline v1.4.0 / v1.3.0.

GUI nigdy nie pobiera ani nie instaluje pakietów i nigdy nie woła `sudo`,
`pkexec`, `apt-get` ani `apt`, żeby się samo zaktualizować. About może pokazać
kopiowalne polecenia, na przykład `sudo apt update` i
`sudo apt install --only-upgrade fortigate-vpn-linux-gui`, do uruchomienia
przez użytkownika. Za aktualizacje zainstalowanej paczki odpowiada `apt`.

Zweryfikowana platforma: **Ubuntu 24.04 LTS (`noble`), amd64**. Inne
dystrybucje nie były testowane.

## Repozytorium APT (produkcja, live)

Kanoniczne repozytorium:

```text
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt
```

`fortigate-vpn-linux-gui.gpg` to **binarny** keyring OpenPGP. Pobierz go
bezpośrednio do `/etc/apt/keyrings/`. Nie uruchamiaj `gpg --dearmor`. Nie
używaj `apt-key`, `trusted=yes` ani `--allow-unauthenticated`.

```bash
sudo mkdir -p /etc/apt/keyrings
sudo chmod 0755 /etc/apt/keyrings
curl -fsSL https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/fortigate-vpn-linux-gui.gpg \
  | sudo tee /etc/apt/keyrings/fortigate-vpn-linux-gui.gpg >/dev/null
sudo chmod 0644 /etc/apt/keyrings/fortigate-vpn-linux-gui.gpg
sudo tee /etc/apt/sources.list.d/fortigate-vpn-linux-gui.sources >/dev/null <<'EOF'
Types: deb
URIs: https://timewizard007.github.io/fortigate-vpn-linux-gui/apt
Suites: noble
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/fortigate-vpn-linux-gui.gpg
EOF
sudo apt update
sudo apt install fortigate-vpn-linux-gui
```

Aktualizacja:

```bash
sudo apt update
sudo apt upgrade
```

albo:

```bash
sudo apt install --only-upgrade fortigate-vpn-linux-gui
```

Oczekiwany układ Pages:

```text
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/fortigate-vpn-linux-gui.gpg
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/dists/noble/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/pool/
```

### Usunięcie repozytorium

```bash
sudo rm -f /etc/apt/sources.list.d/fortigate-vpn-linux-gui.sources
sudo rm -f /etc/apt/keyrings/fortigate-vpn-linux-gui.gpg
sudo apt update
```

Usunięcie źródła nie usuwa aplikacji. Do tego służy
`sudo apt remove fortigate-vpn-linux-gui`.

### Cofnięcie wersji (rollback)

Starsze `.deb` zostają w `pool/`, więc `apt` może obniżyć wersję, gdy te
paczki nadal są publikowane:

```bash
apt-cache madison fortigate-vpn-linux-gui
sudo apt install fortigate-vpn-linux-gui=1.4.0-1
```

Opcjonalnie `apt-mark hold`. Nie usuwaj historycznych zasobów GitHub Release;
publisher APT odbudowuje `pool/` ze stabilnych plików `.deb`.

## Instalacja bezpośredniego `.deb` (alternatywa)

Pobierz `fortigate-vpn-linux-gui_1.6.0-1_amd64.deb` z
[GitHub Releases](https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases)
i zainstaluj:

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.6.0-1_amd64.deb
```

Późniejsza aktualizacja to nowszy pobrany `.deb` albo repozytorium APT powyżej.

Usuwanie:

```bash
sudo apt remove fortigate-vpn-linux-gui
```

Profile w `~/.config/fortigate-vpn-linux-gui/` zostają.

## Sprawdzanie aktualizacji w GUI

About ma **Check for updates**. Settings może włączyć automatyczne sprawdzenie
najwyżej raz na 24 godziny po starcie. Zapytania idą do publicznego API GitHub
Releases przez HTTPS, bez tokenu i bez danych profilu, bramy ani użytkownika.
Brak telemetrii.

Stany: `Up to date`, `Update available` z Installed vs Available,
`Checking...`, `Unable to check for updates`. Awaria sieci nie oznacza
dostępnej aktualizacji. Lokalne informacje Debian/APT mogą być nadal
pokazane, gdy GitHub jest niedostępny.

Gdy najnowsze GitHub jest nowsze niż aplikacja, a kandydat APT jest nadal
starszy, About pokazuje oba stany i nie twierdzi, że APT już ma aktualizację.
Użytkownicy APT widzą kopiowalne polecenia. Instalacje bezpośredniego `.deb`
bez repozytorium projektu dostają informację, że nowszy `.deb` można wziąć
z GitHub Releases albo skonfigurować repozytorium APT. Uruchomienie ze
źródła jest opisane jako source/dev.

**View release** otwiera stronę wydania w systemowej przeglądarce dopiero po
kliknięciu. GUI samo się nie aktualizuje. Ta aplikacja nie instaluje
aktualizacji systemowych.

## Model zaufania

- Klient ufa tylko kluczowi publicznemu tego repozytorium przez `Signed-By`.
- Pages publikuje binarny keyring publiczny. Zcommitowane źródło publiczne to
  ASCII-armored `packaging/apt/fortigate-vpn-linux-gui-apt.asc`.
- Klucz **prywatny** nigdy nie jest commitowany. GitHub Actions używa sekretów
  `APT_SIGNING_KEY` i opcjonalnie `APT_SIGNING_PASSPHRASE`.
- Tymczasowy materiał klucza jest usuwany po zadaniu publikacji.
- Pull requesty nie uruchamiają workflow podpisu.

## Procedura wydania (opiekun)

1. Wersja aplikacji, `pyproject.toml`, changelog/control Debiana i
   `scripts/build-deb.sh` muszą być zgodne (`1.6.0` / `1.6.0-1`).
   `python scripts/check-version-consistency.py` musi przejść.
2. Nie przesuwaj historycznych tagów. `v1.4.0` i `v1.5.0` są niezmienne.
3. Po przeglądzie oznacz commit tagiem `vX.Y.Z`. Workflow **Release** buduje
   `.deb` z tego tagu i dołącza go do GitHub Release.
4. Po sukcesie **Release** workflow **APT repository** weryfikuje pasujący
   opublikowany `.deb`, a potem podpisuje i wdraża Pages. Tag-only recovery
   może ponownie opublikować metadane APT z istniejącego stabilnego Release
   bez zmiany tego Release.

Szczegóły: [`packaging/apt/README.md`](../../packaging/apt/README.md).
