# Instalacja, aktualizacje i repozytorium APT

v1.5.0 to wydanie dystrybucji i aktualizacji. SSL VPN, IPsec, SAML i protokół
pomocnika pozostają zamrożonym baseline v1.4.0 / v1.3.0.

GUI nigdy nie pobiera ani nie instaluje pakietów i nigdy nie woła `sudo`,
`pkexec` ani `apt`, żeby się samo zaktualizować. Za aktualizacje zainstalowanej
paczki odpowiada `apt`.

## Instalacja bezpośredniego `.deb` (zawsze dostępna)

Pobierz `fortigate-vpn-linux-gui_1.5.0-1_amd64.deb` z
[GitHub Releases](https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases)
i zainstaluj:

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.5.0-1_amd64.deb
```

Późniejsza aktualizacja to nowszy pobrany `.deb` albo repozytorium APT, gdy
zostanie opublikowane.

Usuwanie:

```bash
sudo apt remove fortigate-vpn-linux-gui
```

Profile w `~/.config/fortigate-vpn-linux-gui/` zostają.

## Repozytorium APT (nie jest live, dopóki pierwszy podpisany deployment nie zostanie zweryfikowany)

GitHub Pages jest skonfigurowane na GitHub Actions. Produkcyjna publikacja APT
jeszcze się nie odbyła. Zamierzony przebieg po weryfikacji pierwszego
podpisanego deploymentu:

```bash
sudo apt update
sudo apt install fortigate-vpn-linux-gui
sudo apt upgrade
```

**To repozytorium nie jest live, dopóki podpisany deployment GitHub Pages nie
zostanie przetestowany.** Poniższe URL-e nie są produkcyjnym źródłem, zanim
to się stanie. Do tego czasu wspieraną ścieżką jest `.deb` z GitHub Releases.

Oczekiwany układ Pages po wdrożeniu:

```text
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/dists/noble/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/pool/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/fortigate-vpn-linux-gui.gpg
```

### Dodanie repozytorium (Ubuntu 24.04)

Użyj osobnego keyringu i `Signed-By`. Nie używaj `apt-key add` i nie ufaj
kluczowi globalnie.

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

## Sprawdzanie aktualizacji w GUI

About ma **Check for updates**. Settings może włączyć automatyczne sprawdzenie
najwyżej raz na 24 godziny po starcie. Zapytania idą do publicznego API GitHub
Releases przez HTTPS, bez tokenu i bez danych profilu, bramy ani użytkownika.
Brak telemetrii.

Stany: `Up to date`, `Update available: vX.Y.Z`, `Checking...`,
`Unable to check for updates`. Awaria sieci nie oznacza dostępnej aktualizacji.

**View release** otwiera stronę wydania w systemowej przeglądarce dopiero po
kliknięciu. GUI samo się nie aktualizuje.

## Model zaufania

- Klient ufa tylko kluczowi publicznemu tego repozytorium przez `signed-by=`.
- Klucz **prywatny** nigdy nie jest commitowany. GitHub Actions używa sekretów
  `APT_SIGNING_KEY` i opcjonalnie `APT_SIGNING_PASSPHRASE`.
- Tymczasowy materiał klucza jest usuwany po zadaniu publikacji.
- Pull requesty nie uruchamiają workflow podpisu.

## Procedura wydania (opiekun)

1. Wersja aplikacji, `pyproject.toml`, changelog/control Debiana i
   `scripts/build-deb.sh` muszą być zgodne (`1.5.0` / `1.5.0-1`).
   `python scripts/check-version-consistency.py` musi przejść.
2. Nie przesuwaj historycznych tagów. `v1.4.0` jest niezmienne.
3. Po przeglądzie oznacz commit tagiem `v1.5.0`. Workflow **Release** buduje
   `.deb` z tego tagu i dołącza go do GitHub Release.
4. GitHub Pages (Source = GitHub Actions) i sekrety podpisu APT są już
   skonfigurowane. Po sukcesie **Release** workflow **APT repository**
   weryfikuje pasujący opublikowany `.deb`, a potem podpisuje i wdraża.
   Nie traktuj repozytorium APT jako live, dopóki ten pierwszy podpisany
   deployment nie zostanie zweryfikowany. Do tego czasu dystrybuuj tylko
   `.deb` z GitHub Release.

Szczegóły: [`packaging/apt/README.md`](../../packaging/apt/README.md).
