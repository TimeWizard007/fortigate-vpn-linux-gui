# Środowisko deweloperskie

Ubuntu jest główną wspieraną dystrybucją. Wymagany jest Python 3.10+.
GUI zweryfikowano na Ubuntu 24.04 z Pythonem 3.12.

## Wymagania Ubuntu

```bash
sudo apt install python3.12-venv libxcb-cursor0
```

Do rzeczywistego tunelu z checkoutu potrzebne są `pkexec` oraz openfortivpn
z `--saml-login` na zatwierdzonej ścieżce. Paczka Ubuntu **1.21.0** nie ma
tej opcji. Paczka `.deb` dostarcza prywatny **1.24.1**. Aplikacja **nie**
instaluje pakietów sama.

## Pomocnik uprzywilejowany (rozwój)

GUI z tego checkoutu oczekuje protokołu pomocnika **0.8.0**. Wcześniejsza
paczka **1.0.0-2** ma protokół **0.7.0**. Zainstaluj pomocnik ze źródła:

```bash
sudo ./scripts/install-dev-helper.sh
./scripts/install-dev-helper.sh status
```

Przywrócenie wydanego pomocnika:

```bash
sudo ./scripts/install-dev-helper.sh restore
```

Skrypt nie ustawia setuid, nie osłabia polkit i nie uruchamia GUI jako root.

## Testy zaplecza VPN

Testy muszą mockować wykonanie. Nie mogą łączyć się z VPN, wołać prawdziwego
`openfortivpn`, otwierać prawdziwej przeglądarki, wołać `sudo` ani prawdziwego
okna pkexec, zmieniać tras/DNS/zapory, używać sieci ani działać jako root.

## Uruchomienie

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m fortigate_vpn_gui
```

Nie uruchamiaj jako root.

```bash
ruff check src tests
python -m pytest
./scripts/build-deb.sh
```
