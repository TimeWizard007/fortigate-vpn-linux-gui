# Środowisko deweloperskie

Ubuntu jest główną wspieraną dystrybucją. Wymagany jest Python 3.10+.
GUI zweryfikowano na Ubuntu 24.04 z Pythonem 3.12.

## Wymagania Ubuntu

```bash
sudo apt install python3.12-venv libxcb-cursor0
```

Do rzeczywistego tunelu:

```bash
sudo apt install openfortivpn pkexec
```

Paczka Ubuntu **1.21.0** może nie mieć `--saml-login`; SSO wymaga kompilacji
z SAML (przetestowano **1.24.1**). Aplikacja **nie** instaluje pakietów sama.

## Pomocnik uprzywilejowany (rozwój)

```bash
sudo install -D -m 0755 packaging/libexec/vpn-helper \
  /usr/libexec/fortigate-vpn-linux-gui/vpn-helper
sudo install -D -m 0644 packaging/polkit/com.fortigate-vpn-linux-gui.policy \
  /usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

Pomocnik musi importować `fortigate_vpn_gui`. Szczegóły:
[`packaging/README.md`](../../packaging/README.md).

Opcjonalnie: `FORTIGATE_VPN_HELPER=/ścieżka/do/vpn-helper`. Brak pomocnika,
brak polkit, odmowa autoryzacji i niezgodność wersji są zgłaszane. Nie ma
cichego, niebezpiecznego fallbacku.

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
```
