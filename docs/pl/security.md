# Model bezpieczeństwa

Ten dokument podsumowuje model bezpieczeństwa. Instrukcje zgłaszania są w
[`SECURITY.md`](../../SECURITY.md) w katalogu głównym.

**Ten projekt nie jest powiązany, wspierany ani sponsorowany przez Fortinet.**

## Podział procesów

| Proces | Uprawnienia | Rola |
| ------ | ----------- | ---- |
| GUI | Nieuprzywilejowany użytkownik | UI, intencje, przeglądarka systemowa |
| VpnBackend | Ten sam użytkownik | Żądania do pomocnika, SAML, ocenzurowane logi |
| Pomocnik | Root przez polkit | Start/stop openfortivpn |
| openfortivpn | Własność pomocnika | Tunel SSL VPN i listener SAML |
| Przeglądarka | Nieuprzywilejowany użytkownik | Strony Entra ID / FortiGate SAML |

GUI nigdy nie działa jako root. Odmawia startu przy UID 0. Dodatkowe prawa do
PPP, tras i DNS należą do pomocnika, nie do procesu Qt.

Akcja polkit: `com.fortigate-vpn-linux-gui.manage-vpn`. Użytkownik pulpitu
widzi zwykłe okno uwierzytelniania Linux. GUI nie jest uruchamiane przez
pkexec. Brak reguł sudoers; openfortivpn nie jest setuid.

## Budowa polecenia

Argumenty to **lista** z `shell=False`. Brak hasła, ciasteczka i tokenu.
`--trusted-cert` dodawane jest tylko z zwalidowanym SHA-256 jako osobny
element argv. Pomocnik nie przyjmuje surowego polecenia ani dowolnej ścieżki
wykonywalnej.

Walidacja bramy, portu, odcisku i operacji jest po stronie GUI **oraz** w
pomocniku.

## Przeglądarka i URL

Wyjście procesu jest niewiarygodne. Przed otwarciem URL backend wymaga
http/https i odrzuca javascript/file/data/loopback. Pomocnik emituje
zweryfikowane zdarzenie URL SAML. Nieuprzywilejowane GUI otwiera przeglądarkę.

## Sekrety

Hasła VPN, tokeny SAML i SVPNCOOKIE nie są przechowywane. `trusted_cert_sha256`
to publiczny pin certyfikatu, nie hasło.

## Zaufanie

Walidacja certyfikatu nigdy nie jest po cichu wyłączana. Nieznany certyfikat
FortiGate wymaga jawnego **Zaufaj temu certyfikatowi dla tego profilu VPN**.
Anuluj nie zapisuje pinu. Zmiana odcisku nigdy nie jest przyjmowana
automatycznie.

## Czego v0.7.0 nie robi

- Brak sudo i sudoers.
- Brak dowolnego wykonywania poleceń root przez pomocnika.
- Brak automatycznej instalacji pakietów (`.deb` planowane w v0.8.0).
- GUI samo nie zmienia zapory, tras ani DNS.
- Brak przechowywania haseł, tokenów i ciasteczek VPN.
- Logi są tylko w pamięci; nie są zapisywane na dysk.
- Brak automatycznego zaufania i wyłączania TLS.
- Auto-ponawianie nigdy nie pomija SAML ani walidacji certyfikatu.
- Autostart jest tylko na poziomie użytkownika (`~/.config/autostart/`);
  brak autostartu systemowego i brak automatycznego łączenia VPN przy
  logowaniu.
