# Model bezpieczeństwa

Ten dokument podsumowuje model bezpieczeństwa. Instrukcje zgłaszania problemów
znajdują się w [`SECURITY.md`](../../SECURITY.md) w katalogu głównym
repozytorium.

**Ten projekt nie jest powiązany, wspierany ani sponsorowany przez Fortinet.**

## Podział procesów

| Proces | Uprawnienia | Rola |
| ------ | ----------- | ---- |
| GUI | Nieuprzywilejowany użytkownik | Interfejs, zbieranie intencji |
| Przyszły pomocnik | Minimalne dodatkowe prawa przez polkit | Tylko operacje, które ich wymagają |
| openfortivpn | Uruchamiany przez pomocnik (planowane) | Tunel SSL VPN |

GUI nigdy nie może działać jako root. Odmawia startu przy UID 0.

## Sekrety

- Hasła VPN nigdy nie mogą być przechowywane jawnym tekstem.
- Tokeny SAML i ciasteczka nigdy nie mogą trafiać do logów.
- Diagnostyka musi cenzurować poświadczenia i materiał uwierzytelniający.
- Pliki profili połączeń **nie zawierają sekretów**: bez haseł, tokenów SAML,
  ciasteczek, sekretów klienta i danych MFA. Mogą zawierać nazwę bramy, port,
  nazwę wyświetlaną, opis i opcjonalną podpowiedź nazwy użytkownika.

Profile są zapisywane per-użytkownik w
`${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json`.
Ta ścieżka jest pokazana w Settings i Diagnostics tylko do odczytu.

## Zaufanie

Weryfikacja certyfikatów nie może być po cichu wyłączana. Niebezpieczne
ustawienia TLS muszą być jawne, rzadkie i wyraźnie ostrzeżone. Domyślna ścieżka
musi weryfikować certyfikat bramy.

## Czego v0.2.x nie robi

Obecny kod nie uwierzytelnia, nie otwiera gniazd do bramy VPN, nie uruchamia
pomocników i nie zmienia sieci hosta. Magazyn profili to wyłącznie lokalny
JSON. Model bezpieczeństwa i tak określa, jak funkcje VPN i SAML mają być
dodawane później.
