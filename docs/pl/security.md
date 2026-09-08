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

GUI nigdy nie może działać jako root. Wersja v0.1.x już odmawia startu przy
UID 0.

## Sekrety

- Hasła VPN nigdy nie mogą być przechowywane jawnym tekstem.
- Tokeny SAML i ciasteczka nigdy nie mogą trafiać do logów.
- Diagnostyka musi cenzurować poświadczenia i materiał uwierzytelniający.
- Przyszłe pliki profili mogą zawierać nazwy bram i użytkowników, nie hasła.

## Zaufanie

Weryfikacja certyfikatów nie może być po cichu wyłączana. Niebezpieczne
ustawienia TLS muszą być jawne, rzadkie i wyraźnie ostrzeżone. Domyślna ścieżka
musi weryfikować certyfikat bramy.

## Czego v0.1.x nie robi

Obecny kod nie uwierzytelnia, nie otwiera gniazd do bramy VPN, nie uruchamia
pomocników i nie zmienia sieci hosta. Model bezpieczeństwa i tak określa, jak
te funkcje mają być dodawane później.
