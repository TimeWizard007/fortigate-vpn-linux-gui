# Znane ograniczenia

Wersja v0.6.0 utwardza cykl życia połączenia, oczekiwanie na zaufanie
certyfikatu i utratę tunelu na bazie pomocnika polkit i SAML/SSO.

- GUI nigdy nie działa jako root. Praca uprzywilejowana idzie tylko przez
  pomocnika.
- Do prawdziwego tunelu trzeba zainstalować pomocnika i politykę polkit. Brak
  pomocnika, brak polkit, odmowa autoryzacji i niezgodność wersji są
  zgłaszane; GUI nie spada na sudo ani na uruchamianie openfortivpn jako
  użytkownik pulpitu.
- Paczkowany openfortivpn Ubuntu 24.04 **1.21.0** może nie mieć
  `--saml-login`. SSO wymaga kompilacji z SAML (przetestowano: **1.24.1**).
- Certyfikaty nigdy nie są zaufane automatycznie. Walidacja TLS nigdy nie jest
  wyłączana. `--trusted-cert` dodawane jest tylko po jawnym pinie profilu.
- Zmiana certyfikatu bramy nie jest przyjmowana automatycznie.
- W danej chwili działa tylko jedna próba połączenia. Dodatkowe kliknięcia
  Connect są ignorowane. Po zaufaniu certyfikatu jest jedno ponowienie, gdy
  poprzedni proces się zakończy.
- Nieoczekiwana utrata tunelu jest wykrywana (`VPN connection was lost.`);
  klient **nie** ponawia połączenia automatycznie (planowane w v0.7.0).
- Disconnect/Cancel jest bezpieczny w STARTING, WAITING_FOR_AUTH,
  WAITING_FOR_CERTIFICATE_TRUST, CONNECTING i CONNECTED. Przeglądarka nie
  jest zamykana na siłę; listener SAML znika razem z procesem.
- Hasła, ciasteczka SAML i tokeny nie są przechowywane.
- GUI samo nie zmienia zapory, tras ani DNS.
- Pakiety nigdy nie są instalowane automatycznie.
- Logi są tylko w pamięci i są ocenzurowane.
- Pełny URL SAML nie jest pokazywany; kopiowanie używa origin+ścieżka.
- Profile to lokalny JSON per-użytkownik.
- Tylko Linux; Ubuntu jest główną wspieraną dystrybucją.
- Dokumentacja jest po angielsku i polsku.
- Brak `libxcb-cursor.so.0` pokazuje dialog `sudo apt install libxcb-cursor0`.
- Brak `openfortivpn` lub pomocnika nie blokuje startu GUI.

To oprogramowanie niezależne. To nie FortiClient i nie jest powiązane z
Fortinet.
