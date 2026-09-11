# Znane ograniczenia

Wersja v0.7.0 dodaje zasobnik, opcjonalny autostart i opcjonalne ponawianie
połączenia na bazie utwardzonego cyklu życia i pomocnika polkit.

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
- Auto-ponawianie jest **domyślnie wyłączone**. Działa tylko po nieoczekiwanej
  utracie tunelu, nie po Disconnect ani Quit, nie po odrzuceniu certyfikatu
  i nigdy bez SAML/przeglądarki ani bez jawnego zaufania certyfikatu, gdy
  są wymagane. Szybkie błędy uwierzytelniania nie są ponawiane w pętli.
- Autostart tylko uruchamia GUI po zalogowaniu. Nie łączy VPN. Plik
  `.desktop` jest na poziomie użytkownika (`~/.config/autostart/`) i nie
  wymaga root.
- Zamykanie do zasobnika wymaga działającego zasobnika. Bez niego zamknięcie
  okna nadal kończy aplikację.
- W danej chwili działa tylko jedna próba połączenia. Dodatkowe kliknięcia
  Connect są ignorowane. Po zaufaniu certyfikatu jest jedno ponowienie, gdy
  poprzedni proces się zakończy.
- Disconnect/Cancel jest bezpieczny w STARTING, WAITING_FOR_AUTH,
  WAITING_FOR_CERTIFICATE_TRUST, CONNECTING i CONNECTED. Przeglądarka nie
  jest zamykana na siłę; listener SAML znika razem z procesem.
- Hasła, ciasteczka SAML i tokeny nie są przechowywane.
- GUI samo nie zmienia zapory, tras ani DNS.
- Pakiety nigdy nie są instalowane automatycznie. Pakiet `.deb` jest
  planowany w późniejszym wydaniu (v1.0.0).
- Logi są tylko w pamięci i są ocenzurowane.
- Skopiowane raporty diagnostyczne są ocenzurowane i nie zawierają sekretów.
- Pełny URL SAML nie jest pokazywany; kopiowanie używa origin+ścieżka.
- Profile to lokalny JSON per-użytkownik.
- Tylko Linux; Ubuntu jest główną wspieraną dystrybucją.
- Dokumentacja jest po angielsku i polsku.
- Brak `libxcb-cursor.so.0` pokazuje dialog `sudo apt install libxcb-cursor0`.
- Brak `openfortivpn` lub pomocnika nie blokuje startu GUI.

To oprogramowanie niezależne. To nie FortiClient i nie jest powiązane z
Fortinet.
