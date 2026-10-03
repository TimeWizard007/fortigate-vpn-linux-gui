# Znane ograniczenia

Wersja v1.6.0 to zamierzone wydanie kompletne na zamrożonych
backendach SSL i IPsec z v1.4.0 / v1.3.0 (zasobnik, opcjonalny autostart i
opcjonalne ponawianie bez zmian). GUI samo się nie aktualizuje. Szyfrowany
Backup obejmuje profile i zapisane sekrety IPsec; hasła SSL i sesje SAML
nie są zapisywane.

- GUI nigdy nie działa jako root. Praca uprzywilejowana idzie tylko przez
  pomocnika.
- Do prawdziwego tunelu trzeba zainstalować pomocnika i politykę polkit. Brak
  pomocnika, brak polkit, odmowa autoryzacji i niezgodność wersji są
  zgłaszane; GUI nie spada na sudo ani na uruchamianie openfortivpn jako
  użytkownik pulpitu.
- Paczkowany openfortivpn Ubuntu 24.04 **1.21.0** nie ma `--saml-login`.
  Paczka FortiGate VPN Linux GUI dostarcza własny **1.24.1** w
  `/usr/libexec/fortigate-vpn-linux-gui/openfortivpn`.
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
- IPsec to ogólny typ profilu. Ta wersja uruchamia IKEv1 Aggressive Mode
  z PSK, XAuth, Mode Config, NAT-T i FortiGate/Cisco Unity split include
  oraz IKEv2 + SAML/SSO z kompatybilnym EAP-MSCHAPv2 FortiClient i
  negocjowanym split-tunnel `INTERNAL_IP4_SUBNET`. Main Mode, certyfikat
  i adresacja ręczna nie są łączone.
- IPsec używa dystrybucyjnego strongSwan (`charon`/`swanctl`). Nie jest
  dołączany do paczki. Wsparcie Debian 13, Fedora, Windows i macOS nie jest
  deklarowane.
- Prywatny IPsec nie może współdzielić UDP/500 i UDP/4500 z innym demonem IKE
  (w tym `strongswan-starter`). Klient wykrywa konflikt i kończy czysto
  komunikatem **IKE ports in use**; nie zatrzymuje, nie wyłącza i nie zabija
  obcej usługi. SSL VPN może działać przy włączonym systemowym strongSwan.
  Paczka `.deb` nigdy nie zatrzymuje `strongswan-starter`. Dwa demony IKE nie
  mogą jednocześnie zająć tych samych portów UDP.
- Klucz pre-shared nie trafia do `profiles.json`. Jeśli użytkownik wyrazi
  zgodę, PSK IPsec i/lub hasło XAuth są zapisywane w Secret Service / GNOME
  Keyring pod stabilnym identyfikatorem profilu, w osobnych nazwach usług.
  Gdy Secret Service jest niedostępny, sekret podaje się przy łączeniu.
  Brak zapisu jawnego. `username_hint` nie jest sekretem.
- Hasła SSL, ciasteczka SAML i tokeny nie są przechowywane.
- GUI samo nie zmienia zapory, tras ani DNS.
- GUI samo nie instaluje pakietów. Instalacja na Ubuntu 24.04 używa
  pakietu `.deb` `fortigate-vpn-linux-gui` albo `apt` z repozytorium
  projektu. Sprawdzenie aktualizacji pokazuje GitHub Releases i lokalny
  kontekst paczki. GUI nigdy nie uruchamia `apt`, `sudo` ani `pkexec`,
  żeby się zaktualizować.
- Logi są tylko w pamięci i są ocenzurowane.
- Skopiowane i eksportowane raporty diagnostyczne są ocenzurowane i nie zawierają sekretów.
- Pełny URL SAML nie jest pokazywany; kopiowanie używa origin+ścieżka.
- Profile to lokalny JSON per-użytkownik. Szyfrowany Backup (`.fvbackup`)
  może skopiować profile i zapisane sekrety IPsec; hasła SSL i sesje SAML
  nigdy nie są zapisywane ani kopiowane. Restore wymaga Secret Service,
  gdy kopia zawiera sekrety IPsec.
- Tylko Linux; wspieraną platformą wydania jest Ubuntu 24.04 LTS amd64.
- Dokumentacja jest po angielsku i polsku.
- Brak `libxcb-cursor.so.0` pokazuje dialog `sudo apt install libxcb-cursor0`.
- Brak `openfortivpn` lub pomocnika nie blokuje startu GUI.

To oprogramowanie niezależne. To nie FortiClient i nie jest powiązane z
Fortinet.
