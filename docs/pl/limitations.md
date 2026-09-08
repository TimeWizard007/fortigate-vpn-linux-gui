# Znane ograniczenia

Wersja v0.3.0 dodaje nieuprzywilejowane zaplecze procesu `openfortivpn`. Nadal
**nie** jest to kompletny klient VPN.

- SAML/SSO nie jest zaimplementowane. Profile z włączonym Use SSO nie
  uruchamiają VPN. Komunikat: `SAML/SSO connection support is planned for
  v0.4.0.` Przeglądarka nie jest otwierana. Microsoft Entra ID jest poza
  zakresem.
- Pomocnik uprzywilejowany / polkit nie jest zaimplementowany. `openfortivpn`
  działa jako bieżący użytkownik. Błędy uprawnień (PPP, trasy, DNS) są
  zgłaszane; nie obchodzi się ich uruchamianiem GUI jako root.
- Hasła, ciasteczka SAML i tokeny nie są przechowywane. Połączenie bez SSO
  może więc paść na uwierzytelnianiu. W v0.3.0 to oczekiwane.
- Weryfikacja certyfikatów nigdy nie jest po cichu wyłączana. `--trusted-cert`
  nie jest przekazywane.
- GUI samo nie zmienia reguł zapory, tras ani DNS.
- Pakiety nigdy nie są instalowane automatycznie. Zalecana komenda Ubuntu:
  `sudo apt install openfortivpn`.
- Logi są tylko w pamięci i są ocenzurowane. Nie są zapisywane na dysk.
- Profile to lokalny JSON per-użytkownik. Nie są synchronizowane i nie są
  szyfrowane poza zwykłymi uprawnieniami katalogu domowego.
- Pliki profili nie zawierają haseł, tokenów, ciasteczek ani innych sekretów.
- Tylko Linux; Ubuntu jest główną wspieraną dystrybucją.
- Inne środowiska pulpitu powinny działać tam, gdzie działa PySide6; nie są
  jeszcze celami pierwszej klasy.
- Dokumentacja jest po angielsku i polsku; inne języki nie są dostępne.
- Pakiety uruchomieniowe Ubuntu (`python3.x-venv`, `libxcb-cursor0`) musi
  zainstalować użytkownik. Aplikacja nigdy nie instaluje pakietów systemowych.
- Jeśli brakuje `libxcb-cursor.so.0`, start pokazuje okno (oraz stderr) z
  komendą `sudo apt install libxcb-cursor0` i kończy działanie zamiast
  crashować wewnątrz Qt. W czystej sesji X11 bez tej biblioteki Qt nie może
  narysować okna; te same instrukcje i tak trafiają na terminal.
- Jeśli brakuje `openfortivpn`, GUI i tak startuje. Strona Connection wyjaśnia,
  że łączność VPN jest niedostępna.

To niezależne oprogramowanie. To nie jest FortiClient i projekt nie jest
powiązany, wspierany ani sponsorowany przez Fortinet. Fortinet, FortiGate i
FortiClient są znakami towarowymi odpowiednich właścicieli.
