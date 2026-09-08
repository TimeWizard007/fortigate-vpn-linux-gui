# Znane ograniczenia

Wersja v0.2.x dodaje trwałe profile. **Nie** jest działającym klientem VPN.

- Brak połączenia VPN: `openfortivpn` nie jest uruchamiany.
- Brak SAML/SSO: logowanie Microsoft Entra ID jest planowane, nie
  zaimplementowane. Connect with SSO pokazuje tylko komunikat, że funkcji
  jeszcze nie ma.
- Profile to lokalny JSON per-użytkownik. Nie są synchronizowane i nie są
  szyfrowane poza zwykłymi uprawnieniami katalogu domowego.
- Pliki profili nie zawierają haseł, tokenów, ciasteczek ani innych sekretów.
- Brak pomocnika uprzywilejowanego, reguł polkit i usług systemd.
- Brak zmian tras, DNS i zapory.
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

To niezależne oprogramowanie. To nie jest FortiClient i projekt nie jest
powiązany, wspierany ani sponsorowany przez Fortinet. Fortinet, FortiGate i
FortiClient są znakami towarowymi odpowiednich właścicieli.
