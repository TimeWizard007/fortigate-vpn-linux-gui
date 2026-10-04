# Szyfrowany Backup i Restore

v1.6.0 dodaje **Backup** i **Restore**. To nie jest to samo co **Export** i
**Import** profilu.

**Export nie jest kopią zapasową sekretów.** Export zapisuje wersjonowany
JSON tylko z przenośnymi polami bez sekretów. Nie zawiera klucza IPsec
(PSK), hasła użytkownika, tokenid, FCT UID, ciasteczek ani wartości z
keyringa.

**Backup** zapisuje jeden szyfrowany plik `.fvbackup`, z którego można
odtworzyć obsługiwane profile i sekrety IPsec zapisane w Secret Service.

**Import** ładuje profile wyeksportowane bez poświadczeń. **Export**
zapisuje profile bez zapisanych poświadczeń. **Backup** tworzy szyfrowaną
kopię wszystkich profili i zapisanych poświadczeń. **Restore** odtwarza
profile i zapisane poświadczenia z szyfrowanego backupu.

## Po reinstalacji Ubuntu

1. Na starym systemie: Profiles → **Backup…** → wybierz miejsce zapisu
   pliku `.fvbackup` → ustaw hasło backupu (co najmniej 12 znaków) i
   potwierdź je.
2. Przechowuj plik i hasło osobno.
3. Zainstaluj FortiGate VPN Linux GUI na nowym systemie (APT albo `.deb`).
4. Profiles → **Restore…** → wybierz plik `.fvbackup` → podaj hasło użyte
   przy tworzeniu tej kopii (to nie hasło sudo, VPN ani konta) → przejrzyj
   podsumowanie → potwierdź nadpisania.
5. Odblokuj keyring pulpitu, jeśli GNOME o to poprosi.
6. Połącz. Profile IPsec z zapisanym PSK (i opcjonalnym hasłem XAuth) nie
   powinny wymagać ponownego wpisywania tych sekretów.

## Co zawiera Backup

- Stabilne identyfikatory i nazwy profili
- Bramę, port, typ VPN, ustawienia IPsec, pin certyfikatu
- Opcjonalny profil domyślny
- Opcjonalnie zapisany klucz IPsec (PSK)
- Opcjonalnie zapisane hasło XAuth

## Czego Backup nie zawiera

- Haseł SSL VPN (nigdy nie są zapisywane)
- Ciasteczek SAML, tokenów, adresów sesji, tokenid, FCT UID, sekretów EAP
- Preferencji pulpitu, autostartu, pamięci sprawdzania aktualizacji
- Logów i diagnostyki
- Stanu pomocnika albo strongSwan

Profile SSL z hasłem odtwarzają profil i opcjonalną podpowiedź nazwy
użytkownika. Hasło SSL trzeba wpisać ponownie przy łączeniu. Profile SSL
SAML/SSO nie potrzebują zapisanego hasła. IKEv2 SAML/SSO odtwarza PSK
tunelu, jeśli był zapisany; logowanie w przeglądarce następuje znowu przy
łączeniu.

## Hasło i kryptografia

Hasło backupu wybierasz przy tworzeniu kopii. Nie jest zapisywane. Restore
używa tego samego hasła. Złe hasło i uszkodzony plik dają ten sam komunikat:
**Wrong password or the backup file is damaged.**

Kontener używa Argon2id (64 MiB, 3 iteracje, 1 ścieżka) do wyprowadzenia
klucza AES-256-GCM. Nagłówek ma tylko parametry szyfrowania. Nazwy profili
i sekrety są w uwierzytelnionym szyfrogramie.

Restore jest „wszystko albo nic”. Jeśli Secret Service jest niedostępny, a
backup zawiera sekrety, Restore jest przerywany. Jeśli Restore miałby
zastąpić profil używany przez aktywne połączenie VPN, najpierw rozłącz.

Pliki są zapisywane atomowo z prawami `0600`.
