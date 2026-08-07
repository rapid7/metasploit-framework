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
4. Do: `run lhost=<lhost> rhost=<rhost> email=<email> newpassword=<new password>`
5. You should get a status success message indicating that the new username and password have been stored to loot.


## Options

### EMAIL (required)

Email address of the Flowise user who's password is to be reset

### NEWPASSWORD (required)

The new password of the targeted Flowise user.
NOTE: Flowise does not accept empty strings as passwords.


## Scenarios
