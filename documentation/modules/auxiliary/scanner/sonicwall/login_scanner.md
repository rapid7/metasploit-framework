## Description

The module performs bruteforce attack against SonicWall NSv (Network Security Virtual).
It allows to attack both regular SSLVPN user and admin as well. The module will automatically perform attack against SSLVPN user if `DOMAIN` parameter is not empty.

## Vulnerable Application

- [SonicWall](https://www.sonicwall.com/resources/trials-landing/sonicwall-nsv-next-gen-virtual-firewall-trial)

## Verification Steps

1. `use auxiliary/scanner/sonicwall/login_scanner`
2. `set RHOSTS [IP]`
3. either `set USERNAME [username]` or `set USERPASS_FILE [usernames file]`
4. either `set PASSWORD [password]` or `set PASS_FILE [passwords file]`
5. `set DOMAIN [domain to attack/empty string to attack admin account]`
6. `run`


