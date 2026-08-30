## Description

The module will perform a bruteforce attack against SonicWall NSv (Network Security Virtual).
It allows attacking both regular SSLVPN users and as well as admins. The module will automatically target SSLVPN users if the `DOMAIN` parameter is not empty.

## Vulnerable Application

- [SonicWall](https://www.sonicwall.com/resources/trials-landing/sonicwall-nsv-next-gen-virtual-firewall-trial)

## Verification Steps

1. `use auxiliary/scanner/sonicwall/sonicwall_login`
2. `set RHOSTS [IP]`
3. either `set USERNAME [username]` or `set USERPASS_FILE [usernames file]`
4. either `set PASSWORD [password]` or `set PASS_FILE [passwords file]`
5. `set DOMAIN [domain to attack/empty string to attack admin account]`
6. `run`


