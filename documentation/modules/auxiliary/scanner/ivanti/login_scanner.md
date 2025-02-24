## Description

The module performs bruteforce attack against Ivanti Connect Secure.
It allows to attack both regular user and admin as well - you can select which type of account to attack with `ADMIN` parameter. 

## Vulnerable Application

- [Ivanti](https://www.ivanti.com/products/connect-secure-vpn)

## Verification Steps

1. `use auxiliary/scanner/ivanti/login_scanner`
2. `set RHOSTS [IP]`
3. either `set USERNAME [username]` or `set USERPASS_FILE [usernames file]`
4. either `set PASSWORD [password]` or `set PASS_FILE [passwords file]`
5. `set ADMIN [attack admin?]`
6. `run`


