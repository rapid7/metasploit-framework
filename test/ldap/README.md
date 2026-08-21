## Setup

This contains a custom Docker image used for LDAP acceptance testing.

## Credentials

| Username                  | Password     | Domain   |
|---------------------------|--------------|----------|
| `DEV-AD\Administrator`    | `admin123!`  | `DEV-AD` |

The server is available on `127.0.0.1:389` (LDAP) and `127.0.0.1:636` (LDAPS).

## Running

- Build:
```shell
docker compose build
```

- Run:
```shell
docker compose up -d --wait
```

- Shut down:
```shell
docker compose down
```

## Example

```msf
msf auxiliary(scanner/ldap/ldap_login) > run rhost=127.0.0.1 username=DEV-AD\\Administrator password=admin123! CreateSession=true
...
msf auxiliary(scanner/ldap/ldap_login) > sessions -i -1
[*] Starting interaction with 1...

LDAP (127.0.0.1) >
```
