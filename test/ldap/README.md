## Usage

Building:

```
docker compose build
docker compose up
```

The system should be available on `127.0.0.1:389` and `127.0.0.1:636` - with the creds `Administrator:admin123!` and `DEV-AD` as the domain.

Example of running a wih a Metasploit module:

```msf
msf6 auxiliary(scanner/ldap/ldap_login) > run rhost=127.0.0.1 username=DEV-AD\\Administrator password=admin123! CreateSession=true
...
msf6 auxiliary(scanner/ldap/ldap_login) > sessions -i -1
[*] Starting interaction with 1...

LDAP (127.0.0.1) > 
```
