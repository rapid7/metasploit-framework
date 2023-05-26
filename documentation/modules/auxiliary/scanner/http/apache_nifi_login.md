## Vulnerable Application

This attempts to login to Apache NiFi websites.

Tested against NiFi major releases 1.14.0 - 1.21.0, and 1.13.0
Also works against NiFi <= 1.13.0, but the module needs to be adjusted:

 - set SSL false
 - set rport 8080

### Docker Install

Apache manages Docker installs for NiFi with version numbers, simply select the version number you wish to install. Examples:

```
docker run -p 8443:8443 -d apache/nifi:1.21.0
docker run -p 8443:8443 -d apache/nifi:1.20.0
docker run -p 8443:8443 -d apache/nifi:1.19.0
docker run -p 8443:8443 -d apache/nifi:1.18.0
docker run -p 8443:8443 -d apache/nifi:1.17.0
docker run -p 8443:8443 -d apache/nifi:1.16.0
docker run -p 8443:8443 -d apache/nifi:1.15.0
docker run -p 8443:8443 -d apache/nifi:1.14.0
docker run -p 8080:8080 -d apache/nifi:1.13.0
```

Versions > 1.13.0 dynamically create a username and password. To view them in the docker logs, use the following command:
```
docker log <container> | grep Generated
```


## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/apache_nifi_login`
1. Do: `set rhosts [ip]`
1. Do: `set username [username]`
1. Do: `set password [password]`
1. Do: `run`
1. If any logins are valid, they will be printed

## Options

## Scenarios

### Docker image 1.18.0 and 1.13.0

```
msf6 > use auxiliary/scanner/http/nifi_login
msf6 auxiliary(scanner/http/nifi_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/nifi_login) > set username 21acf672-7935-441c-a38b-b52643f029bf
username => 21acf672-7935-441c-a38b-b52643f029bf
msf6 auxiliary(scanner/http/nifi_login) > set password bad
password => bad
msf6 auxiliary(scanner/http/nifi_login) > run

[*] Checking 127.0.0.1
[-] 127.0.0.1:8443        - Apache NiFi - Failed to login as '21acf672-7935-441c-a38b-b52643f029bf' with password 'bad'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/nifi_login) > set password R4+xdl8P9Phrqne4NxHDponQs5X9ktn2
password => R4+xdl8P9Phrqne4NxHDponQs5X9ktn2
msf6 auxiliary(scanner/http/nifi_login) > run

[*] Checking 127.0.0.1
[+] 127.0.0.1:8443        - Apache NiFi - Login successful as '21acf672-7935-441c-a38b-b52643f029bf' with password 'R4+xdl8P9Phrqne4NxHDponQs5X9ktn2'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
msf6 > use auxiliary/scanner/http/nifi_login
msf6 auxiliary(scanner/http/nifi_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/nifi_login) > set ssl false
[!] Changing the SSL option's value may require changing RPORT!
ssl => false
msf6 auxiliary(scanner/http/nifi_login) > set rport 8080
rport => 8080
msf6 auxiliary(scanner/http/nifi_login) > run

[*] Checking 127.0.0.1
[+] 127.0.0.1:8080        - User login not supported, try visiting /nifi to gain access
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
