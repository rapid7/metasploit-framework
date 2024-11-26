## Vulnerable Application

This module identifies Apache NiFi websites and reports their version number.

Tested against NiFi major releases 1.14.0 - 1.21.0, and 1.11.0-1.13.0.

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
docker run -p 8080:8080 -d apache/nifi:1.13.0
docker run -p 8080:8080 -d apache/nifi:1.12.0
docker run -p 8080:8080 -d apache/nifi:1.11.0
```

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/apache_nifi_version`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get back the version number of the NiFi instance

## Options

## Scenarios

### Docker image 1.21.0 and 1.11.0

```
└─$ docker run -p 8443:8443 -d apache/nifi:1.21.0
1df39f1d1dc0a4abde9e2daedf8b3dc66d37fb53126e491b7050da618e971dfd
└─$ ./msfconsole -q
msf6 > use auxiliary/scanner/http/apache_nifi_version
msf6 auxiliary(scanner/http/apache_nifi_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/apache_nifi_version) > run

[+] Apache NiFi 1.21.0 found on 127.0.0.1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
└─$ docker run -p 8080:8080 -d apache/nifi:1.11.0
089f1b164853df8b088a3e80d25d7f886b1934a654ed7807433e3eef46a5973f
└─$ ./msfconsole -q
msf6 > use auxiliary/scanner/http/apache_nifi_version
msf6 auxiliary(scanner/http/apache_nifi_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/apache_nifi_version) > set ssl false
[!] Changing the SSL option's value may require changing RPORT!
ssl => false
msf6 auxiliary(scanner/http/apache_nifi_version) > set rport 8080
rport => 8080
msf6 auxiliary(scanner/http/apache_nifi_version) > run

[+] Apache NiFi 1.11.0 found on 127.0.0.1
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
