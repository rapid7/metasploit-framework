## Vulnerable Application

SSH, Secure SHell, is an encrypted network protocol used to remotely interact with an Operating System at a command line level.
SSH is available on most every system, including Windows, but is mainly used by *nix administrators.

This module identifies the version of SSH service in use by the server based on the server's banner.
Any SSH server should return this information. It also identifies the varous cryptographic settings
and vulnerabilities associated with those.

This module is tested on several different SSH services, such as:

- Virtual testing environment: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
- `github.com`: SSH-2.0-babeld-38be96bc
- `gitlab.com`: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8

### Vulnerable Ubuntu 14.04.1

The following `Dockerfile` can be used to create an Ubuntu 14.04.1 image with SSH running.

```
FROM ubuntu:14.04.1

RUN apt-get update && apt-get -y install --no-install-recommends openssh-server=1:6.6p1-2ubuntu1 openssh-client=1:6.6p1-2ubuntu1 openssh-sftp-server=1:6.6p1-2ubuntu1
RUN mkdir /var/run/sshd
EXPOSE 22

CMD ["/usr/sbin/sshd","-D"]
```

## Verification Steps

  1. Do: `use auxiliary/scanner/ssh/ssh_version`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Options

### EXTENDED_CHECKS

Check for cryptographic issues. Defaults to `true`

## Scenarios

### SSH-2.0 on GitHub

```
msf5 > use auxiliary/scanner/ssh/ssh_version
msf5 auxiliary(scanner/ssh/ssh_version) > set RHOSTS github.com
RHOSTS => github.com
msf5 auxiliary(scanner/ssh/ssh_version) > run

[*] 140.82.113.4 - Key Fingerprint: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
[*] 140.82.113.4 - SSH server version: SSH-2.0-babeld-8405f9f3
[*] 140.82.113.4 - Server Information and Encryption
=================================

  Type                           Value                                 Note
  ----                           -----                                 ----
  encryption.compression         none
  encryption.compression         zlib@openssh.com
  encryption.compression         zlib
  encryption.encryption          chacha20-poly1305@openssh.com
  encryption.encryption          aes256-gcm@openssh.com
  encryption.encryption          aes128-gcm@openssh.com
  encryption.encryption          aes256-ctr
  encryption.encryption          aes192-ctr
  encryption.encryption          aes128-ctr
  encryption.hmac                hmac-sha2-512-etm@openssh.com
  encryption.hmac                hmac-sha2-256-etm@openssh.com
  encryption.hmac                hmac-sha2-512
  encryption.hmac                hmac-sha2-256
  encryption.host_key            ssh-ed25519
  encryption.host_key            ecdsa-sha2-nistp256                   Weak elliptic curve
  encryption.host_key            rsa-sha2-512
  encryption.host_key            rsa-sha2-256
  encryption.host_key            ssh-rsa
  encryption.key_exchange        curve25519-sha256
  encryption.key_exchange        curve25519-sha256@libssh.org
  encryption.key_exchange        ecdh-sha2-nistp256
  encryption.key_exchange        ecdh-sha2-nistp384
  encryption.key_exchange        ecdh-sha2-nistp521
  encryption.key_exchange        diffie-hellman-group-exchange-sha256
  encryption.key_exchange        kex-strict-s-v00@openssh.com

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Docker image

```
msf5 > use auxiliary/scanner/ssh/ssh_version
msf6 auxiliary(scanner/ssh/ssh_version) > set rhosts 172.17.0.2
rhosts => 172.17.0.2
msf6 auxiliary(scanner/ssh/ssh_version) > set verbose true
verbose => true
msf6 auxiliary(scanner/ssh/ssh_version) > run

[*] 172.17.0.2 - Key Fingerprint: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG52hWkobwr57akGxiK6eeMN9/M5MH+sQsNPv8Mci049
[*] 172.17.0.2 - SSH server version: SSH-2.0-OpenSSH_6.6p1 Ubuntu-2ubuntu1
[+] 172.17.0.2 - Key Exchange (kex) diffie-hellman-group-exchange-sha1 is deprecated and should not be used.
[+] 172.17.0.2 - Key Exchange (kex) diffie-hellman-group1-sha1 is deprecated and should not be used.
[+] 172.17.0.2 - Host Key Encryption ecdsa-sha2-nistp256 uses a weak elliptic curve and should not be used.
[+] 172.17.0.2 - HMAC hmac-md5 is deprecated and should not be used.
[+] 172.17.0.2 - HMAC hmac-ripemd160 is deprecated and should not be used.
[+] 172.17.0.2 - HMAC hmac-sha1-96 is deprecated and should not be used.
[+] 172.17.0.2 - HMAC hmac-md5-96 is deprecated and should not be used.
[+] 172.17.0.2 - Encryption arcfour256 is deprecated and should not be used.
[+] 172.17.0.2 - Encryption arcfour128 is deprecated and should not be used.
[+] 172.17.0.2 - Encryption aes128-cbc is deprecated and should not be used.
[+] 172.17.0.2 - Encryption 3des-cbc is deprecated and should not be used.
[+] 172.17.0.2 - Encryption blowfish-cbc is deprecated and should not be used.
[+] 172.17.0.2 - Encryption cast128-cbc is deprecated and should not be used.
[+] 172.17.0.2 - Encryption aes192-cbc is deprecated and should not be used.
[+] 172.17.0.2 - Encryption aes256-cbc is deprecated and should not be used.
[+] 172.17.0.2 - Encryption arcfour is deprecated and should not be used.
[+] 172.17.0.2 - Encryption rijndael-cbc@lysator.liu.se is deprecated and should not be used.
[*] 172.17.0.2 - Server Information and Encryption
=================================

  Type                           Value                                 Note
  ----                           -----                                 ----
  encryption.compression         none
  encryption.compression         zlib@openssh.com
  encryption.encryption          aes128-ctr
  encryption.encryption          aes192-ctr
  encryption.encryption          aes256-ctr
  encryption.encryption          arcfour256                            Deprecated
  encryption.encryption          arcfour128                            Deprecated
  encryption.encryption          aes128-gcm@openssh.com
  encryption.encryption          aes256-gcm@openssh.com
  encryption.encryption          chacha20-poly1305@openssh.com
  encryption.encryption          aes128-cbc                            Deprecated
  encryption.encryption          3des-cbc                              Deprecated
  encryption.encryption          blowfish-cbc                          Deprecated
  encryption.encryption          cast128-cbc                           Deprecated
  encryption.encryption          aes192-cbc                            Deprecated
  encryption.encryption          aes256-cbc                            Deprecated
  encryption.encryption          arcfour                               Deprecated
  encryption.encryption          rijndael-cbc@lysator.liu.se           Deprecated
  encryption.hmac                hmac-md5-etm@openssh.com
  encryption.hmac                hmac-sha1-etm@openssh.com
  encryption.hmac                umac-64-etm@openssh.com
  encryption.hmac                umac-128-etm@openssh.com
  encryption.hmac                hmac-sha2-256-etm@openssh.com
  encryption.hmac                hmac-sha2-512-etm@openssh.com
  encryption.hmac                hmac-ripemd160-etm@openssh.com
  encryption.hmac                hmac-sha1-96-etm@openssh.com
  encryption.hmac                hmac-md5-96-etm@openssh.com
  encryption.hmac                hmac-md5                              Deprecated
  encryption.hmac                hmac-sha1
  encryption.hmac                umac-64@openssh.com
  encryption.hmac                umac-128@openssh.com
  encryption.hmac                hmac-sha2-256
  encryption.hmac                hmac-sha2-512
  encryption.hmac                hmac-ripemd160                        Deprecated
  encryption.hmac                hmac-ripemd160@openssh.com
  encryption.hmac                hmac-sha1-96                          Deprecated
  encryption.hmac                hmac-md5-96                           Deprecated
  encryption.host_key            ssh-rsa
  encryption.host_key            ssh-dss
  encryption.host_key            ecdsa-sha2-nistp256                   Weak elliptic curve
  encryption.host_key            ssh-ed25519
  encryption.key_exchange        curve25519-sha256@libssh.org
  encryption.key_exchange        ecdh-sha2-nistp256
  encryption.key_exchange        ecdh-sha2-nistp384
  encryption.key_exchange        ecdh-sha2-nistp521
  encryption.key_exchange        diffie-hellman-group-exchange-sha256
  encryption.key_exchange        diffie-hellman-group-exchange-sha1    Deprecated
  encryption.key_exchange        diffie-hellman-group14-sha1
  encryption.key_exchange        diffie-hellman-group1-sha1            Deprecated
  fingerprint_db                 ssh.banner
  openssh.comment                Ubuntu-2ubuntu1
  os.cpe23                       cpe:/o:canonical:ubuntu_linux:14.04
  os.family                      Linux
  os.product                     Linux
  os.vendor                      Ubuntu
  os.version                     14.04
  service.cpe23                  cpe:/a:openbsd:openssh:6.6p1
  service.family                 OpenSSH
  service.product                OpenSSH
  service.protocol               ssh
  service.vendor                 OpenBSD
  service.version                6.6p1

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming using NMAP

Utilizing the [ssh2-enum-algos](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html) NMAP script.

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-11 14:55 EST
Nmap scan report for 172.17.0.2
Host is up (0.000099s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6p1 Ubuntu 2ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh2-enum-algos: 
|   kex_algorithms: (8)
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group-exchange-sha1
|       diffie-hellman-group14-sha1
|       diffie-hellman-group1-sha1
|   server_host_key_algorithms: (4)
|       ssh-rsa
|       ssh-dss
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (16)
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       arcfour256
|       arcfour128
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|       chacha20-poly1305@openssh.com
|       aes128-cbc
|       3des-cbc
|       blowfish-cbc
|       cast128-cbc
|       aes192-cbc
|       aes256-cbc
|       arcfour
|       rijndael-cbc@lysator.liu.se
|   mac_algorithms: (19)
|       hmac-md5-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-ripemd160-etm@openssh.com
|       hmac-sha1-96-etm@openssh.com
|       hmac-md5-96-etm@openssh.com
|       hmac-md5
|       hmac-sha1
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-ripemd160
|       hmac-ripemd160@openssh.com
|       hmac-sha1-96
|       hmac-md5-96
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds
```
