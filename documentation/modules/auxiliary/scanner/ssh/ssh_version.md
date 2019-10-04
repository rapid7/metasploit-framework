## Description

SSH, Secure SHell, is an encrypted network protocol used to remotely interact with an Operating System at a command line level.  SSH is available on most every system, including Windows, but is mainly used by *nix administrators.

This module identifies the version of SSH service in use by the server based on the server's banner. Any SSH server should return this information.

## Vulnerable Application

### SSH service:

This module is tested on several different SSH services, such as:

- Virtual testing environment: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
- `github.com`: SSH-2.0-babeld-38be96bc
- `gitlab.com`: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8

## Verification Steps

  1. Do: `use auxiliary/scanner/ssh/ssh_version`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Scenarios

### SSH-2.0 on GitHub

  ```
msf5 auxiliary(scanner/ssh/ssh_version) > use auxiliary/scanner/ssh/ssh_version
msf5 auxiliary(scanner/ssh/ssh_version) > set RHOSTS github.com
RHOSTS => github.com
msf5 auxiliary(scanner/ssh/ssh_version) > run

[+] 140.82.118.4:22       - SSH server version: SSH-2.0-babeld-38be96bc
[*] github.com:22         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
