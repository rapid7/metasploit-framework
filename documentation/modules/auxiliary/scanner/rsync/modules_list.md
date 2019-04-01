## Description

An rsync module is essentially a directory share. These modules can optionally be protected by a password. This module connects to and
negotiates with an rsync server, lists the available modules and, optionally, determines if the module requires a password to access.

## Vulnerable Application

### Configuring rsync on Kali Linux:

Rsync is installed by default on Kali, however we need to configure some modules for the scanner to find.  Step three will
create the secrets files which we'll use to test the authentication mechanism.  Much of this is based on the guide from
[atlantic.net](https://www.atlantic.net/cloud-hosting/how-to-setup-rsync-daemon-linux-server/).

1. ```mkdir /home/public_rsync2; mkdir /home/public_rsync3; mkdir /home/public_rsync```
2. Create the configuration file: 

    ```
    echo -n "[read only files]
    path = /home/public_rsync
    comment = Files are read only
    read only = true
    timeout = 300
    
    [writable]
    path = /home/public_rsync2
    comment = Files can be written to
    read only = false
    timeout = 300
    
    [authenticated]
    path = /home/public_rsync3
    comment = Files require authentication
    read only = true
    timeout = 300
    auth users = rsync1,rsync2
    secrets file = /etc/rsyncd.secrets
    " > /etc/rsyncd.conf
    ```

3. ```echo -n "rsync1:9$AZv2%5D29S740k
rsync2:Xyb#vbfUQR0og0$6
rsync3:VU&A1We5DEa8M6^8" > /etc/rsyncd.secrets```
4. ```chmod 600 /etc/rsyncd.secrets```
5. ```rsync --daemon```

## Verification Steps

  1. Do: `use auxiliary/scanner/rsync/modules_list`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Options

  **TEST_AUTHENTICATION**

  Connect to each share and test if authentication is required.

  **VERBOSE**

  When set to `false`, each module will be listed.  When set to `true` each module will be listed, then a summary
  table will also be printed including if authentication is required, and any module comments.  `false` is the default value.

## Scenarios

### rsyncd on Kali (using above config)

With verbose set to `false`:

  ```
  msf5 > use auxiliary/scanner/rsync/modules_list
  msf5 auxiliary(scanner/rsync/modules_list) > set rhosts 10.168.202.216
  rhosts => 10.168.202.216
  msf5 auxiliary(scanner/rsync/modules_list) > run
  
  [+] 10.168.202.216:873    - 3 rsync modules found: read only files, writable, authenticated
  ```

With verbose set to `true`:

  ```
  msf5 > use auxiliary/scanner/rsync/modules_list
  msf5 auxiliary(scanner/rsync/modules_list) > set rhosts 10.168.202.216
  rhosts => 10.168.202.216
  msf5 auxiliary(scanner/rsync/modules_list) > set verbose true
  verbose => true
  msf5 auxiliary(scanner/rsync/modules_list) > run
  
  [+] 10.168.202.216:873    - 3 rsync modules found: read only files, writable, authenticated
  
  rsync modules for 10.168.202.216:873   
  =======================================
  
     Name             Comment                       Authentication
     ----             -------                       --------------
     authenticated    Files require authentication  required
     read only files  Files are read only           not required
     writable         Files can be written to       not required
  
  ```

## Confirming

### [nmap](https://nmap.org/nsedoc/scripts/rsync-list-modules.html)

```
# nmap -p 873 -sV -script=rsync-list-modules 10.168.202.216
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-12 16:32 EDT
Nmap scan report for 10.168.202.216
Host is up (0.000045s latency).

PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules: 
|   read only files	Files are read only
|   writable       	Files can be written to
|_  authenticated  	Files require authentication

```
