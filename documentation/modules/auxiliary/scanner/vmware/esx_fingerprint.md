## Vulnerable Application

This module works against VMWare ESX and ESXi.  Both can be downloaded from VMWare from [here](https://my.vmware.com/en/web/vmware/evalcenter?p=free-esxi6), free account signup required.

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/scanner/vmware/esx_fingerprint`
  3. Do: `set rhosts`
  4. Do: `run`

## Scenarios

  A run against ESXi 6.0.0 Update 2 (Build 4600944)

  ```
    msf > use auxiliary/scanner/vmware/esx_fingerprint 
    msf auxiliary(esx_fingerprint) > set rhosts 10.1.2.5
    rhosts => 10.1.2.5
    msf auxiliary(esx_fingerprint) > run
    
    [+] 10.1.2.5:443 - Identified VMware ESXi 6.0.0 build-4600944
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
    msf auxiliary(esx_fingerprint) > 
  ```

## Confirming using NMAP

Utilizing [vmware-version](https://nmap.org/nsedoc/scripts/vmware-version.html)

**Note**: This script was not installed by default on Kali at the time of writing this document.
It can be installed via: `wget -O /usr/share/nmap/scripts/vmware-version.nse https://svn.nmap.org/nmap/scripts/vmware-version.nse`

  ```
nmap --script vmware-version -p443 10.1.2.5

Starting Nmap 7.40 ( https://nmap.org ) at 2017-05-11 21:14 EDT
Nmap scan report for 10.1.2.5
Host is up (0.17s latency).
PORT    STATE SERVICE
443/tcp open  https
| vmware-version: 
|   Server version: VMware ESXi 6.0.0
|   Build: 4600944
|   Locale version: INTL 000
|   OS type: vmnix-x86
|_  Product Line ID: embeddedEsx
  ```