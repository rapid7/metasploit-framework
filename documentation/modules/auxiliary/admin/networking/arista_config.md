## Vulnerable Application

### General Notes

This module imports an Arista configuration file into the database.
This is similar to `post/networking/gather/enum_arista` only access isn't required,
and assumes you already have the file.

Arista vEOS is available to download for [GNS3](https://www.gns3.com/marketplace/featured/arista-veos)

Example config file:

```
! Command: show running-config
! device: aristaveos (vEOS, EOS-4.19.10M)
!
! boot system flash:vEOS-lab.swi
!
transceiver qsfp default-mode 4x10G
!
hostname aristaveos
!
snmp-server community read ro
snmp-server community write rw
!
spanning-tree mode mstp
!
enable secret sha512 $6$jemN09cUdoLRim6i$Mvl2Fog/VZ7ktxyLSVDR1KnTTTPSMHU3WD.G/kxwgODdsc3d7S1aSNJX/DJmQI3nyrYnEw4lsmoKPGClFJ9hH1
aaa root secret sha512 $6$Rnanb2dQsVy2H3QL$DEYDZMy6j6KK4XK62Uh.3U3WXxK5XJvn8Zd5sm36T7BVKHS5EmIcQV.EN1X1P1ZO099S0lkxpvEGzA9yK5PQF.
!
username admin privilege 15 role network-admin secret sha512 $6$Ei2bjrcTCGPOjSkk$7S.XSTZqdRVXILbUUDcRPCxzyfqEFYzg6HfL0BHXvriETX330MT.KObHLkGx7n9XZRVWBr68ZsKfvzvxYCvj61
!
interface Ethernet1
!
interface Ethernet2
!
interface Ethernet3
!
interface Ethernet4
!
interface Ethernet5
!
interface Ethernet6
!
interface Ethernet7
!
interface Ethernet8
!
interface Ethernet9
!
interface Ethernet10
!
interface Ethernet11
!
interface Ethernet12
!
interface Management1
   ip address dhcp
!
no ip routing
!
end
```

## Verification Steps

1. Have a Arista configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/networking/arista_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.config`
6. `run`

## Options

### RHOST

Needed for setting services and items to.  This is relatively arbitrary.

### CONFIG

File path to the configuration file.

## Scenarios

```
resource (arista_config.rb)> use auxiliary/admin/networking/arista_config
resource (arista_config.rb)> set rhost 1.1.1.1
rhost => 1.1.1.1
resource (arista_config.rb)> set config /tmp/veos.config
config => /tmp/veos.config
resource (arista_config.rb)> set verbose true
verbose => true
resource (arista_config.rb)> run
[*] Running module against 1.1.1.1
[*] Importing config
[+] 1.1.1.1:22 Hostname: aristaveos, Device: vEOS, OS: EOS, Version: 4.19.10M
[+] 1.1.1.1:22 Hostname: aristaveos
[+] 1.1.1.1:22 SNMP Community (ro): read
[+] 1.1.1.1:22 SNMP Community (rw): write
[+] 1.1.1.1:22 Enable hash: $6$jemN09cUdoLRim6i$Mvl2Fog/VZ7ktxyLSVDR1KnTTTPSMHU3WD.G/kxwgODdsc3d7S1aSNJX/DJmQI3nyrYnEw4lsmoKPGClFJ9hH1
[+] 1.1.1.1:22 AAA Username 'root' with Hash: $6$Rnanb2dQsVy2H3QL$DEYDZMy6j6KK4XK62Uh.3U3WXxK5XJvn8Zd5sm36T7BVKHS5EmIcQV.EN1X1P1ZO099S0lkxpvEGzA9yK5PQF.
[+] 1.1.1.1:22 Username 'admin' with privilege 15, Role network-admin, and Hash: $6$Ei2bjrcTCGPOjSkk$7S.XSTZqdRVXILbUUDcRPCxzyfqEFYzg6HfL0BHXvriETX330MT.KObHLkGx7n9XZRVWBr68ZsKfvzvxYCvj61
[+] Config import successful
[*] Auxiliary module execution completed
```


