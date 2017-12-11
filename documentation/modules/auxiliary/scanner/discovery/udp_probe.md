## Description

The “udp_probe” module scans a given range of hosts for common UDP services. Note: This module is deprecated and may disappear at any time.

## Verification Steps

1. Do: ```use auxiliary/scanner/discovery/ipv6_neighbor```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

There are very few required settings for this module so we just configure the RHOSTS and THREADS values and let it run.

## Scenarios

**Running the scanner**
```
msf > use auxiliary/scanner/discovery/udp_probe

[!] ******************************************************************************************
[!] *                 The module scanner/discovery/udp_probe is deprecated!                  *
[!] *                       It will be removed on or about 2016-11-23                        *
[!] *                   Use auxiliary/scanner/discovery/udp_sweep instead                    *
[!] ******************************************************************************************
msf auxiliary(udp_probe) > show options

Module options (auxiliary/scanner/discovery/udp_probe):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   RHOSTS                    yes       The target address range or CIDR identifier
   THREADS  1                yes       The number of concurrent threads

msf auxiliary(udp_probe) > set RHOSTS 192.168.1.2-254
RHOSTS => 192.168.1.2-254
msf auxiliary(udp_probe) > set THREADS 253
THREADS => 253
msf auxiliary(udp_probe) > run

[*] Discovered SNMP on 192.168.1.2:161 (GSM7224 L2 Managed Gigabit Switch)
[*] Discovered SNMP on 192.168.1.2:161 (GSM7224 L2 Managed Gigabit Switch)
[*] Discovered NetBIOS on 192.168.1.109:137 (SAMSUNG::U :SAMSUNG::U :00:15:99:3f:40:bd)
[*] Discovered NetBIOS on 192.168.1.150:137 (XEN-WIN7-PROD::U :WORKGROUP::G :XEN-WIN7-PROD::U :WORKGROUP::G :aa:e3:27:6e:3b:a5)
[*] Discovered SNMP on 192.168.1.109:161 (Samsung CLX-3160 Series; OS V1.01.01.16 02-25-2008;Engine 6.01.00;NIC V4.03.08(CLX-3160) 02-25-2008;S/N 8Y61B1GP400065Y.)
[*] Discovered NetBIOS on 192.168.1.206:137 (XEN-XP-PATCHED::U :XEN-XP-PATCHED::U :HOTZONE::G :HOTZONE::G :12:fa:1a:75:b8:a5)
[*] Discovered NetBIOS on 192.168.1.203:137 (XEN-XP-SPLOIT::U :WORKGROUP::G :XEN-XP-SPLOIT::U :WORKGROUP::G :3e:ff:3c:4c:89:67)
[*] Discovered NetBIOS on 192.168.1.201:137 (XEN-XP-SP2-BARE::U :HOTZONE::G :XEN-XP-SP2-BARE::U :HOTZONE::G :HOTZONE::U :__MSBROWSE__::G :c6:ce:4e:d9:c9:6e)
[*] Discovered SNMP on 192.168.1.109:161 (Samsung CLX-3160 Series; OS V1.01.01.16 02-25-2008;Engine 6.01.00;NIC V4.03.08(CLX-3160) 02-25-2008;S/N 8Y61B1GP400065Y.)
[*] Discovered NTP on 192.168.1.69:123 (NTP v4)
[*] Discovered NetBIOS on 192.168.1.250:137 (FREENAS::U :FREENAS::U :FREENAS::U :__MSBROWSE__::G :WORKGROUP::U :WORKGROUP::G :WORKGROUP::G :00:00:00:00:00:00)
[*] Discovered NTP on 192.168.1.203:123 (Microsoft NTP)
[*] Discovered MSSQL on 192.168.1.206:1434 (ServerName=XEN-XP-PATCHED InstanceName=SQLEXPRESS IsClustered=No Version=9.00.4035.00 tcp=1050 np=\\XEN-XP-PATCHED\pipe\MSSQL$SQLEXPRESS\sql\query )
[*] Discovered NTP on 192.168.1.206:123 (Microsoft NTP)
[*] Discovered NTP on 192.168.1.201:123 (Microsoft NTP)
[*] Scanned 029 of 253 hosts (011% complete)
[*] Scanned 052 of 253 hosts (020% complete)
[*] Scanned 084 of 253 hosts (033% complete)
[*] Scanned 114 of 253 hosts (045% complete)
[*] Scanned 140 of 253 hosts (055% complete)
[*] Scanned 160 of 253 hosts (063% complete)
[*] Scanned 184 of 253 hosts (072% complete)
[*] Scanned 243 of 253 hosts (096% complete)
[*] Scanned 250 of 253 hosts (098% complete)
[*] Scanned 253 of 253 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(udp_probe) >
```

As you can see in the above output, our quick little scan discovered many services running on a wide variety of platforms.