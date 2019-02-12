## Intro

This module acts as a simple remote control for Belkin Wemo-enabled
Crock-Pots by implementing a subset of the functionality provided by the
Wemo App.

No vulnerabilities are exploited by this Metasploit module in any way.

## Setup

You may buy the device on Amazon at <https://www.amazon.com/dp/B00IPEO02C/>.

## Actions

```
Available actions:
  Name  Description
  ----  -----------
  Cook  Cook stuff
  Stop  Stop cooking
```

## Options

**TEMP**

Set this to the desired temperature for cooking. Valid values are `Off`,
`Warm`, `Low`, and `High`.

**TIME**

Set this to the desired cook time in full seconds.

**DefangedMode**

Set this to `false` to disable defanged mode and enable module
functionality. Set this only if you're SURE you want to proceed.

## Usage

```
msf5 auxiliary(admin/wemo/crockpot) > set rhosts [redacted]
rhosts => [redacted]
msf5 auxiliary(admin/wemo/crockpot) > set action Stop
action => Stop
msf5 auxiliary(admin/wemo/crockpot) > run

[*] Setting temperature to Off and cook time to 0s
[+] Cook time set to 0s
[*] Auxiliary module execution completed
msf5 auxiliary(admin/wemo/crockpot) >
```
