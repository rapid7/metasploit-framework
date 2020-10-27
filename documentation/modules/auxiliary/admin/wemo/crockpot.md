## Introduction

This module acts as a simple remote control for Belkin Wemo-enabled
Crock-Pots by implementing a subset of the functionality provided by the
Wemo App.

No vulnerabilities are exploited by this Metasploit module in any way.

## Setup

You may buy the device on Amazon at <https://www.amazon.com/dp/B00IPEO02C/>.

## Actions

```
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

Set this to the desired cook time in full minutes.

**DefangedMode**

Set this to `false` to disable defanged mode and enable module
functionality. Set this only if you're SURE you want to proceed.

## Usage

```
msf5 > use auxiliary/admin/wemo/crockpot
msf5 auxiliary(admin/wemo/crockpot) > set rhosts 10.22.22.1
rhosts => 10.22.22.1
msf5 auxiliary(admin/wemo/crockpot) > set temp High
temp => High
msf5 auxiliary(admin/wemo/crockpot) > set time 1
time => 1
msf5 auxiliary(admin/wemo/crockpot) > set defangedmode false
defangedmode => false
msf5 auxiliary(admin/wemo/crockpot) > set verbose true
verbose => true
msf5 auxiliary(admin/wemo/crockpot) > run

[+] Wemo-enabled Crock-Pot detected
[*] Cooking on High for 1m
[+] Cook time set to 1m
[*] Auxiliary module execution completed
msf5 auxiliary(admin/wemo/crockpot) >
```
