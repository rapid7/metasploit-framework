## Vulnerable Application

This module prints information about a given SID from the perspective
of this session.


## Verification Steps

1. Start msfconsole
1. Get a session on a Windows host
1. Do: `use post/windows/gather/resolve_sid`
1. Do: `set session [#]`
1. Do: `run`
1. You should receive user SID information


## Options

### SID

SID to lookup.

### SYSTEM_NAME

Where to search. If undefined, first local then trusted DCs.


## Scenarios

### Windows 2008 SP1 DC

```
msf6 > use post/windows/gather/resolve_sid
msf6 post(windows/gather/resolve_sid) > set sid S-1-5-32-544
sid => S-1-5-32-544
msf6 post(windows/gather/resolve_sid) > set session 1
session => 1
msf6 post(windows/gather/resolve_sid) > run

[*] SID Type: alias
[*] Name:     Administrators
[*] Domain:   BUILTIN
[*] Post module execution completed
```
