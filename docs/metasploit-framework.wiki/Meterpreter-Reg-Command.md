This guide outlines how to use Meterpreter to manipulate the registry, similar to the `regedit.cmd` program on a Windows machine.

# Concepts

The Window's registry is used to store configuration settings for both the operating system, as well as software applications. This registry is hierarchical and stores keys and values. The registry keys are similar to folders, and registry values are similar to files. Each registry key should be unique and is separated by backslashes - similar to a Window's filepath.

## Root keys

Every registry key must start from one of the following root keys or abbreviations:

- `HKEY_LOCAL_MACHINE` or `HKLM`
- `HKEY_CURRENT_USER` or `HKCU`
- `HKEY_USERS` or `HKU`
- `HKEY_CLASSES_ROOT` or `HKCR`
- `HKEY_CURRENT_CONFIG` or `HKCC`
- `HKEY_PERFORMANCE_DATA` or `HKPD`
- `HKEY_DYN_DATA` or `HKDD`

## Value types

Each value also has an associated type, for example:

- `REG_NONE`
- `REG_BINARY`
- `REG_DWORD` / `REG_DWORD_LITTLE_ENDIAN` / `REG_DWORD_BIG_ENDIAN` - 32-bit number
- `REG_QWORD` / `REG_QWORD_LITTLE_ENDIAN` - 64-bit number
- `REG_SZ` - String value, terminated with a null byte
- `REG_EXPAND_SZ` - String value which contains unexpanded environment variables, i.e. `%APPDATA%`
- `REG_MULTI_SZ` - An array of strings. Each string is separated by a null byte, with a final trailing null byte. i.e. `line1\0line2\0\line3\0\0`

# Examples

All of these examples assume you are in a Meterpreter session. To see the latest help information run `help reg`:

```msf
meterpreter > help reg
Usage: reg [command] [options]
Interact with the target machine's registry.
```

## Common mistakes

### Escaping keys

Registry keys must be escaped correctly. Window's registry keys are escaped with backslashes. In msfconsole backslashes and spaces have a special meaning - which means you will need to escape these characters for your key to work as expected.

```msf
# Valid: Using single quotes around the registry key
meterpreter > reg enumkey -k 'HKCU\Keyboard Layout'

# Valid: Escaping the backslash and spaces within the registry key
meterpreter > reg enumkey -k HKCU\\Keyboard\ Layout

# Invalid examples: The user has not escaped backslashes or spaces correctly:
meterpreter > reg enumkey -k HKLM\SAM
meterpreter > reg enumkey -k HKCU\\Keyboard Layout
```

### 32/64 bit differences

The result of your registry queries can be impacted if you are interacting with a x86 or x64 Windows session.
You can see the type of session you currently have open with the `sessions` command:

```msf
msf6 exploit(windows/smb/psexec) > sessions

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ DESKTOP-N3MAG5R  192.168.123.1:4444 -> 192.168.123.141:58209 (192.168.123.141)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ DESKTOP-N3MAG5R  192.168.123.1:4433 -> 192.168.123.141:58263 (192.168.123.141)
```

For example - when interacting with a x86 session there are 12 keys listed:

```msf
# x86 Session
meterpreter > reg enumkey -k 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows'
Enumerating: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows

  Keys (12):
  # ... omitted for clarity ...
```

Versus a x64 session which shows 23 keys:

```msf
# x64 Session
meterpreter > reg enumkey -k 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows'
Enumerating: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows

  Keys (23):

  # ... omitted for clarity ...
```

If this is problematic either [[upgrade your session to Meterpreter|./Metasploit-Guide-Upgrading-Shells-to-Meterpreter.md]], or specify the `-w` flag which will impact the result of queries:

```msf
meterpreter > reg enumkey -k 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows' -w 32
Enumerating: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows

  Keys (12):
  # ... omitted for clarity ...
```

```msf
meterpreter > reg enumkey -k 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows' -w 64
Enumerating: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows

  Keys (23):

  # ... omitted for clarity ...
```

## Enumerate registry keys

Enumerate a root key:

```msf
meterpreter > reg enumkey -k HKLM
Enumerating: HKLM

  Keys (6):

        BCD00000000
        HARDWARE
        SAM
        SECURITY
        SOFTWARE
        SYSTEM
```

Enumerate a subkey:

```msf
meterpreter > reg enumkey -k 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Enumerating: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

  Values (2):

        SecurityHealth
        VMware User Process
```

## Query values

Display the registry value and type information:

```msf
meterpreter > reg queryval -k 'HKLM\Software\Microsoft\Windows NT\CurrentVersion' -v ProductName
Key: HKLM\Software\Microsoft\Windows NT\CurrentVersion
Name: ProductName
Type: REG_SZ
Data: Windows 10 Enterprise
```

Values that are of type `REG_SZ_EXPAND` such as ` %SystemRoot%\system32\drivers\GM.DLS` will not automatically be expanded:

```msf
meterpreter > reg queryval -k 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectMusic' -v 'GMFilePath'
Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectMusic
Name: GMFilePath
Type: REG_EXPAND_SZ
Data: C:\Windows\system32\drivers\GM.DLS
```

Values that are of type `REG_MULTI_SZ` will be separated by `\0`:

```msf
meterpreter > reg queryval -k 'HKLM\Software\example' -v 'example multi value with spaces'
Key: HKLM\Software\example
Name: example multi value with spaces
Type: REG_MULTI_SZ
Data: line1\0line2\0line3
```

### Creating a key

```msf
meterpreter > reg createkey -k 'HKLM\software\example'
Successfully created key: HKLM\software\example
```

### Setting a value

Setting a `REG_DWORD` - use a decimal value:

```msf
meterpreter > reg setval -k 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\system' -v LocalAccountTokenFilterPolicy -t REG_DWORD -d 1
Successfully set LocalAccountTokenFilterPolicy of REG_DWORD.
```

Setting a `REG_QWORD` - use a decimal value:

```msf
meterpreter > reg setval -k 'HKLM\Software\example' -t REG_DWORD -v qword_example -d 12345678
Successfully set example multi value with spaces of REG_MULTI_SZ.
```

Setting `REG_MULTI_SZ` - i.e. an array of strings:

```msf
meterpreter > reg setval -k 'HKLM\Software\example' -t REG_MULTI_SZ -v 'example multi value with spaces' -d 'line1\0line2\0line3'
Successfully set example multi value with spaces of REG_MULTI_SZ.
```

Setting `REG_BINARY` - use lowercase hexadecimal input without the preceding `0x`:

```msf
meterpreter > reg setval -k 'HKLM\Software\example' -t REG_BINARY -v binary_example -d deadbeef
Successfully set binary_example of REG_BINARY.
```

### Deleting a key

```msf
meterpreter > reg deletekey -k 'HKLM\software\example'
Successfully deleted key: HKLM\software\example
```

### Deleting a value

```msf
meterpreter > reg deleteval -k 'HKLM\software\example' -v 'example multi value with spaces'
Successfully deleted example multi value with spaces.
```
