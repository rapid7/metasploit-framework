## Vulnerable Application

This module reads or writes a Windows registry security descriptor remotely.

In READ mode, the `FILE` option can be set to specify where the security
descriptor should be written to.

The following format is used:
```
key: <registry key>
security_info: <security information>
sd: <security descriptor as a hex string>
```

In WRITE mode, the `FILE` option can be used to specify the information needed
to write the security descriptor to the remote registry. The file must follow
the same format as described above.

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/admin/registry_security_descriptor`
1. Do: `run verbose=true rhost=<host> smbuser=<username> smbpass=<password> key=<registry key>`
1. **Verify** the registry key security descriptor is displayed
1. Do: `run verbose=true rhost=<host> smbuser=<username> smbpass=<password> key=<registry key> file=<file path>`
1. **Verify** the registry key security descriptor is saved to the file
1. Do: `run verbose=true rhost=<host> smbuser=<username> smbpass=<password> key=<registry key> action=write sd=<security descriptor as a hex string>`
1. **Verify** the security descriptor is correctly set on the given registry key
1. Do: `run verbose=true rhost=<host> smbuser=<username> smbpass=<password> file=<file path>`
1. **Verify** the security descriptor taken from the file is correctly set on the given registry key

## Options

### KEY
Registry key to read or write.

### SD
Security Descriptor to write as a hex string.

### SECURITY_INFORMATION
Security Information to read or write (see
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/23e75ca3-98fd-4396-84e5-86cd9d40d343
(default: OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).

### FILE
File path to store the security descriptor when reading or source file path used to write the security descriptor when writing


## Scenarios

### Read against Windows Server 2019

```
msf6 auxiliary(admin/registry_security_descriptor) > run verbose=true rhost=192.168.101.124 smbuser=Administrator smbpass=123456 action=READ key='HKLM\SECURITY\Policy\PolEKList'
[*] Running module against 192.168.101.124

[+] 192.168.101.124:445 - Raw security descriptor for HKLM\SECURITY\Policy\PolEKList: 01000480480000005800000000000000140000000200340002000000000214003f000f0001010000000000051200000000021800000006000102000000000005200000002002000001020000000000052000000020020000010100000000000512000000
[*] Auxiliary module execution completed
```

### Write against Windows Server 2019
Note that the information security has been set to 4 (DACL_SECURITY_INFORMATION) to avoid an access denied error.

```
msf6 auxiliary(admin/registry_security_descriptor) > run verbose=true rhost=192.168.101.124 smbuser=Administrator smbpass=123456 key='HKLM\SECURITY\Policy\PolEKList' action=WRITE sd=01000480480000005800000000000000140000000200340002000000000214003f000f0001010000000000051200000000021800000006000102000000000005200000002002000001020000000000052000000020020000010100000000000512000000 security_information=4
[*] Running module against 192.168.101.124

[+] 192.168.101.124:445 - Security descriptor set for HKLM\SECURITY\Policy\PolEKList
[*] Auxiliary module execution completed
```

### Write against Windows Server 2019 (from file)

```
msf6 auxiliary(admin/registry_security_descriptor) > run verbose=true rhost=192.168.101.124 smbuser=Administrator smbpass=123456 action=WRITE file=/tmp/remote_registry_sd_backup.yml
[*] Running module against 192.168.101.124

[*] 192.168.101.124:445 - Getting security descriptor info from file /tmp/remote_registry_sd_backup.yml
  key: HKLM\SECURITY\Policy\PolEKList
  security information: 4
  security descriptor: 01000480480000005800000000000000140000000200340002000000000214003f000f0001010000000000051200000000021800000006000102000000000005200000002002000001020000000000052000000020020000010100000000000512000000
[+] 192.168.101.124:445 - Security descriptor set for HKLM\SECURITY\Policy\PolEKList
[*] Auxiliary module execution completed
```
