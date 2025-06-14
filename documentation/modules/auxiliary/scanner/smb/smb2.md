## Description

The SMB2 scanner module simply scans the remote hosts and determines if they support the SMB2 protocol.

## Verification Steps

1. Do: ```use auxiliary/scanner/smb/smb2```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/smb/smb2
msf auxiliary(smb2) > set RHOSTS 192.168.1.150-165
RHOSTS => 192.168.1.150-165
msf auxiliary(smb2) > set THREADS 16
THREADS => 16
msf auxiliary(smb2) > run

[*] 192.168.1.162 supports SMB 2 [dialect 255.2] and has been online for 618 hours
[*] Scanned 06 of 16 hosts (037% complete)
[*] Scanned 13 of 16 hosts (081% complete)
[*] Scanned 14 of 16 hosts (087% complete)
[*] Scanned 16 of 16 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(smb2) >
```
