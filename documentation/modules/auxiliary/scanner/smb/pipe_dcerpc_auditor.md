## Description

The pipe_dcerpc_auditor scanner will return the DCERPC services that can be accessed via a SMB pipe.

## Verification Steps

1. Do: ```use auxiliary/scanner/smb/pipe_dcerpc_auditor```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

**Running the scanner**
```
msf > use auxiliary/scanner/smb/pipe_dcerpc_auditor
msf auxiliary(pipe_dcerpc_auditor) > show options

Module options:

   Name       Current Setting    Required  Description
   ----       ---------------    --------  -----------
   RHOSTS     192.168.1.150-160  yes       The target address range or CIDR identifier
   SMBDomain  WORKGROUP          no        The Windows domain to use for authentication
   SMBPIPE    BROWSER            yes       The pipe name to use (BROWSER)
   SMBPass                       no        The password for the specified username
   SMBUser                       no        The username to authenticate as
   THREADS    11                 yes       The number of concurrent threads

msf auxiliary(pipe_dcerpc_auditor) > set RHOSTS 192.168.1.150-160
RHOSTS => 192.168.1.150-160
msf auxiliary(pipe_dcerpc_auditor) > set THREADS 11
THREADS => 11
msf auxiliary(pipe_dcerpc_auditor) > run

The connection was refused by the remote host (192.168.1.153:139).
The connection was refused by the remote host (192.168.1.153:445).
192.168.1.160 - UUID 00000131-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.150 - UUID 00000131-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.160 - UUID 00000134-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.150 - UUID 00000134-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.150 - UUID 00000143-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.160 - UUID 00000143-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
...snip...
```