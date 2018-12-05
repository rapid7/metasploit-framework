This module creates a mock print server which accepts print jobs.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/printjob_capture```
  3. Do: ```set MODE [mode]```
  4. Do: ```run```

## Options

  **FORWARD**

  After the print job is captured, should it be forwarded to another printer.  Default is `false`.

  **RPORT**

  If `forward` is set, this is the port of the remote printer to forward the print job to.  Default is `9100`.

  **RHOST**

  If `forward` is set, this is the IP of the remote printer to forward the print job to.

  **METADATA**

  If set to `true` the print job metadata will be printed to screen.  Default is `true`.

  **MODE**

  Set the printer mode.  RAW format, which typically runs on port `9100`, is a raw TCP data stream that would send to a printer.
  `LPR`, Line Printer remote, which typically runs on port 515, is the newer more widely accepted standard.  Default is `RAW`.

## Scenarios

### Capturing a RAW print job

Server:

```
msf5 > use auxiliary/server/capture/printjob_capture 
msf5 auxiliary(server/capture/printjob_capture) > run
[*] Auxiliary module running as background job 0.

[*] Starting Print Server on 0.0.0.0:9100 - RAW mode
[*] Started service listener on 0.0.0.0:9100 
[*] Server started.
msf5 auxiliary(server/capture/printjob_capture) > [*] Printjob Capture Service: Client connection from 127.0.0.1:44678
[*] Printjob Capture Service: Client 127.0.0.1:44678 closed connection after 249 bytes of data
[-] Unable to detect printjob type, dumping complete output
[+] Incoming printjob - Unnamed saved to loot
[+] Loot filename: /root/.msf4/loot/20181117205902_default_127.0.0.1_prn_snarf.unknow_003464.bin

msf5 auxiliary(server/capture/printjob_capture) > cat /root/.msf4/loot/20181117205902_default_127.0.0.1_prn_snarf.unknow_003464.bin
[*] exec: cat /root/.msf4/loot/20181117205902_default_127.0.0.1_prn_snarf.unknow_003464.bin

PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
ID=kali
VERSION="2018.4"
VERSION_ID="2018.4"
ID_LIKE=debian
ANSI_COLOR="1;31"
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
```

Client:

```
root@kali:~# cat /etc/os-release | nc 127.0.0.1 9100
^C
```
