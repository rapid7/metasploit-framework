## Description

The dcerpc/tcp_dcerpc_auditor module scans a range of IP addresses to determine what DCERPC services are available over a TCP port.

## Verification Steps

1. Do: ```use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

### Example Windows 2003, and Windows 7 Targets

```
msf > use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
msf auxiliary(tcp_dcerpc_auditor) > set RHOSTS 192.168.1.200-254
RHOSTS => 192.168.1.200-254
msf auxiliary(tcp_dcerpc_auditor) > set THREADS 55
THREADS => 55
msf auxiliary(tcp_dcerpc_auditor) > run

The connection was refused by the remote host (192.168.1.250:135).
The host (192.168.1.210:135) was unreachable.
...snip...
The host (192.168.1.200:135) was unreachable.
[*] Scanned 38 of 55 hosts (069% complete)
...snip...
The host (192.168.1.246:135) was unreachable.
192.168.1.203 - UUID 99fcfec4-5260-101b-bbcb-00aa0021347a 0.0 OPEN VIA 135 ACCESS GRANTED 00000000000000000000000000000000000000000000000005000000
192.168.1.201 - UUID 99fcfec4-5260-101b-bbcb-00aa0021347a 0.0 OPEN VIA 135 ACCESS GRANTED 00000000000000000000000000000000000000000000000005000000
192.168.1.204 - UUID 99fcfec4-5260-101b-bbcb-00aa0021347a 0.0 OPEN VIA 135 ACCESS GRANTED 00000000000000000000000000000000000000000000000076070000
192.168.1.202 - UUID 99fcfec4-5260-101b-bbcb-00aa0021347a 0.0 OPEN VIA 135 ACCESS GRANTED 00000000000000000000000000000000000000000000000005000000
192.168.1.204 - UUID afa8bd80-7d8a-11c9-bef4-08002b102989 1.0 OPEN VIA 135 ACCESS GRANTED 000002000b0000000b00000004000200080002000c0002001000020014000200180002001c0002002000020024000200280002002c0002000883afe11f5dc91191a408002b14a0fa0300000084650a0b0f9ecf11a3cf00805f68cb1b0100010026b5551d37c1c546ab79638f2a68e86901000000e6730ce6f988cf119af10020af6e72f402000000c4fefc9960521b10bbcb00aa0021347a00000000609ee7b9523dce11aaa100006901293f000002001e242f412ac1ce11abff0020af6e7a17000002003601000000000000c0000000000000460000000072eef3c67eced111b71e00c04fc3111a01000000b84a9f4d1c7dcf11861e0020af6e7c5700000000a001000000000000c0000000000000460000000000000000
192.168.1.204 - UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa 3.0 OPEN VIA 135 ACCESS GRANTED d8060000
[*] Scanned 52 of 55 hosts (094% complete)
[*] Scanned 54 of 55 hosts (098% complete)
The connection timed out (192.168.1.205:135).
[*] Scanned 55 of 55 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(tcp_dcerpc_auditor) >
```
