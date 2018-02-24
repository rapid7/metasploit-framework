## Description

The dcerpc/management module scans a range of IP addresses and obtains information from the Remote Management interface of the DCERPC service.

## Verification Steps

1. Do: ```use auxiliary/scanner/dcerpc/management```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

### Example Windows 2003, and Windows 7 Targets

```
msf > use auxiliary/scanner/dcerpc/management
msf auxiliary(management) > set RHOSTS 192.168.1.200-254
RHOSTS => 192.168.1.200-254
msf auxiliary(management) > set THREADS 55
THREADS => 55
msf auxiliary(management) > run

[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_access_denied
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_access_denied
[*] UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_access_denied
[*] Remote Management Interface Error: The connection was refused by the remote host (192.168.1.250:135).
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID 0b0a6584-9e0f-11cf-a3cf-00805f68cb1b v1.1
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID 1d55b526-c137-46c5-ab79-638f2a68e869 v1.0
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID e60c73e6-88f9-11cf-9af1-0020af6e72f4 v2.0
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID 99fcfec4-5260-101b-bbcb-00aa0021347a v0.0
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID b9e79e60-3d52-11ce-aaa1-00006901293f v0.2
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID 412f241e-c12a-11ce-abff-0020af6e7a17 v0.2
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID 00000136-0000-0000-c000-000000000046 v0.0
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID c6f3ee72-ce7e-11d1-b71e-00c04fc3111a v1.0
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57 v0.0
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
[*] UUID 000001a0-0000-0000-c000-000000000046 v0.0
[*] Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 	 listening: 00000000
[*] 	 killed: 00000005
[*] 	 name: 00010000000000000100000000000000d3060000
...snip...
[*] Scanned 55 of 55 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(management) >
```
