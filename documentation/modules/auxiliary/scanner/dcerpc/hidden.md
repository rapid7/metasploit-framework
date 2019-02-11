## Description

The hidden scanner connects to a given range of IP addresses and tries to locate any RPC services that are not listed in the Endpoint Mapper and determines if anonymous access to the service is allowed.

## Verification Steps

1. Do: ```use auxiliary/scanner/dcerpc/hidden```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/dcerpc/hidden
msf auxiliary(hidden) > set RHOSTS 192.168.1.200-254
RHOSTS => 192.168.1.200-254
msf auxiliary(hidden) > set THREADS 55
THREADS => 55
msf auxiliary(hidden) > run

[*] Connecting to the endpoint mapper service...
[*] Connecting to the endpoint mapper service...
[*] Connecting to the endpoint mapper service...
...snip...
[*] Connecting to the endpoint mapper service...
[*] Connecting to the endpoint mapper service...
[*] Could not obtain the endpoint list: DCERPC FAULT => nca_s_fault_access_denied
[*] Could not contact the endpoint mapper on 192.168.1.203
[*] Could not obtain the endpoint list: DCERPC FAULT => nca_s_fault_access_denied
[*] Could not contact the endpoint mapper on 192.168.1.201
[*] Could not connect to the endpoint mapper service
[*] Could not contact the endpoint mapper on 192.168.1.250
[*] Looking for services on 192.168.1.204:1025...
[*] 	HIDDEN: UUID 12345778-1234-abcd-ef00-0123456789ab v0.0
[*] Looking for services on 192.168.1.202:49152...
[*] 		CONN BIND CALL ERROR=DCERPC FAULT => nca_s_fault_ndr 
[*] 
[*] 	HIDDEN: UUID c681d488-d850-11d0-8c52-00c04fd90f7e v1.0
[*] 		CONN BIND CALL ERROR=DCERPC FAULT => nca_s_fault_ndr 
[*] 
[*] 	HIDDEN: UUID 11220835-5b26-4d94-ae86-c3e475a809de v1.0
[*] 		CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 
[*] 	HIDDEN: UUID 5cbe92cb-f4be-45c9-9fc9-33e73e557b20 v1.0
[*] 		CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 
[*] 	HIDDEN: UUID 3919286a-b10c-11d0-9ba8-00c04fd92ef5 v0.0
[*] 		CONN BIND CALL DATA=0000000057000000 
[*] 
[*] 	HIDDEN: UUID 1cbcad78-df0b-4934-b558-87839ea501c9 v0.0
[*] 		CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 
[*] 	HIDDEN: UUID c9378ff1-16f7-11d0-a0b2-00aa0061426a v1.0
[*] 		CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 
[*] Remote Management Interface Error: The connection timed out (192.168.1.202:49152).
...snip...
[*] Scanned 55 of 55 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(hidden) >
```
