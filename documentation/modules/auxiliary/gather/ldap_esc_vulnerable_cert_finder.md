## Vulnerable Application
The `auxiliary/gather/ldap_esc_vulnerable_cert_finder` module allows users to query a LDAP server for vulnerable certificate
templates and will print these certificates out in a table along with which
attack they are vulnerable to and the SIDs that can be used to enroll in that
certificate template.

Additionally the module will also print out a list of known certificate servers
along with info about which vulnerable certificate templates the certificate server
allows enrollment in and which SIDs are authorized to use that certificate server to
perform this enrollment operation.

Currently the module is capable of checking for ESC1, ESC2, and ESC3 vulnerable certificates.

### Installing AD CS
1. Install AD CS on either a new or existing domain controller
1. Open the Server Manager
1. Select Add roles and features
1. Select "Active Directory Certificate Services" under the "Server Roles" section
1. When prompted add all of the features and management tools
1. On the AD CS "Role Services" tab, leave the default selection of only "Certificate Authority"
1. Completion the installation and reboot the server
1. Reopen the Server Manager
1. Go to the AD CS tab and where it says "Configuration Required", hit "More" then "Configure Active Directory Certificate..."
1. Select "Certificate Authority" in the Role Services tab
1. Keep all of the default settings, noting the "Common name for this CA" value on the "CA Name" tab.
1. Accept the rest of the default settings and complete the configuration

### Setting up a ESC1 Vulnerable Certificate Template
1. Open up the run prompt and type in `certsrv`.
1. In the window that appears you should see your list of certification authorities under `Certification Authority (Local)`.
1. Right click on the folder in the drop down marked `Certificate Templates` and then click `Manage`.
1. Scroll down to the `User` certificate. Right click on it and select `Duplicate Template`.
1. From here you can refer to https://github.com/RayRRT/Active-Directory-Certificate-Services-abuse/blob/3da1d59f1b66dd0e381b2371b8fb42d87e2c9f82/ADCS.md for screenshots.
1. Select the `General` tab and rename this to something meaningful like `ESC1-Template`, then click the `Apply` button.
1. In the `Subject Name` tab, select `Supply in the request` and click `Ok` on the security warning that appears.
1. Click the `Apply` button.
1. Scroll to the `Extensions` tab.
1. Under `Application Policies` ensure that `Client Authentication`, `Server Authentication`, `KDC Authentication`, or `Smart Card Logon` is listed.
1. Click the `Apply` button.
1. Under the `Security` tab make sure that `Domain Users` group listed and the `Enroll` permissions is marked as allowed for this group.
1. Under `Issuance Requirements` tab, ensure that under `Require the following for enrollment` that the `CA certificate manager approval` box is unticked, as is the `This number of authorized signatures` box.
1. Click `Apply` and then `Ok`
1. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
1. Scroll down and select the `ESC1-Template` certificate, or whatever you named the ESC1 template you created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC2 Vulnerable Certificate Template
1. Open up `certsrv`
1. Scroll down to `Certificate Templates` folder, right click on it and select `Manage`.
1. Find the `ESC1` certificate template you created earlier and right click on that, then select `Duplicate Template`.
1. Select the `General` tab, and then name the template `ESC2-Template`. Then click `Apply`.
1. Go to the `Subject Name` tab and select `Build from this Active Directory Information` and select `Fully distinguished name` under the `Subject Name Format`. The main idea of setting this option is to prevent being able to supply the subject name in the request as this is more what makes the certificate vulnerable to ESC1. The specific options here I don't think will matter so much so long as the `Supply in the request` option isn't ticked. Then click `Apply`.
1. Go the to `Extensions` tab and click on `Application Policies`. Then click on `Edit`.
1. Delete all the existing application policies by clicking on them one by one and clicking the `Remove` button.
1. Click the `Add` button and select `Any Purpose` from the list that appears. Then click the `OK` button.
1. Click the `Apply` button, and then `OK`. The certificate should now be created.
1. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
1. Scroll down and select the `ESC2-Template` certificate, or whatever you named the ESC2 template you created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC3 Template 1 Vulnerable Certificate Template
1. Follow the instructions above to duplicate the ESC2 template and name it `ESC3-Template1`, then click `Apply`.
1. Go to the `Extensions` tab, click the Application Policies entry, click the `Edit` button, and remove the `Any Purpose` policy and replace it with `Certificate Request Agent`, then click `OK`.
1. Click `Apply`.
1. Go to `Issuance Requirements` tab and double check that both `CA certificate manager approval` and `This number of authorized signatures` are unchecked.
1. Click `Apply` if any changes were made or the button is not grey'd out, then click `OK` to create the certificate.
1. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
1. Scroll down and select the `ESC3-Template1` certificate, or whatever you named the ESC3 template number 1 template you just created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC3 Template 2 Vulnerable Certificate Template
1. Follow the instructions above to duplicate the ESC2 template and name it `ESC3-Template2`, then click `Apply`.
1. Go to the `Extensions` tab, click the Application Policies entry, click the `Edit` button, and remove the `Any Purpose` policy and replace it with `Client Authentication`, then click `OK`.
1. Click `Apply`.
1. Go to `Issuance Requirements` tab and double check that both `CA certificate manager approval` is unchecked.
1. Check the `This number of authorized signatures` checkbox and ensure the value specified is 1, and that the `Policy type required in signature` is set to `Application Policy`, and that the `Application policy` value is `Certificate Request Agent`.
1. Click `Apply` and then click `OK` to issue the certificate.
1. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder.
1. Click `New` followed by `Certificate Template to Issue`.
1. Scroll down and select the `ESC3-Template2` certificate, and select `OK`.
1. The certificate should now be available to be issued by the CA server.

## Module usage

1. Do: Start msfconsole
1. Do: `use auxiliary/gather/ldap_esc_vulnerable_cert_finder`
1. Do: `set BIND_DN <DOMAIN>\\<USERNAME to log in as>`
1. Do: `set BIND_PW <PASSWORD FOR USER>`
1. Do: `set RHOSTS <target IP(s)>`
1. Optional: `set RPORT <target port>` if target port is non-default.
1. Optional: `set SSL true` if the target port is SSL enabled.
1. Do: `run`

## Options

### REPORT_NONENROLLABLE
If set to `True` then report any certificate templates that are vulnerable but which are not known to be enrollable.
If set to `False` then skip over these certificate templates and only report on certificate templates
that are both vulnerable and enrollable.

## Scenarios

### Windows Server 2022 with AD CS
```msf
msf6 > use auxiliary/gather/ldap_esc_vulnerable_cert_finder
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > set RHOST 172.26.104.157
RHOST => 172.26.104.157
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > set BIND_DN DAFOREST\\Administrator
BIND_DN => DAFOREST\Administrator
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > set BIND_PW theAdmin123
BIND_PW => theAdmin123
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > show options

Module options (auxiliary/gather/ldap_esc_vulnerable_cert_finder):

   Name                  Current Setting         Required  Description
   ----                  ---------------         --------  -----------
   BASE_DN                                       no        LDAP base DN if you already have it
   BIND_DN               DAFOREST\Administrator  no        The username to authenticate to LDAP server
   BIND_PW               theAdmin123             no        Password for the BIND_DN
   REPORT_NONENROLLABLE  false                   yes       Report nonenrollable certificate templates
   RHOSTS                172.26.104.157          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT                 389                     yes       The target port
   SSL                   false                   no        Enable SSL on the LDAP connection

msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > run
[*] Running module against 172.26.104.157

[*] Discovering base DN automatically
[+] 172.26.104.157:389 Discovered base DN: DC=daforest,DC=com
[*] Template: SubCA
[*]    Distinguished Name: CN=SubCA,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC1, ESC2, ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: ESC1-Template
[*]    Distinguished Name: CN=ESC1-Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC1
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: ESC2-Template
[*]    Distinguished Name: CN=ESC2-Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: ESC3-Template1
[*]    Distinguished Name: CN=ESC3-Template1,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_1
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: User
[*]    Distinguished Name: CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: Administrator
[*]    Distinguished Name: CN=Administrator,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: Machine
[*]    Distinguished Name: CN=Machine,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-515 (Domain Computers)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: DomainController
[*]    Distinguished Name: CN=DomainController,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-498 (Enterprise Read-only Domain Controllers)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-516 (Domain Controllers)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]       * S-1-5-9 (Enterprise Domain Controllers)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: ESC3-Template2
[*]    Distinguished Name: CN=ESC3-Template2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) >
```

### Windows Server 2022 with AD CS and REPORT_NONENROLLABLE Set To TRUE
```msf
msf6 > use auxiliary/gather/ldap_esc_vulnerable_cert_finder
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > set RHOST 172.26.104.157
RHOST => 172.26.104.157
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > set BIND_DN DAFOREST\\Administrator
BIND_DN => DAFOREST\Administrator
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > set BIND_PW theAdmin123
BIND_PW => theAdmin123
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > set REPORT_NONENROLLABLE true
REPORT_NONENROLLABLE => true
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > show options

Module options (auxiliary/gather/ldap_esc_vulnerable_cert_finder):

   Name                  Current Setting         Required  Description
   ----                  ---------------         --------  -----------
   BASE_DN                                       no        LDAP base DN if you already have it
   BIND_DN               DAFOREST\Administrator  no        The username to authenticate to LDAP server
   BIND_PW               theAdmin123             no        Password for the BIND_DN
   REPORT_NONENROLLABLE  true                    yes       Report nonenrollable certificate templates
   RHOSTS                172.26.104.157          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT                 389                     yes       The target port
   SSL                   false                   no        Enable SSL on the LDAP connection

msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) > run
[*] Running module against 172.26.104.157

[*] Discovering base DN automatically
[+] 172.26.104.157:389 Discovered base DN: DC=daforest,DC=com
[*] Template: CA
[*]    Distinguished Name: CN=CA,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC1, ESC2, ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    CA not published as an enrollable certificate!
[*] Template: SubCA
[*]    Distinguished Name: CN=SubCA,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC1, ESC2, ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: OfflineRouter
[*]    Distinguished Name: CN=OfflineRouter,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC1, ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    OfflineRouter not published as an enrollable certificate!
[*] Template: ESC1-Template
[*]    Distinguished Name: CN=ESC1-Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC1
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: ESC2-Template
[*]    Distinguished Name: CN=ESC2-Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: EnrollmentAgent
[*]    Distinguished Name: CN=EnrollmentAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_1
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    EnrollmentAgent not published as an enrollable certificate!
[*] Template: EnrollmentAgentOffline
[*]    Distinguished Name: CN=EnrollmentAgentOffline,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_1
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    EnrollmentAgentOffline not published as an enrollable certificate!
[*] Template: MachineEnrollmentAgent
[*]    Distinguished Name: CN=MachineEnrollmentAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_1
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    MachineEnrollmentAgent not published as an enrollable certificate!
[*] Template: CEPEncryption
[*]    Distinguished Name: CN=CEPEncryption,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_1
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    CEPEncryption not published as an enrollable certificate!
[*] Template: ESC3-Template1
[*]    Distinguished Name: CN=ESC3-Template1,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_1
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: User
[*]    Distinguished Name: CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: UserSignature
[*]    Distinguished Name: CN=UserSignature,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    UserSignature not published as an enrollable certificate!
[*] Template: SmartcardUser
[*]    Distinguished Name: CN=SmartcardUser,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    SmartcardUser not published as an enrollable certificate!
[*] Template: ClientAuth
[*]    Distinguished Name: CN=ClientAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    ClientAuth not published as an enrollable certificate!
[*] Template: SmartcardLogon
[*]    Distinguished Name: CN=SmartcardLogon,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[!]    SmartcardLogon not published as an enrollable certificate!
[*] Template: Administrator
[*]    Distinguished Name: CN=Administrator,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: Machine
[*]    Distinguished Name: CN=Machine,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-515 (Domain Computers)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: DomainController
[*]    Distinguished Name: CN=DomainController,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-498 (Enterprise Read-only Domain Controllers)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-516 (Domain Controllers)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]       * S-1-5-9 (Enterprise Domain Controllers)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Template: ESC3-Template2
[*]    Distinguished Name: CN=ESC3-Template2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=daforest,DC=com
[*]    Vulnerable to: ESC3_TEMPLATE_2
[*]    Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3290009963-1772292745-3260174523-512 (Domain Admins)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-513 (Domain Users)
[*]       * S-1-5-21-3290009963-1772292745-3260174523-519 (Enterprise Admins)
[*]    Issuing CAs:
[*]       * daforest-WIN-BR0CCBA815B-CA
[*]          Server: WIN-BR0CCBA815B.daforest.com
[*]          Enrollment SIDs:
[*]             * S-1-5-11 (Authenticated Users)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_esc_vulnerable_cert_finder) >
```
