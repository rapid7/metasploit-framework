## Vulnerable Application
The `auxiliary/gather/ldap_esc_vulnerable_cert_finder` module allows users to query a LDAP server for vulnerable certificate
templates and will print these certificates out in a table along with which
attack they are vulnerable to and the SIDs that can be used to enroll in that
certificate template.

Additionally the module will also print out a list of known certificate servers
along with info about which vulnerable certificate templates the certificate server
allows enrollment in and which SIDs are authorized to use that certificate server to
perform this enrollment operation.

Currently the module is capable of checking for certificates that are vulnerable to ESC1, ESC2, ESC3, ESC13,
and ESC15. The module is limited to checking for these techniques due to them being identifiable remotely from
a normal user account by analyzing the objects in LDAP.

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

### Setting up a ESC4 Vulnerable Certificate Template
1. Follow the instructions above to duplicate the ESC2 template and name it `ESC4-Template`, then click `Apply`.
1. Go to the `Security` tab.
1. Under `Groups or usernames` select `Authenticated Users`
1. Under `Permissions for Authenticated Users` select `Write` -> `Allow`.
1. Click `Apply` and then click `OK` to issue the certificate.
1. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder.
1. Click `New` followed by `Certificate Template to Issue`.
1. Scroll down and select the `ESC3-Template2` certificate, and select `OK`.
1. The certificate should now be available to be issued by the CA server.

### Setting up a ESC8 Vulnerable Host
1. Follow instructions for creating an AD CS enabled server
1. Select Add Roles and Features
1. Under "Select Server Roles" expand Active Directory Certificate Services and add `Certificate Enrollment Policy Web Service`, `Certificate Enrollment Web Service`, and `Certificate Authority Web Enrollment`.
1. For each selection, accept the default for any pop-up.
1. Accept the default features and install.
1. When the installation is complete, click on the warning in the Dashboard for post-deployment configuration.
1. Under Credentials, accept the default
1. Under Role Services, select `Certificate Authority Web Enrollment`, `Certificate Enrollment Web Service`, and `Certificate Enrollment Policy Web Service`
1. In CA for CES, accept the defaults
1. In Authentication Types, accept the default integrated authentication
1. In Service account for CES, select `Use built-in application pool identity`
1. Accept default integrated authentication for CEP
1. Select the domain certificate in Server Certificate (the one that starts with the domain name by default) if more than one appears.
1. Accept the remaining defaults.

### Setting up a ESC9 Vulnerable Certificate Template
1. Open up the run prompt and type in `certsrv`.
1. In the window that appears you should see your list of certification authorities under `Certification Authority (Local)`.
1. Right click on the folder in the drop down marked `Certificate Templates` and then click `Manage`.
1. Scroll down to the `User` certificate. Right click on it and select `Duplicate Template`.
1. The `User` certificate already has the `Client Authentication` EKU enabled so we can use this as a base template.
1. Select the Subject Name tab and select `Build from this Active Directory Information`, under the `Subject Name Format` section select `User Principal Name (UPN)` (or `DNS Name` depending on what scenario you're attempting to exploit).
1. Under the `Subject Name Format` also be sure to unselect `Include e-mail name in subject name` and `E-mail name`.
1. Select the `General` tab and rename this to something meaningful like `ESC9-Template`, then click the `Apply` button.
1. Select the Security tab and click the `Add` button.
1. Enter `user2` (or whatever user's UPN you will be changing for this attack). Click OK.
1. Under Permissions for `user2` select `Allow` for `Enroll` and `Read`.
1. Click `Apply` and then `OK`.
1. Open Active Directory Users and Computers, expand the domain on the left hand side.
1. Enable advanced features to access the security tab by checking "View" > "Advanced Features"
1. Right click `Users` and navigate `user2` and select `Properties`.
1. In the security tab, select `Add` and enter `user1` (or whatever user you will be using to perform the attack). Click OK.
1. Under Permissions for `user1` select `Allow` for `Read` and `Write` (or select `Allow` for `Full Control`).
1. Open a Powershell prompt as Administrator and run the following (change `kerberos.issue` to your domain name):
```powershell
$template = [ADSI]"LDAP://CN=ESC9-Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=kerberos,DC=issue"
$template.Put("msPKI-Enrollment-Flag", 0x80000)
$template.SetInfo()
```
#### Configuring Windows to be Vulnerable to ESC9
1. The template should now be reported as `Potentially Vulnerable` by the module.
1. In order to be able to exploit this template run the following Powershell command and ensure `StrongCertificateBindingEnforcement` is not set to `2` (it should be 1, or 0):
```powershell
Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\Kdc\" -Name StrongCertificateBindingEnforcement -Value 1
Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\Kdc\" -Name StrongCertificateBindingEnforcement
```

### Setting up a ESC10 Vulnerable Certificate Template
1. Follow the first 15 steps `Setting up a ESC9 Vulnerable Certificate Template` to create the `ESC10-Template`.
    1. Everything up to and excluding the `msPKI-Enrollment-Flag", 0x80000` powershell step.
#### Configuring Windows to be Vulnerable to ESC10
1. The template should now be reported as `Potentially Vulnerable` by the module.
##### ESC10 Case1:
1. In order to be able to exploit this template run the following Powershell command and ensure `StrongCertificateBindingEnforcement` is set to `0`
```powershell
Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\Kdc\" -Name StrongCertificateBindingEnforcement -Value 0
Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\Kdc\" -Name StrongCertificateBindingEnforcement
```
##### ESC10 Case2:
1. In order to be able to exploit this template run the following Powershell command and ensure `CertificateMappingMethods` is set to `0x4`
```powershell
Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\" -Name CertificateMappingMethods -Value 4
Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\" -Name CertificateMappingMethods
```

### Setting up a ESC13 Vulnerable Certificate Template
1. Follow the instructions above to duplicate the ESC2 template and name it `ESC13`, then click `Apply`.
1. Go to the `Extensions` tab, click the Issuance Policies entry, click the `Add` button, click the `New...` button.
1. Name the new issuance policy `ESC13-Issuance-Policy`.
4. Copy the Object Identifier as this will be needed later (ex: 11.3.6.1.4.1.311.21.8.12682474.6065318.6963902.6406785.3291287.83.1172775.12545198`).
1. Leave the CPS location field blank.
1. Click `Apply`.
1. Open Active Directory Users and Computers, expand the domain on the left hand side.
1. Right click `Users` and navigate to New -> Group.
1. Enter `ESC13-Group` for the Group Name.
1. Select `Universal` for Group scope and `Security` for Group type.
1. Click `Apply`.
1. Open ADSI Edit.
1. In the left hand side right click `ADSI Edit` and select `Connect to...`.
1. Under `Select a well known naming context` select `Default naming context`.
1. Select the newly established connection, select the domain, select `CN=User`.
1. On the right hand side find the recently created security group `CN=ESC13-Group`, right click select properties.
1. Copy the value of the `distinguishedName` attribute, save this as we'll need it later.
1. Back on the left hand side establish another connection, right click `ADSI Edit` and select `Connect to...`.
1. This time under `Select a well known naming context` select `Configuration`.
1. Select the newly established connection, select the domain, select `CN=Services` -> `CN=Public Key Services` -> `CN=OID`.
1. In the right hand side find the object that corresponds to the Object Identifier saved earlier.
1. The OID saved earlier ended in `12545198`, the object on the right will start with `CN=12545198.` followed by 34 hex characters. ex: `CN=12545198.7BCA239924D9515E63EA6B6F00748837`).
1. Once located right click -> properties, select `msDS-OIDToGroupLink`.
1. Paste the `distingushedName` of the security group saved above (ex: `CN=ESC13-Group,CN=Users,DC=demo,DC=lab`).
1. Click `Apply`.
1. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder.
1. Click `New` followed by `Certificate Template to Issue`.
1. Scroll down and select the `ESC13-Template` certificate, and select `OK`.
1. The certificate should now be available to be issued by the CA server.

### Setting up a ESC15 Vulnerable Certificate Template
1. ESC15 depends on the schema version of the template being version 1 - which can no longer be created so we will edit an existing template that is schema version 1.
1. Right click the `WebServer` template, select properties.
1. Go to the Security Tab.
1. Under `Groups or usernames` select `Authenticated Users`.
1. Under `Permissions for Authenticated Users` select `Enroll` -> `Allow`.
1. Click Apply.
1. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder and ensure `WebServer` is listed, if it's not, add it.
1. The certificate should now be available to be issued by the CA server.

### Setting up a ESC16 Vulnerable Certificate Template
#### Configuring Windows to be Vulnerable to ESC16
1. There are two ECS16 scenarios and both depend on the CA having the OID: `1.3.6.1.4.1.311.25.2` being present in its `policy\DisableExtensionList`
1. Run the following Powershell snippet to add the OID to the `DisableExtensionList` if it is not already present:
```powershell
$activePolicyName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\*\PolicyModules" -Name "Active" | Select-Object -ExpandProperty Active
$disableExtensionList = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\*\PolicyModules\$activePolicyName" -Name "DisableExtensionList" | Select-Object -ExpandProperty DisableExtensionList

if (-not ($disableExtensionList -contains "1.3.6.1.4.1.311.25.2")) {
    $updatedList = $disableExtensionList + @("1.3.6.1.4.1.311.25.2")
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\*\PolicyModules\$activePolicyName" -Name "DisableExtensionList" -Value $updatedList
    Write-Output "OID 1.3.6.1.4.1.311.25.2 has been added to the DisableExtensionList."
} else {
    Write-Output "OID 1.3.6.1.4.1.311.25.2 is already present in the DisableExtensionList."
}
```
#### ESC16 Scenario 1
When a CA has the OID `1.3.6.1.4.1.311.25.2` added to its `policy\DisableExtensionList` registry setting every certificate issued by this CA will lack this SID security extension.
This effectively makes all templates published by this CA behave as if they were individually configured with the `CT_FLAG_NO_SECURITY_EXTENSION` flag (as seen in ESC9).
So if `StrongCertificateBindingEnforcement` is not set to `2` we can exploit this weak mapping.

In order to create a template vulnerable to ESC16 scenario 1, follow the first 15 steps in `Setting up a ESC9 Vulnerable Certificate Template`,
which is all the steps up to and excluding the `msPKI-Enrollment-Flag", 0x80000` powershell step which is how you set the `CT_FLAG_NO_SECURITY_EXTENSION`.
Ensure that `StrongCertificateBindingEnforcement` is set to `0` or `1` (not `2`) by running the following command listed in `Configuring Windows to be Vulnerable to ESC9`

#### ESC16 Scenario 2
When a CA has the OID `1.3.6.1.4.1.311.25.2` added to its `policy\DisableExtensionList` and `StrongCertificateBindingEnforcement` is set to `2`, there is still a way to exploit the template.
If the policy module's `EditFlags` has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set (which is essentially ESC6), then the template is vulnerable to ESC16 scenario 2.

Ensure the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is set by running following PowerShell command:
```powershell
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Then restart the Certificate Services service:
```powershell
net stop certsvc
net start certsvc
```

Then vefify the flag is set by running:
```powershell
certutil -getreg policy\EditFlags
```

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

### REPORT
What templates to report (applies filtering to results).

* **all** - Report all certificate templates.
* **published** - Report certificate templates that are published by at least one CA server.
* **enrollable** - Same as above, but omits templates that the user does not have permissions to enroll in.
* **vulnerable** - Report certificate templates where at least one misconfiguration is appears to be present.
* **vulnerable-and-published** - Same as above, but omits templates that are not published by at least one CA server.
* **vulnerable-and-enrollable** - Same as above, but omits templates that the user does not have permissions to enroll in.

## Scenarios

### Windows Server 2022 with AD CS
```msf
msf auxiliary(gather/ldap_esc_vulnerable_cert_finder) > run
[*] Running module against 192.168.159.10

[*] Discovering base DN automatically
[!] Couldn't find any vulnerable ESC13 templates!
[+] Template: ESC1-Test
[*]   Distinguished Name: CN=ESC1-Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=msflab,DC=local
[*]   Manager Approval: Disabled
[*]   Required Signatures: 0
[+]   Vulnerable to: ESC1
[*]   Notes: ESC1: Request can specify a subjectAltName (msPKI-Certificate-Name-Flag)
[*]     Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3978004297-3499718965-4169012971-512 (Domain Admins)
[*]       * S-1-5-21-3978004297-3499718965-4169012971-513 (Domain Users)
[*]       * S-1-5-21-3978004297-3499718965-4169012971-519 (Enterprise Admins)
[+]   Issuing CA: msflab-DC-CA (DC.msflab.local)
[*]     Enrollment SIDs:
[*]       * S-1-5-11 (Authenticated Users)
[*]       * S-1-5-21-3978004297-3499718965-4169012971-519 (Enterprise Admins)
[*]       * S-1-5-21-3978004297-3499718965-4169012971-512 (Domain Admins)
[+] Template: ESC2-Test
[*]   Distinguished Name: CN=ESC2-Test,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=msflab,DC=local
[*]   Manager Approval: Disabled
[*]   Required Signatures: 0
[+]   Vulnerable to: ESC2
[*]   Notes: ESC2: Template defines the Any Purpose OID or no EKUs (PkiExtendedKeyUsage)
[*]     Certificate Template Enrollment SIDs:
[*]       * S-1-5-21-3978004297-3499718965-4169012971-512 (Domain Admins)
[*]       * S-1-5-21-3978004297-3499718965-4169012971-513 (Domain Users)
[*]       * S-1-5-21-3978004297-3499718965-4169012971-519 (Enterprise Admins)
[+]   Issuing CA: msflab-DC-CA (DC.msflab.local)
[*]     Enrollment SIDs:
[*]       * S-1-5-11 (Authenticated Users)
[*]       * S-1-5-21-3978004297-3499718965-4169012971-519 (Enterprise Admins)
[*]       * S-1-5-21-3978004297-3499718965-4169012971-512 (Domain Admins)
[*] Auxiliary module execution completed
```
