## What is AD CS?

TODO

## Required Ports for AD CS
Active Directory requires the following TCP ports be open on all domain controllers (taken from
https://www.encryptionconsulting.com/ports-required-for-active-directory-and-pki/), which
heavily overlaps with the ports required for AD CS (see https://learn.microsoft.com/en-us/archive/blogs/pki/firewall-rules-for-active-directory-certificate-services):

- TCP/UDP port 53: DNS
- TCP/UDP port 88: Kerberos authentication
- TCP/UDP port 135: RPC
- TCP/UDP port 137-138: NetBIOS
- TCP/UDP port 389: LDAP
- TCP/UDP port 445: SMB
- TCP/UDP port 464: Kerberos password change
- TCP/UDP port 636: LDAP SSL
- TCP/UDP port 3268-3269: Global catalog

AD CS additionally has the following requirements for Certificate Authorities:

- TCP random port above 1023: RPC dynamic port allocation

The following ports are optional depending on services used, and tend to apply to
Certificate Enrollment Web Services:

- TCP port 80: HTTP
- TCP port 443: HTTPS
- TCP port 445: SMB

If using Active Directory Federation Services (ADFS) for single sign on the following ports are
also required:

- TCP port 80: HTTP
- TCP port 443: HTTPS
- TCP port 49443: ADFS

## Core Concepts

TODO

## Common AD CS workflows

TODO

## Setting up A Vulnerable AD CS Server
### Installing AD CS
- [ ] Install AD CS on either a new or existing domain controller
    - [ ] Open the Server Manager
    - [ ] Select Add roles and features
    - [ ] Select "Active Directory Certificate Services" under the "Server Roles" section
    - [ ] When prompted add all of the features and management tools
    - [ ] On the AD CS "Role Services" tab, leave the default selection of only "Certificate Authority"
    - [ ] Completion the installation and reboot the server
    - [ ] Reopen the Server Manager
    - [ ] Go to the AD CS tab and where it says "Configuration Required", hit "More" then "Configure Active Directory Certificate..."
    - [ ] Select "Certificate Authority" in the Role Services tab
    - [ ] Select "Enterprise CA" in the "Setup Type" tab (the user must be a Domain Administrator for this option to be available)
    - [ ] Keep all of the default settings, noting the value of the "Common name for this CA" on the "CA Name" tab (this value corresponds to the `CA` datastore option)
    - [ ] Accept the rest of the default settings and complete the configuration

### Setting up a ESC1 Vulnerable Certificate Template
- [ ] Open up the run prompt and type in `certsrv`.
- [ ] In the window that appears you should see your list of certification authorities under `Certification Authority (Local)`. Right click on the folder in the drop down marked `Certificate Templates` and then click `Manage`.
- [ ] Scroll down to the `User` certificate. Right click on it and select `Duplicate Template`.
- [ ] From here you can refer to https://github.com/RayRRT/Active-Directory-Certificate-Services-abuse/blob/3da1d59f1b66dd0e381b2371b8fb42d87e2c9f82/ADCS.md for screenshots.
- [ ] Select the `General` tab and rename this to something meaningful like `ESC1-Template`, then click the `Apply` button.
- [ ] In the `Subject Name` tab, select `Supply in the request` and click `Ok` on the security warning that appears. Then click the `Apply` button.
- [ ] Scroll to the `Extensions` tab and under `Application Policies` ensure that `Client Authentication`, `Server Authentication`, `KDC Authentication`, or `Smart Card Logon`  is listed. Then click the `Apply` button.
- [ ] Under the `Security` tab make sure that `Domain Users` group listed and the `Enroll` permissions is marked as allowed for this group.
- [ ] Under `Issuance Requirements` tab, ensure that under `Require the following for enrollment` that the `CA certificate manager approval` box is unticked, as is the `This number of authorized signatures` box.
- [ ] Click `Apply` and then `Ok`
- [ ] Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
- [ ] Scroll down and select the `ESC1-Template` certificate, or whatever you named the ESC1 template you created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC2 Vulnerable Certificate Template
- [ ] Open up `certsrv`
- [ ] Scroll down to `Certificate Templates` folder, right click on it and select `Manage`.
- [ ] Find the `ESC1` certificate template you created earlier and right click on that, then select `Duplicate Template`.
- [ ] Select the `General` tab, and then name the template `ESC2-Template`. Then click `Apply`.
- [ ] Go to the `Subject Name` tab and select `Build from this Active Directory Information` and select `Fully distinguished name` under the `Subject Name Format`. The main idea of setting this option is to prevent being able to supply the subject name in the request as this is more what makes the certificate vulnerable to ESC1. The specific options here I don't think will matter so much so long as the `Supply in the request` option isn't ticked. Then click `Apply`.
- [ ] Go the to `Extensions` tab and click on `Application Policies`. Then click on `Edit`.
- [ ] Delete all the existing application policies by clicking on them one by one and clicking the `Remove` button.
- [ ] Click the `Add` button and select `Any Purpose` from the list that appears. Then click the `OK` button.
- [ ] Click the `Apply` button, and then `OK`. The certificate should now be created.
- [ ] Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
- [ ] Scroll down and select the `ESC2-Template` certificate, or whatever you named the ESC2 template you created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC3 Template 1 Vulnerable Certificate Template
- [ ] Follow the instructions above to duplicate the ESC2 template and name it `ESC3-Template1`, then click `Apply`.
- [ ] Go to the `Extensions` tab, click the Application Policies entry, click the `Edit` button, and remove the `Any Purpose` policy and replace it with `Certificate Request Agent`, then click `OK`.
- [ ] Click `Apply`.
- [ ] Go to `Issuance Requirements` tab and double check that both `CA certificate manager approval` and `This number of authorized signatures` are unchecked.
- [ ] Click `Apply` if any changes were made or the button is not grey'd out, then click `OK` to create the certificate.
- [ ] Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
- [ ] Scroll down and select the `ESC3-Template1` certificate, or whatever you named the ESC3 template number 1 template you just created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC3 Template 2 Vulnerable Certificate Template
- [ ] Follow the instructions above to duplicate the ESC2 template and name it `ESC3-Template2`, then click `Apply`.
- [ ] Go to the `Extensions` tab, click the Application Policies entry, click the `Edit` button, and remove the `Any Purpose` policy and replace it with `Client Authentication`, then click `OK`.
- [ ] Click `Apply`.
- [ ] Go to `Issuance Requirements` tab and double check that both `CA certificate manager approval` is unchecked.
- [ ] Check the `This number of authorized signatures` checkbox and ensure the value specified is 1, and that the `Policy type required in signature` is set to `Application Policy`, and that the `Application policy` value is `Certificate Request Agent`.
- [ ] Click `Apply` and then click `OK` to issue the certificate.
- [ ] Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
- [ ] Scroll down and select the `ESC3-Template2` certificate, or whatever you named the ESC3 template number 2 template you just created, and select `OK`. The certificate should now be available to be issued by the CA server.
