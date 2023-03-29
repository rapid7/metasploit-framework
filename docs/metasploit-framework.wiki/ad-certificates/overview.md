## What is AD CS?

Active Directory Certificate Services, also known as AD CS, is an Active Directory tool for
letting administrators issue and manage public key certificates that can be used to
connect to various services and principals on the domain. It is often used to provide
certificates that can be used in place of credentials for logging into a network, or to
provide certificates that can be used to sign and verify the authenticity of data.

The main guarantees that AD CS aims to provide are:
- Confidentiality via encryption
- Integrity via digital signatures
- Authentication by associating certificate keys with computers, users, or device accounts
  on a computer network.

Given that AD CS often holds highly sensitive keys and access credentials for a corporate
network, this makes it a prime target for attackers.

## Required Ports for AD CS
Active Directory requires the following TCP [ports](https://www.encryptionconsulting.com/ports-required-for-active-directory-and-pki/) 
be open on all domain controllers, which heavily overlaps with the [ports](https://learn.microsoft.com/en-us/archive/blogs/pki/firewall-rules-for-active-directory-certificate-services) required for AD CS:

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
Microsoft provides a very useful [training module](https://learn.microsoft.com/en-us/training/modules/implement-manage-active-directory-certificate-services/) 
that covers the fundamentals of AD CS and as well as examples which cover the management of certificate enrollment, certificate revocation and certificate trusts.

## Setting up A Vulnerable AD CS Server
The following steps assume that you have installed an AD CS on either a new or existing domain controller.
### Installing AD CS
1. Open the Server Manager
2. Select Add roles and features
3. Select "Active Directory Certificate Services" under the "Server Roles" section
4. When prompted add all of the features and management tools
5. On the AD CS "Role Services" tab, leave the default selection of only "Certificate Authority"
6. Completion the installation and reboot the server
7. Reopen the Server Manager
8. Go to the AD CS tab and where it says "Configuration Required", hit "More" then "Configure Active Directory Certificate..."
9. Select "Certificate Authority" in the Role Services tab
10. Select "Enterprise CA" in the "Setup Type" tab (the user must be a Domain Administrator for this option to be available)
11. Keep all of the default settings, noting the value of the "Common name for this CA" on the "CA Name" tab (this value corresponds to the `CA` datastore option)
12. Accept the rest of the default settings and complete the configuration

### Setting up a ESC1 Vulnerable Certificate Template
1. Open up the run prompt and type in `certsrv`.
2. In the window that appears you should see your list of certification authorities under `Certification Authority (Local)`. Right click on the folder in the drop down marked `Certificate Templates` and then click `Manage`.
3. Scroll down to the `User` certificate. Right click on it and select `Duplicate Template`.
4. From here you can refer to the following [Active-Directory-Certificate-Services-abuse](https://github.com/RayRRT/Active-Directory-Certificate-Services-abuse/blob/3da1d59f1b66dd0e381b2371b8fb42d87e2c9f82/ADCS.md) documentation for screenshots.
5. Select the `General` tab and rename this to something meaningful like `ESC1-Template`, then click the `Apply` button.
6. In the `Subject Name` tab, select `Supply in the request` and click `Ok` on the security warning that appears. Then click the `Apply` button.
7. Scroll to the `Extensions` tab and under `Application Policies` ensure that `Client Authentication`, `Server Authentication`, `KDC Authentication`, or `Smart Card Logon`  is listed. Then click the `Apply` button.
8. Under the `Security` tab make sure that `Domain Users` group listed and the `Enroll` permissions is marked as allowed for this group.
9. Under `Issuance Requirements` tab, ensure that under `Require the following for enrollment` that the `CA certificate manager approval` box is unticked, as is the `This number of authorized signatures` box.
10. Click `Apply` and then `Ok`
11. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
12. Scroll down and select the `ESC1-Template` certificate, or whatever you named the ESC1 template you created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC2 Vulnerable Certificate Template
1. Open up `certsrv`
2. Scroll down to `Certificate Templates` folder, right click on it and select `Manage`.
3. Find the `ESC1` certificate template you created earlier and right click on that, then select `Duplicate Template`.
4. Select the `General` tab, and then name the template `ESC2-Template`. Then click `Apply`.
5. Go to the `Subject Name` tab and select `Build from this Active Directory Information` and select `Fully distinguished name` under the `Subject Name Format`. The main idea of setting this option is to prevent being able to supply the subject name in the request as this is more what makes the certificate vulnerable to ESC1. The specific options here I don't think will matter so much so long as the `Supply in the request` option isn't ticked. Then click `Apply`.
6. Go the to `Extensions` tab and click on `Application Policies`. Then click on `Edit`.
7. Delete all the existing application policies by clicking on them one by one and clicking the `Remove` button.
8. Click the `Add` button and select `Any Purpose` from the list that appears. Then click the `OK` button.
9. Click the `Apply` button, and then `OK`. The certificate should now be created.
10. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
11. Scroll down and select the `ESC2-Template` certificate, or whatever you named the ESC2 template you created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC3 Template 1 Vulnerable Certificate Template
1. Follow the instructions above to duplicate the ESC2 template and name it `ESC3-Template1`, then click `Apply`.
2. Go to the `Extensions` tab, click the Application Policies entry, click the `Edit` button, and remove the `Any Purpose` policy and replace it with `Certificate Request Agent`, then click `OK`.
3. Click `Apply`.
4. Go to `Issuance Requirements` tab and double check that both `CA certificate manager approval` and `This number of authorized signatures` are unchecked.
5. Click `Apply` if any changes were made or the button is not grey'd out, then click `OK` to create the certificate.
6. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
7. Scroll down and select the `ESC3-Template1` certificate, or whatever you named the ESC3 template number 1 template you just created, and select `OK`. The certificate should now be available to be issued by the CA server.

### Setting up a ESC3 Template 2 Vulnerable Certificate Template
1. Follow the instructions above to duplicate the ESC2 template and name it `ESC3-Template2`, then click `Apply`.
2. Go to the `Extensions` tab, click the Application Policies entry, click the `Edit` button, and remove the `Any Purpose` policy and replace it with `Client Authentication`, then click `OK`.
3. Click `Apply`.
4. Go to `Issuance Requirements` tab and double check that both `CA certificate manager approval` is unchecked.
5. Check the `This number of authorized signatures` checkbox and ensure the value specified is 1, and that the `Policy type required in signature` is set to `Application Policy`, and that the `Application policy` value is `Certificate Request Agent`.
6. Click `Apply` and then click `OK` to issue the certificate.
7. Go back to the `certsrv` screen and right click on the `Certificate Templates` folder. Then click `New` followed by `Certificate Template to Issue`.
8. Scroll down and select the `ESC3-Template2` certificate, or whatever you named the ESC3 template number 2 template you just created, and select `OK`. The certificate should now be available to be issued by the CA server.
