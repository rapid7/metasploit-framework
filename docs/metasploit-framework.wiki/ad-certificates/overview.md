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
The steps for setting up a vulnerable AD CS server are covered in the [[Installing AD CS|./ldap_esc_vulnerable_cert_finder.md]] section.
