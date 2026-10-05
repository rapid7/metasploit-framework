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

### Windows Server 2019 CES, HTTP to HTTPS relay

```
msf auxiliary(server/relay/esc8_ces) > set RELAY_SOURCE HTTP
msf auxiliary(server/relay/esc8_ces) > set SRVPORT 8080
msf auxiliary(server/relay/esc8_ces) > set RHOSTS 10.5.134.192
msf auxiliary(server/relay/esc8_ces) > set TARGETURI /whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
msf auxiliary(server/relay/esc8_ces) > set VHOST jackdc.whistler.local
msf auxiliary(server/relay/esc8_ces) > set CES_TO https://jackdc.whistler.local/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
msf auxiliary(server/relay/esc8_ces) > set MODE AUTO
msf auxiliary(server/relay/esc8_ces) > run
[*] Checking endpoint on https://10.5.134.192:443/whistler-JACKDC-CA_CES_Kerberos/service.svc/CES
[*] Relay server started
[*] Received Type 1 message from 10.5.134.194, attempting to relay...
[*] Received Type 3 message from 10.5.134.194, attempting to relay...
[+] Identity: WHISTLER\JACKWS$ - Successfully relayed NTLM authentication to HTTPS!
[+] Certificate generated using template Machine for WHISTLER\JACKWS$
[*] Certificate stored at: /home/user/.msf4/loot/certificate.pfx
```

For SMB coercion, change `RELAY_SOURCE` to `SMB`, use `SRVPORT 445`, and direct PetitPotam or another SMB authentication coercion method to `SRVHOST`.
