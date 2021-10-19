## Vulnerable Application

This module checks if the host(s) is(are) vulnerable to Cross-Site Tracing (XST).
The module does more than just check for the HTTP Trace method, and actually
attempts a trace request to verify that XST is possible.

## Verification Steps

- [ ] Start `msfconsole`
- [ ] `use auxiliary/scanner/http/trace`
- [ ] `show info`
- [ ] `set RHOSTS YYY.YY.YYY.YYY`
- [ ] `set RPORT 443`
- [ ] `set SSL true`
- [ ] `run`
- [ ] Check output for presence of XST

## Options

### RHOSTS
The target host(s) to verify Cross-Site Tracing (XST) on.

### RPORT
The target port to check.

### SSL
Needed if the target port uses SSL/TLS. Tells Metasploit to negotiate an SSL/TLS connection.

## Scenarios
You can use this module on a single target or several targets. See below for single target usage:

```msf6 > use auxiliary/scanner/http/trace
msf6 auxiliary(scanner/http/trace) > set RHOSTS YYY.YY.YYY.YYY
RHOSTS => YYY.YY.YYY.YYY
msf6 auxiliary(scanner/http/trace) > set RPORT 443
RPORT => 443
msf6 auxiliary(scanner/http/trace) > set SSL true
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
msf6 auxiliary(scanner/http/trace) > run

[+] YYY.YY.YYY.YYY:443 is vulnerable to Cross-Site Tracing```

## References
- https://owasp.org/www-community/attacks/Cross_Site_Tracing