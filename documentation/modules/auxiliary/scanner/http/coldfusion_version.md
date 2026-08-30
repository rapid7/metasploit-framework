## Vulnerable Application

This module attempts to identify Adobe ColdFusion installations and determine the version
running on the target. It inspects the ColdFusion Administrator login page at
`/CFIDE/administrator/index.cfm` and fingerprints the version based on meta tags, copyright
strings, and other patterns in the HTML response. The module can detect ColdFusion MX6, MX7,
8, 9, and 10, as well as identify the underlying operating system from the `Server` header.

### Setup

Install any version of Adobe ColdFusion up to version 10. The default installation should
have the administrator page accessible at `/CFIDE/administrator/index.cfm`. No additional
configuration is needed.

Alternatively, older ColdFusion trial installers can often be found on the
[Adobe archive](https://helpx.adobe.com/coldfusion/kb/coldfusion-downloads.html).

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/http/coldfusion_version`
3. Do: `set RHOSTS [target IP]`
4. Do: `run`
5. You should see the detected ColdFusion version and OS printed to the console.

## Options

## Scenarios

### ColdFusion 9 on Windows Server 2008

```
msf > use auxiliary/scanner/http/coldfusion_version
msf auxiliary(scanner/http/coldfusion_version) > set RHOSTS 10.0.0.20
RHOSTS => 10.0.0.20
msf auxiliary(scanner/http/coldfusion_version) > set THREADS 5
THREADS => 5
msf auxiliary(scanner/http/coldfusion_version) > run

[+] 10.0.0.20: Adobe ColdFusion 9 (administrator access) (Windows (Microsoft-IIS/7.5))
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### ColdFusion 8 on Linux

```
msf > use auxiliary/scanner/http/coldfusion_version
msf auxiliary(scanner/http/coldfusion_version) > set RHOSTS 10.0.0.30
RHOSTS => 10.0.0.30
msf auxiliary(scanner/http/coldfusion_version) > run

[+] 10.0.0.30: Adobe ColdFusion 8 (administrator access) (Unix (Apache/2.2.22))
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

