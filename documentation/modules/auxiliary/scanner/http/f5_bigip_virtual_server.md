## Vulnerable Application

This module scans for BigIP HTTP virtual servers using banner
grabbing. BigIP system uses different HTTP profiles for managing
HTTP traffic and these profiles allow to customize the string used
as Server HTTP header. The default values are "BigIP" or "BIG-IP"
depending on the BigIP system version.

## Setting up Server or Finding Test Targets
The easiest way to find a target to test this module against
is to search Shodan for BigIP and use one of these hosts to
test against. F5 does have a free trial for some of their BigIP
products if you want to test locally as well.

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/scanner/http/f5_bigip_virtual_server`
3. `show info`
4. `set RHOSTS [ip]`
5. `run`
6. Check output for presence of BigIP confirmation

## Options

## Scenarios
You can use this module on a single target or several targets. See below for single target usage:

```
msf6 > use auxiliary/scanner/http/f5_bigip_virtual_server
msf6 auxiliary(scanner/http/f5_bigip_virtual_server) > set RHOSTS YYY.YY.YYY.YYY
RHOSTS => YYY.YY.YYY.YYY
msf6 auxiliary(scanner/http/f5_bigip_virtual_server) > run

[+] YYY.YY.YYY.YYY:80 - BigIP HTTP virtual server found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming with cURL
The BigIP is in the Server HTTP response header, so this module can be
verified using a HEAD HTTP request with curl. An example is shown below:

```
curl -i --head http://YYY.YY.YYY.YYY/
HTTP/1.0 302 Found
Location: https://YYY.YY.YYY.YYY/
Server: BigIP
Connection: Keep-Alive
Content-Length: 0
```
