## Vulnerable Application
This module uses the ZoomEye API to conduct either a host search or a web search (web servers only),
and output the information gathered into a table which can then be saved for later use.

## Note
You need to register for ZoomEye by creating an account with Telnet404. You can register for a temp email
at https://temp-mail.org and get a temp phone number to recieve the SMS's needed to sign up at https://smsreceivefree.com.

Then browse to https://www.zoomeye.org, click on the `Register` button, and follow the steps from there.

## Verification Steps

1. Start `msfconsole`
2. Do: `use/auxiliary/gather/zoomeye`
3. Do: `set USERNAME <your username>`
4. Do: `set PASSWORD <your password>`
5. Do: `set ZOOMEYE_DORK ''`
6. Do: `run`
7. If you see 'Logged in to zoomeye', despite an internal error coming from the null dork, it means that the creds are valid.

## Options

### RESOURCE
Can be set to either `host` or `web`. `host` looks for any kind of servers,
whilst `web` restricts the search to only web (http/https) servers.

### DATABASE
Records the output to the database if set. If using `host` search, the ip, hostname, and
OS are recorded within the `hosts` table. Additionally, the IP, port, protocol name,
service name and version, and any additional information received are recorded into
the `services` table.

### FACETS
Just show a summary of (all) the results concerning a particular facet.

For host searches, you can filter results by using the following facets:
  - app
  - device
  - service
  - os
  - port
  - country
  - city

For web searches you can filter results by using the following facets:
  - webapp
  - component
  - framework
  - frontend
  - server
  - waf
  - os
  - country
  - city

### MAXPAGE
The maximum number of pages to collect, expressed as an integer.

### OUTFILE
The file to save the output to, if specified.

### USERNAME
The username to log into ZoomEye as.

### PASSWORD
The password to log into ZoomEye as.

### ZOOMEYE_DORK
The query/dork to run on ZoomEye. This must be composed of keywords and search
filters from the list located [here](https://www.zoomeye.org/doc#search-filters).

The request must be enclosed with single quotes and any search terms that
you want to match explicitly on must be enclosed within double quotes. You
must put the filters before any keyword. An example would be: `'country:"FR"+decathlon'`.

Note that if you don't use double quotes to delimit your search filters, then the search filters will not
use the correct data from your query and likely won't end up finding anything. Additionally, putting keywords
first, as mentioned previously, will not return any results, so be wary of this.

## Scenarios

### Host Search With No Database
```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use zoomeye_search

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/gather/zoomeye_search                   normal  No     ZoomEye Search


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/gather/zoomeye_search

[*] Using auxiliary/gather/zoomeye_search
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DATABASE      false            no        Add search results to the database
   FACETS                         no        A comma-separated list of properties to get summary information on query
   MAXPAGE       1                yes       Max amount of pages to collect
   OUTFILE                        no        Path to the file to store the resulting table of info
   PASSWORD                       yes       The ZoomEye password
   RESOURCE      host             yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME                       yes       The ZoomEye username
   ZOOMEYE_DORK                   yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > set USERNAME mexig33784@mtlcz.com
USERNAME => mexig33784@mtlcz.com
msf6 auxiliary(gather/zoomeye_search) > set PASSWORD *redacted*
PASSWORD => *redacted*
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting       Required  Description
   ----          ---------------       --------  -----------
   DATABASE      false                 no        Add search results to the database
   FACETS                              no        A comma-separated list of properties to get summary information on query
   MAXPAGE       1                     yes       Max amount of pages to collect
   OUTFILE                             no        Path to the file to store the resulting table of info
   PASSWORD      *redacted*            yes       The ZoomEye password
   RESOURCE      host                  yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME      mexig33784@mtlcz.com  yes       The ZoomEye username
   ZOOMEYE_DORK                        yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > set ZOOMEYE_DORK 'app:"moxa OnCell G3470A-LTE-EU"'
ZOOMEYE_DORK => app:"moxa OnCell G3470A-LTE-EU"
msf6 auxiliary(gather/zoomeye_search) > run

[-] Unable to resolve api.zoomeye.org
[*] Auxiliary module execution completed
msf6 auxiliary(gather/zoomeye_search) > run

[*] Logged in to zoomeye
[*] Total: 189 on 10 pages. Showing: 1 page(s)
[*] Collecting data, please wait...
Host search
===========

 IP:Port           Protocol  City                  Country      Hostname  OS  service  AppName            Version  Info
 -------           --------  ----                  -------      --------  --  -------  -------            -------  ----
 138.188.35.215:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.35.37:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.37.20:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.39.245:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.39.249:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.41.234:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.41.65:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.42.12:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.43.252:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.45.14:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.50.1:80   tcp                             Switzerland                http     GoAhead WebServer
 138.188.52.135:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.55.140:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.55.71:80  tcp                             Switzerland                http     GoAhead WebServer
 178.145.113.16:4  tcp                             Belgium                    https    GoAhead WebServer
 43
 178.182.239.27:8  tcp                             Poland                     http     GoAhead WebServer
 0
 183.171.15.197:4  tcp                             Malaysia                   https    GoAhead WebServer
 43
 183.171.15.221:4  tcp                             Malaysia                   https    GoAhead WebServer
 43
 62.79.16.38:80    tcp       Aalborg Municipality  Denmark                    https    GoAhead WebServer
 90.117.110.158:4  tcp                             France                     https    GoAhead WebServer
 43

[*] Auxiliary module execution completed
msf6 auxiliary(gather/zoomeye_search) >
```

### Host Search With No Database and Multiple Pages And Saving To Disk
```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use zoomeye_search

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/gather/zoomeye_search                   normal  No     ZoomEye Search


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/gather/zoomeye_search

[*] Using auxiliary/gather/zoomeye_search
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DATABASE      false            no        Add search results to the database
   FACETS                         no        A comma-separated list of properties to get summary information on query
   MAXPAGE       1                yes       Max amount of pages to collect
   OUTFILE                        no        Path to the file to store the resulting table of info
   PASSWORD                       yes       The ZoomEye password
   RESOURCE      host             yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME                       yes       The ZoomEye username
   ZOOMEYE_DORK                   yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > set USERNAME mexig33784@mtlcz.com
USERNAME => mexig33784@mtlcz.com
msf6 auxiliary(gather/zoomeye_search) > set PASSWORD *redacted*
PASSWORD => *redacted*
msf6 auxiliary(gather/zoomeye_search) > set ZOOMEYE_DORK 'app:"moxa OnCell G3470A-LTE-EU"'
ZOOMEYE_DORK => app:"moxa OnCell G3470A-LTE-EU"
msf6 auxiliary(gather/zoomeye_search) >
msf6 auxiliary(gather/zoomeye_search) > set MAXPAGE 5
MAXPAGE => 5
msf6 auxiliary(gather/zoomeye_search) > set OUTFILE /tmp/results.txt
OUTFILE => /tmp/results.txt
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting                  Required  Description
   ----          ---------------                  --------  -----------
   DATABASE      false                            no        Add search results to the database
   FACETS                                         no        A comma-separated list of properties to get summary information on q
                                                            uery
   MAXPAGE       5                                yes       Max amount of pages to collect
   OUTFILE       /tmp/results.txt                 no        Path to the file to store the resulting table of info
   PASSWORD      *redacted*                       yes       The ZoomEye password
   RESOURCE      host                             yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME      mexig33784@mtlcz.com             yes       The ZoomEye username
   ZOOMEYE_DORK  app:"moxa OnCell G3470A-LTE-EU"  yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > run

[*] Logged in to zoomeye
[*] Total: 189 on 10 pages. Showing: 5 page(s)
[*] Collecting data, please wait...
Host search
===========

 IP:Port           Protocol  City                  Country             Hostname  OS  service  AppName            Version  Info
 -------           --------  ----                  -------             --------  --  -------  -------            -------  ----
 123.209.112.240:  tcp       Sydney                Australia                         http     GoAhead WebServer
 80
 123.209.121.222:  tcp       Sydney                Australia                         https    GoAhead WebServer
 443
 123.209.198.169:  tcp       Sydney                Australia                         http     GoAhead WebServer
 80
 123.209.248.218:  tcp       Sydney                Australia                         https    GoAhead WebServer
 443
 123.209.248.218:  tcp       Sydney                Australia                         http     GoAhead WebServer
 80
 138.188.32.57:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.32.80:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.32.80:80  tcp                             Switzerland                       https    GoAhead WebServer
 138.188.33.104:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.33.104:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.33.134:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.34.129:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.34.129:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.34.217:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.34.21:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.34.21:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.34.77:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.35.215:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.35.37:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.35.55:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.37.20:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.38.11:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.39.0:443  tcp                             Switzerland                       https    GoAhead WebServer
 138.188.39.172:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.39.245:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.39.249:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.40.125:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.40.125:8  tcp                             Switzerland                       https    GoAhead WebServer
 0
 138.188.40.210:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.40.38:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.41.135:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.41.135:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.41.234:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.41.65:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.42.12:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.42.150:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.42.213:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.42.219:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.42.246:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.42.246:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.42.78:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.42.78:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.43.205:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.43.231:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.43.252:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.44.151:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.44.92:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.45.14:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.46.196:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.46.196:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.46.197:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.46.197:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.47.158:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.47.158:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.47.215:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.47.215:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.48.206:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.48.206:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.48.217:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.48.23:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.50.148:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.50.153:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.50.153:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.50.1:80   tcp                             Switzerland                       http     GoAhead WebServer
 138.188.51.169:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.52.135:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.52.18:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.52.239:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.53.51:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.54.188:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.54.237:8  tcp                             Switzerland                       https    GoAhead WebServer
 0
 138.188.54.247:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.54.247:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.54.71:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.54.85:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.55.140:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.55.71:80  tcp                             Switzerland                       http     GoAhead WebServer
 176.118.19.96:80  tcp                             Russian Federation                http     GoAhead WebServer
 178.145.113.16:4  tcp                             Belgium                           https    GoAhead WebServer
 43
 178.182.239.27:8  tcp                             Poland                            http     GoAhead WebServer
 0
 178.182.239.28:4  tcp                             Poland                            https    GoAhead WebServer
 43
 178.182.239.30:8  tcp                             Poland                            http     GoAhead WebServer
 0
 178.183.132.209:  tcp                             Poland                            https    GoAhead WebServer
 443
 183.171.15.197:4  tcp                             Malaysia                          https    GoAhead WebServer
 43
 183.171.15.221:4  tcp                             Malaysia                          https    GoAhead WebServer
 43
 31.0.211.25:443   tcp                             Poland                            https    GoAhead WebServer
 31.173.131.227:4  tcp                             Russian Federation                https    GoAhead WebServer
 43
 37.184.151.252:4  tcp                             Belgium                           https    GoAhead WebServer
 43
 37.62.232.145:80  tcp                             Belgium                           http     GoAhead WebServer
 37.62.240.111:44  tcp                             Belgium                           https    GoAhead WebServer
 3
 37.84.125.16:443  tcp                             Germany                           https    GoAhead WebServer
 46.179.5.232:443  tcp                             Belgium                           https    GoAhead WebServer
 62.79.16.36:80    tcp       Aalborg Municipality  Denmark                           http     GoAhead WebServer
 62.79.16.38:80    tcp       Aalborg Municipality  Denmark                           https    GoAhead WebServer
 78.25.91.170:443  tcp                             Russian Federation                https    GoAhead WebServer
 80.251.198.20:80  tcp                             Denmark                           http     GoAhead WebServer
 85.26.192.153:44  tcp                             Russian Federation                https    GoAhead WebServer
 3
 90.117.100.109:8                                  France                            https    GoAhead WebServer
 080
 90.117.110.158:4  tcp                             France                            https    GoAhead WebServer
 43
 90.117.120.142:8  tcp                             France                            http     GoAhead WebServer
 0

[*] Saved results in /tmp/results.txt
[*] Auxiliary module execution completed
msf6 auxiliary(gather/zoomeye_search) > cat /tmp/results.txt
[*] exec: cat /tmp/results.txt

Host search
===========

 IP:Port           Protocol  City                  Country             Hostname  OS  service  AppName            Version  Info
 -------           --------  ----                  -------             --------  --  -------  -------            -------  ----
 123.209.112.240:  tcp       Sydney                Australia                         http     GoAhead WebServer
 80
 123.209.121.222:  tcp       Sydney                Australia                         https    GoAhead WebServer
 443
 123.209.198.169:  tcp       Sydney                Australia                         http     GoAhead WebServer
 80
 123.209.248.218:  tcp       Sydney                Australia                         https    GoAhead WebServer
 443
 123.209.248.218:  tcp       Sydney                Australia                         http     GoAhead WebServer
 80
 138.188.32.57:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.32.80:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.32.80:80  tcp                             Switzerland                       https    GoAhead WebServer
 138.188.33.104:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.33.104:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.33.134:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.34.129:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.34.129:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.34.217:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.34.21:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.34.21:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.34.77:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.35.215:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.35.37:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.35.55:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.37.20:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.38.11:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.39.0:443  tcp                             Switzerland                       https    GoAhead WebServer
 138.188.39.172:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.39.245:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.39.249:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.40.125:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.40.125:8  tcp                             Switzerland                       https    GoAhead WebServer
 0
 138.188.40.210:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.40.38:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.41.135:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.41.135:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.41.234:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.41.65:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.42.12:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.42.150:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.42.213:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.42.219:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.42.246:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.42.246:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.42.78:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.42.78:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.43.205:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.43.231:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.43.252:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.44.151:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.44.92:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.45.14:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.46.196:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.46.196:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.46.197:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.46.197:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.47.158:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.47.158:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.47.215:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.47.215:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.48.206:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.48.206:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.48.217:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.48.23:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.50.148:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.50.153:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.50.153:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.50.1:80   tcp                             Switzerland                       http     GoAhead WebServer
 138.188.51.169:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.52.135:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.52.18:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.52.239:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.53.51:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.54.188:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.54.237:8  tcp                             Switzerland                       https    GoAhead WebServer
 0
 138.188.54.247:4  tcp                             Switzerland                       https    GoAhead WebServer
 43
 138.188.54.247:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.54.71:80  tcp                             Switzerland                       http     GoAhead WebServer
 138.188.54.85:44  tcp                             Switzerland                       https    GoAhead WebServer
 3
 138.188.55.140:8  tcp                             Switzerland                       http     GoAhead WebServer
 0
 138.188.55.71:80  tcp                             Switzerland                       http     GoAhead WebServer
 176.118.19.96:80  tcp                             Russian Federation                http     GoAhead WebServer
 178.145.113.16:4  tcp                             Belgium                           https    GoAhead WebServer
 43
 178.182.239.27:8  tcp                             Poland                            http     GoAhead WebServer
 0
 178.182.239.28:4  tcp                             Poland                            https    GoAhead WebServer
 43
 178.182.239.30:8  tcp                             Poland                            http     GoAhead WebServer
 0
 178.183.132.209:  tcp                             Poland                            https    GoAhead WebServer
 443
 183.171.15.197:4  tcp                             Malaysia                          https    GoAhead WebServer
 43
 183.171.15.221:4  tcp                             Malaysia                          https    GoAhead WebServer
 43
 31.0.211.25:443   tcp                             Poland                            https    GoAhead WebServer
 31.173.131.227:4  tcp                             Russian Federation                https    GoAhead WebServer
 43
 37.184.151.252:4  tcp                             Belgium                           https    GoAhead WebServer
 43
 37.62.232.145:80  tcp                             Belgium                           http     GoAhead WebServer
 37.62.240.111:44  tcp                             Belgium                           https    GoAhead WebServer
 3
 37.84.125.16:443  tcp                             Germany                           https    GoAhead WebServer
 46.179.5.232:443  tcp                             Belgium                           https    GoAhead WebServer
 62.79.16.36:80    tcp       Aalborg Municipality  Denmark                           http     GoAhead WebServer
 62.79.16.38:80    tcp       Aalborg Municipality  Denmark                           https    GoAhead WebServer
 78.25.91.170:443  tcp                             Russian Federation                https    GoAhead WebServer
 80.251.198.20:80  tcp                             Denmark                           http     GoAhead WebServer
 85.26.192.153:44  tcp                             Russian Federation                https    GoAhead WebServer
 3
 90.117.100.109:8                                  France                            https    GoAhead WebServer
 080
 90.117.110.158:4  tcp                             France                            https    GoAhead WebServer
 43
 90.117.120.142:8  tcp                             France                            http     GoAhead WebServer
 0
msf6 auxiliary(gather/zoomeye_search) >
```

### Hosts Search With Facets
```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use zoomeye_search

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/gather/zoomeye_search                   normal  No     ZoomEye Search


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/gather/zoomeye_search

[*] Using auxiliary/gather/zoomeye_search
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DATABASE      false            no        Add search results to the database
   FACETS                         no        A comma-separated list of properties to get summary information on query
   MAXPAGE       1                yes       Max amount of pages to collect
   OUTFILE                        no        Path to the file to store the resulting table of info
   PASSWORD                       yes       The ZoomEye password
   RESOURCE      host             yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME                       yes       The ZoomEye username
   ZOOMEYE_DORK                   yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > set ZOOMEYE_DORK 'app:"moxa OnCell G3470A-LTE-EU"'
ZOOMEYE_DORK => app:"moxa OnCell G3470A-LTE-EU"
msf6 auxiliary(gather/zoomeye_search) > set USERNAME mexig33784@mtlcz.com
USERNAME => mexig33784@mtlcz.com
msf6 auxiliary(gather/zoomeye_search) > set PASSWORD *redacted*
PASSWORD => *redacted*
msf6 auxiliary(gather/zoomeye_search) > set FACETS os,port,country
FACETS => os,port,country
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting                  Required  Description
   ----          ---------------                  --------  -----------
   DATABASE      false                            no        Add search results to the database
   FACETS        os,port,country                  no        A comma-separated list of properties to get summary information on q
                                                            uery
   MAXPAGE       1                                yes       Max amount of pages to collect
   OUTFILE                                        no        Path to the file to store the resulting table of info
   PASSWORD      *redacted*                       yes       The ZoomEye password
   RESOURCE      host                             yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME      mexig33784@mtlcz.com             yes       The ZoomEye username
   ZOOMEYE_DORK  app:"moxa OnCell G3470A-LTE-EU"  yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > run

[*] Logged in to zoomeye
[*] Total: 189 on 10 pages. Showing facets
Facets
======

 Facet    Name                Count
 -----    ----                -----
 country  Switzerland         115
 country  Poland              18
 country  Belgium             13
 country  Australia           12
 country  Germany             8
 country  Russian Federation  8
 country  France              7
 country  Denmark             3
 country  Malaysia            3
 country  Jersey              1
 os                           189
 port     80                  106
 port     443                 80
 port     8080                2
 port     8081                1

[*] Auxiliary module execution completed
msf6 auxiliary(gather/zoomeye_search) >
```


### Web Search With Facets And OutFile
```
msf6 > use auxiliary/gather/zoomeye_search
msf6 auxiliary(gather/zoomeye_search) > set ZOOMEYE_DORK 'app:"moxa OnCell G3470A-LTE-EU"'
ZOOMEYE_DORK => app:"moxa OnCell G3470A-LTE-EU"
msf6 auxiliary(gather/zoomeye_search) > set USERNAME mexig33784@mtlcz.com
USERNAME => mexig33784@mtlcz.com
msf6 auxiliary(gather/zoomeye_search) > set PASSWORD *redacted*
PASSWORD => *redacted*
msf6 auxiliary(gather/zoomeye_search) > set FACETS os,port,country
FACETS => os,port,country
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting                  Required  Description
   ----          ---------------                  --------  -----------
   DATABASE      false                            no        Add search results to the database
   FACETS        os,port,country                  no        A comma-separated list of properties to get summary information on q
                                                            uery
   MAXPAGE       1                                yes       Max amount of pages to collect
   OUTFILE                                        no        Path to the file to store the resulting table of info
   PASSWORD      *redacted*                       yes       The ZoomEye password
   RESOURCE      host                             yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME      mexig33784@mtlcz.com             yes       The ZoomEye username
   ZOOMEYE_DORK  app:"moxa OnCell G3470A-LTE-EU"  yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > set RESOURCE web
RESOURCE => web
msf6 auxiliary(gather/zoomeye_search) > set OUTFILE /tmp/web.txt
OUTFILE => /tmp/web.txt
msf6 auxiliary(gather/zoomeye_search) > run

[*] Logged in to zoomeye
[*] Total: 9 on 1 pages. Showing facets
Facets
======

 Facet    Name       Count
 -----    ----       -----
 country  Poland     3
 country  Denmark    2
 country  France     2
 country  Australia  1
 country  Austria    1
 os       Windows    9

[*] Saved results in /tmp/web.txt
[*] Auxiliary module execution completed
msf6 auxiliary(gather/zoomeye_search) > cat /tmp/web.txt
[*] exec: cat /tmp/web.txt

Facets
======

 Facet    Name       Count
 -----    ----       -----
 country  Poland     3
 country  Denmark    2
 country  France     2
 country  Australia  1
 country  Austria    1
 os       Windows    9
msf6 auxiliary(gather/zoomeye_search) >
```

### Hosts Search with Database And Outfile Options Set
```
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting                  Required  Description
   ----          ---------------                  --------  -----------
   DATABASE      true                             no        Add search results to the database
   FACETS                                         no        A comma-separated list of properties to get summary information on q
                                                            uery
   MAXPAGE       1                                yes       Max amount of pages to collect
   OUTFILE       /tmp/web.txt                     no        Path to the file to store the resulting table of info
   PASSWORD      aNN9tMSs3e2fJ5U                  yes       The ZoomEye password
   RESOURCE      host                             yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME      mexig33784@mtlcz.com             yes       The ZoomEye username
   ZOOMEYE_DORK  app:"moxa OnCell G3470A-LTE-EU"  yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > run

[*] Logged in to zoomeye
[*] Total: 189 on 10 pages. Showing: 1 page(s)
[*] Collecting data, please wait...
Host search
===========

 IP:Port           Protocol  City                  Country      Hostname  OS  service  AppName            Version  Info
 -------           --------  ----                  -------      --------  --  -------  -------            -------  ----
 138.188.35.215:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.35.37:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.37.20:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.39.245:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.39.249:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.41.234:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.41.65:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.42.12:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.43.252:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.45.14:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.50.1:80   tcp                             Switzerland                http     GoAhead WebServer
 138.188.52.135:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.55.140:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.55.71:80  tcp                             Switzerland                http     GoAhead WebServer
 178.145.113.16:4  tcp                             Belgium                    https    GoAhead WebServer
 43
 178.182.239.27:8  tcp                             Poland                     http     GoAhead WebServer
 0
 183.171.15.197:4  tcp                             Malaysia                   https    GoAhead WebServer
 43
 183.171.15.221:4  tcp                             Malaysia                   https    GoAhead WebServer
 43
 62.79.16.38:80    tcp       Aalborg Municipality  Denmark                    https    GoAhead WebServer
 90.117.110.158:4  tcp                             France                     https    GoAhead WebServer
 43

[*] Saved results in /tmp/web.txt
[*] Auxiliary module execution completed
msf6 auxiliary(gather/zoomeye_search) > cat /tmp/web.txt
[*] exec: cat /tmp/web.txt

Host search
===========

 IP:Port           Protocol  City                  Country      Hostname  OS  service  AppName            Version  Info
 -------           --------  ----                  -------      --------  --  -------  -------            -------  ----
 138.188.35.215:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.35.37:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.37.20:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.39.245:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.39.249:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.41.234:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.41.65:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.42.12:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.43.252:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.45.14:80  tcp                             Switzerland                http     GoAhead WebServer
 138.188.50.1:80   tcp                             Switzerland                http     GoAhead WebServer
 138.188.52.135:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.55.140:8  tcp                             Switzerland                http     GoAhead WebServer
 0
 138.188.55.71:80  tcp                             Switzerland                http     GoAhead WebServer
 178.145.113.16:4  tcp                             Belgium                    https    GoAhead WebServer
 43
 178.182.239.27:8  tcp                             Poland                     http     GoAhead WebServer
 0
 183.171.15.197:4  tcp                             Malaysia                   https    GoAhead WebServer
 43
 183.171.15.221:4  tcp                             Malaysia                   https    GoAhead WebServer
 43
 62.79.16.38:80    tcp       Aalborg Municipality  Denmark                    https    GoAhead WebServer
 90.117.110.158:4  tcp                             France                     https    GoAhead WebServer
 43
msf6 auxiliary(gather/zoomeye_search) > hosts

Hosts
=====

address         mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------         ---  ----  -------  ---------  -----  -------  ----  --------
62.79.16.38                                           device         Added from Zoomeye
90.117.110.158                                        device         Added from Zoomeye
138.188.35.37                                         device         Added from Zoomeye
138.188.35.215                                        device         Added from Zoomeye
138.188.37.20                                         device         Added from Zoomeye
138.188.39.245                                        device         Added from Zoomeye
138.188.39.249                                        device         Added from Zoomeye
138.188.41.65                                         device         Added from Zoomeye
138.188.41.234                                        device         Added from Zoomeye
138.188.42.12                                         device         Added from Zoomeye
138.188.43.252                                        device         Added from Zoomeye
138.188.45.14                                         device         Added from Zoomeye
138.188.50.1                                          device         Added from Zoomeye
138.188.52.135                                        device         Added from Zoomeye
138.188.55.71                                         device         Added from Zoomeye
138.188.55.140                                        device         Added from Zoomeye
178.145.113.16                                        device         Added from Zoomeye
178.182.239.27                                        device         Added from Zoomeye
183.171.15.197                                        device         Added from Zoomeye
183.171.15.221                                        device         Added from Zoomeye

msf6 auxiliary(gather/zoomeye_search) > services
Services
========

host            port  proto  name   state  info
----            ----  -----  ----   -----  ----
62.79.16.38     80    tcp    https  open   GoAhead WebServer running version:
90.117.110.158  443   tcp    https  open   GoAhead WebServer running version:
138.188.35.37   80    tcp    http   open   GoAhead WebServer running version:
138.188.35.215  80    tcp    http   open   GoAhead WebServer running version:
138.188.37.20   80    tcp    http   open   GoAhead WebServer running version:
138.188.39.245  80    tcp    http   open   GoAhead WebServer running version:
138.188.39.249  80    tcp    http   open   GoAhead WebServer running version:
138.188.41.65   80    tcp    http   open   GoAhead WebServer running version:
138.188.41.234  80    tcp    http   open   GoAhead WebServer running version:
138.188.42.12   80    tcp    http   open   GoAhead WebServer running version:
138.188.43.252  80    tcp    http   open   GoAhead WebServer running version:
138.188.45.14   80    tcp    http   open   GoAhead WebServer running version:
138.188.50.1    80    tcp    http   open   GoAhead WebServer running version:
138.188.52.135  80    tcp    http   open   GoAhead WebServer running version:
138.188.55.71   80    tcp    http   open   GoAhead WebServer running version:
138.188.55.140  80    tcp    http   open   GoAhead WebServer running version:
178.145.113.16  443   tcp    https  open   GoAhead WebServer running version:
178.182.239.27  80    tcp    http   open   GoAhead WebServer running version:
183.171.15.197  443   tcp    https  open   GoAhead WebServer running version:
183.171.15.221  443   tcp    https  open   GoAhead WebServer running version:

msf6 auxiliary(gather/zoomeye_search) >
```

### Web Search With Database
```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use auxiliary/gather/zoomeye_search
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DATABASE      false            no        Add search results to the database
   FACETS                         no        A comma-separated list of properties to get summary information on query
   MAXPAGE       1                yes       Max amount of pages to collect
   OUTFILE                        no        Path to the file to store the resulting table of info
   PASSWORD                       yes       The ZoomEye password
   RESOURCE      host             yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME                       yes       The ZoomEye username
   ZOOMEYE_DORK                   yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > set RESOURCE web
RESOURCE => web
msf6 auxiliary(gather/zoomeye_search) > set ZOOMEYE_DORK 'app:"moxa OnCell G3470A-LTE-EU"'
ZOOMEYE_DORK => app:"moxa OnCell G3470A-LTE-EU"
msf6 auxiliary(gather/zoomeye_search) > set USERNAME mexig33784@mtlcz.com
USERNAME => mexig33784@mtlcz.com
msf6 auxiliary(gather/zoomeye_search) > set PASSWORD aNN9tMSs3e2fJ5U
PASSWORD => aNN9tMSs3e2fJ5U
msf6 auxiliary(gather/zoomeye_search) > set OUTFILE /tmp/web-test.txt
OUTFILE => /tmp/web-test.txt
msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name          Current Setting                  Required  Description
   ----          ---------------                  --------  -----------
   DATABASE      false                            no        Add search results to the database
   FACETS                                         no        A comma-separated list of properties to get summary information on q
                                                            uery
   MAXPAGE       1                                yes       Max amount of pages to collect
   OUTFILE       /tmp/web-test.txt                no        Path to the file to store the resulting table of info
   PASSWORD      aNN9tMSs3e2fJ5U                  yes       The ZoomEye password
   RESOURCE      web                              yes       ZoomEye Resource Type (Accepted: host, web)
   USERNAME      mexig33784@mtlcz.com             yes       The ZoomEye username
   ZOOMEYE_DORK  app:"moxa OnCell G3470A-LTE-EU"  yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_search) > set DATABASE true
DATABASE => true
msf6 auxiliary(gather/zoomeye_search) > hosts -d

Hosts
=====

address         mac  name                                         os_name  os_flavor  os_sp  purpose  info  comments
-------         ---  ----                                         -------  ---------  -----  -------  ----  --------
31.0.211.25          apn-31-0-211-25.static.gprs.plus.pl                                                    Added from Zoomeye
46.74.36.255         046074036255.atmpu0002.highway.a1.net                                                  Added from Zoomeye
80.251.198.20        80.251.198.20                                                                          Added from Zoomeye
90.117.106.196       90-117-106-196.mobile.abo.orange.fr                                                    Added from Zoomeye
90.117.110.29        90-117-110-29.mobile.abo.orange.fr                                                     Added from Zoomeye
123.209.125.20       61438337164.mobile.telstra.com                                                         Added from Zoomeye
178.182.239.27       178.182.239.27.nat.umts.dynamic.t-mobile.pl                                            Added from Zoomeye
178.182.244.68       178.182.244.68.nat.umts.dynamic.t-mobile.pl                                            Added from Zoomeye

[*] Deleted 8 hosts
msf6 auxiliary(gather/zoomeye_search) > services -d
Services
========

host  port  proto  name  state  info
----  ----  -----  ----  -----  ----

msf6 auxiliary(gather/zoomeye_search) > run

[*] Logged in to zoomeye
[*] Total: 9 on 1 pages. Showing: 1 page(s)
Web search
==========

 IP              Site                                         City    Country    DB:Version  WebApp:Version
 --              ----                                         ----    -------    ----------  --------------
 31.0.211.25     apn-31-0-211-25.static.gprs.plus.pl                  Poland
 46.74.36.255    046074036255.atmpu0002.highway.a1.net        Vienna  Austria
 80.251.198.20   80.251.198.20.bredband.3.dk                          Denmark
 80.251.198.20   80.251.198.20                                        Denmark
 90.117.106.196  90-117-106-196.mobile.abo.orange.fr                  France
 90.117.110.29   90-117-110-29.mobile.abo.orange.fr                   France
 123.209.125.20  61438337164.mobile.telstra.com               Sydney  Australia
 178.182.239.27  178.182.239.27.nat.umts.dynamic.t-mobile.pl          Poland
 178.182.244.68  178.182.244.68.nat.umts.dynamic.t-mobile.pl          Poland

[*] Saved results in /tmp/web-test.txt
[*] Auxiliary module execution completed
msf6 auxiliary(gather/zoomeye_search) > hosts

Hosts
=====

address         mac  name                                         os_name  os_flavor  os_sp  purpose  info  comments
-------         ---  ----                                         -------  ---------  -----  -------  ----  --------
31.0.211.25          apn-31-0-211-25.static.gprs.plus.pl                                                    Added from Zoomeye
46.74.36.255         046074036255.atmpu0002.highway.a1.net                                                  Added from Zoomeye
80.251.198.20        80.251.198.20                                                                          Added from Zoomeye
90.117.106.196       90-117-106-196.mobile.abo.orange.fr                                                    Added from Zoomeye
90.117.110.29        90-117-110-29.mobile.abo.orange.fr                                                     Added from Zoomeye
123.209.125.20       61438337164.mobile.telstra.com                                                         Added from Zoomeye
178.182.239.27       178.182.239.27.nat.umts.dynamic.t-mobile.pl                                            Added from Zoomeye
178.182.244.68       178.182.244.68.nat.umts.dynamic.t-mobile.pl                                            Added from Zoomeye

msf6 auxiliary(gather/zoomeye_search) > services
Services
========

host  port  proto  name  state  info
----  ----  -----  ----  -----  ----

msf6 auxiliary(gather/zoomeye_search) > cat /tmp/web-test.txt
[*] exec: cat /tmp/web-test.txt

Web search
==========

 IP              Site                                         City    Country    DB:Version  WebApp:Version
 --              ----                                         ----    -------    ----------  --------------
 31.0.211.25     apn-31-0-211-25.static.gprs.plus.pl                  Poland
 46.74.36.255    046074036255.atmpu0002.highway.a1.net        Vienna  Austria
 80.251.198.20   80.251.198.20.bredband.3.dk                          Denmark
 80.251.198.20   80.251.198.20                                        Denmark
 90.117.106.196  90-117-106-196.mobile.abo.orange.fr                  France
 90.117.110.29   90-117-110-29.mobile.abo.orange.fr                   France
 123.209.125.20  61438337164.mobile.telstra.com               Sydney  Australia
 178.182.239.27  178.182.239.27.nat.umts.dynamic.t-mobile.pl          Poland
 178.182.244.68  178.182.244.68.nat.umts.dynamic.t-mobile.pl          Poland
msf6 auxiliary(gather/zoomeye_search) >
```