### Introduction
ZoomEye is a cyberspace search engine, users can search for network devices using a browser [https://www.zoomeye.org](https://www.zoomeye.org)

`zoomeye search` auxiliary module developed based on the ZoomEye API.

**NOTE: In order for this module to function properly, a ZoomEye API key is needed. 
You can register for a free account here: https://sso.telnet404.com/accounts/register/**


### Verification Steps
- [ ] Install the application
- [ ] Start `msfconsole`
- [ ] Do `use auxiliary/gather/zoomeye_search`
- [ ] Do `set APIKEY  [APIKEY]`, replacing `[APIKEY]` with you ZoomEye API Key
- [ ] Do `set DORK [DORK]`, replacing `[DORK]`  with ZoomEye search keywork(dork)
- [ ] Do `run`
- [ ] If the execution is successful, we will see the asset data returned by ZoomEye

### Options
**APIKEY(Required parameters)**: The ZoomEye API Key, need to be obtained from [ZoomEye](https://www.zoomeye.org).

**DATABASE(Optional parameters)**: Add search results to the database.

**DORK**(Optional parameters): This item is required.Specify keywords for ZoomEye cyberspace search, please refer to ZoomEye search grammar for specific input.

**FACETS((Optional parameters))**: Aggregation of dork's full data (obtained through API after aggregation and statistics by ZoomEye).

 - host resource support field: 'product', 'device','service', 'os', 'port', 'country', 'city' 
 - web resource suppoty field:  "webapp", "component", "framework", "server", "waf", "os", "country"

**OUTFILE((Optional parameters))**: Save the results returned by ZoomEye to a file, optional parameters, and the file name is the keyword you searched for.

**PAGE**(Required parameters, default 1): Number of pages to get data.

**RESOURCE**(Required parameters, default host): Specify the search type of the ZoomEye search engine. ZoomEye supports two types: host and web.

### Scenarios
Here we take CVE-2021-28474 as an example and use ZoomEye cyberspace search engine to determine the global distribution of the vulnerability.
```
msf6 > auxiliary/gather/zoomeye_search

msf6 auxiliary(gather/zoomeye_search) > show options

Module options (auxiliary/gather/zoomeye_search):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   APIKEY                     yes       The ZoomEye API KEY
   DATABASE  false            no        Add search results to the database
   DORK                       yes       The ZoomEye dork
   FACETS                     no        Query the distribution of the full data of the dork
   OUTFILE   false            no        A filename to store ZoomEye search raw data
   PAGE      1                yes       Max amount of pages to collect
   RESOURCE  host             yes       ZoomEye Resource Type (Accepted: host, web)


msf6 auxiliary(gather/zoomeye_search) > set APIKEY 01234567-acbd-00000-1111-22222222222
APIKEY => 01234567-acbd-00000-1111-22222222222
msf6 auxiliary(gather/zoomeye_search) > set DORK 'app:"Microsoft Office SharePoint"'
DORK => app:"Microsoft Office SharePoint"
msf6 auxiliary(gather/zoomeye_search) > set RESOURCE host
RESOURCE => host
msf6 auxiliary(gather/zoomeye_search) > set FACETS city,country
FACETS => city,country
msf6 auxiliary(gather/zoomeye_search) > run

Web Search Result
=================

 IP:Port               City                    Country            Service
 -------               ----                    -------            -------
 113.***.**.253:8000   Xi'an                   China              https
 115.**.**.57:443                              Viet Nam           https
 125.***.***.86:443                            China              https
 184.***.**.139:443    Chicago                 United States      https
 184.***.**.141:443    Chicago                 United States      https
 189.***.***.201:8090                          Mexico             http
 192.***.**.63:443     Providence              United States      https
 194.***.***.36:80     Porto                   Portugal           http
 194.***.**.26:80                              Poland             http
 194.***.**.22:80                              Poland             http
 194.***.***.202:80                            Morocco            https
 194.***.***.78:443                            Germany            https
 195.***.***.22:443    Provincia de La Coruna  Spain              https
 209.***.***.137:443   Saratoga                United States      https
 220.**.***.71:443                             Republic of Korea  https
 38.**.***.140:443     New York City           United States      https
 44.***.***.60:443     Portland                United States      https
 52.***.***.230:443    Ashburn                 United States      https
 77.***.**.16:443                              Iran               https
 83.***.***.74:80                              Finland            http

Facets Search Result
====================

 city       count
 ----       -----
            2993
 Amsterdam  184
 Ashburn    87
 Boydton    86
 Chicago    71
 Dublin     95
 Guangzhou  181
 Hanoi      98
 Jakarta    73
 Riyadh     397

Facets Search Result
====================

 country         count
 -------         -----
 Brazil          232
 Canada          330
 China           466
 Colombia        190
 Germany         242
 Iran            366
 Netherlands     292
 Saudi Arabia    620
 United Kingdom  288
 United States   3183

[*] Total:9627 Current: 20
[*] Auxiliary module execution completed
```
(IP has been desensitized)
The global distribution of SharePoint can be analyzed from the above data. We can save the acquired data to the data by setting `DATABASE=true`.