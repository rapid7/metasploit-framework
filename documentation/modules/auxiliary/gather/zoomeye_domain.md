### Introduction
ZoomEye is a cyberspace search engine, users can search for network devices using a browser [https://www.zoomeye.org](https://www.zoomeye.org)

`zoomeye search` auxiliary module developed based on the ZoomEye API.

**NOTE: In order for this module to function properly, a ZoomEye API key is needed.
You can register for a free account here: https://sso.telnet404.com/accounts/register/**


### Verification Steps
- [ ] Install the application
- [ ] Start `msfconsole`
- [ ] Do `use auxiliary/gather/zoomeye_domian`
- [ ] Do `set APIKEY  [APIKEY]`, replacing `[APIKEY]` with you ZoomEye API Key
- [ ] Do `set ZOOMEYE_DORK [DORK]`, replacing `[DORK]`  with ZoomEye search keywork(dork)
- [ ] Do `run`
- [ ] If the execution is successful, we will see the asset data returned by ZoomEye


### Options

**APIKEY**(Required parameters): The ZoomEye API Key, need to be obtained from [ZoomEye](https://www.zoomeye.org).

**ZOOMEYE_DORK**(Required parameters): The domain name to be searched.

**SOURCE**(Required parameters, default 0): Search type, 1 is the subdomain name, 0 is the associated domain name

**DATABASE**(Optional parameters): Add search results to the database.

**OUTFILE**(Optional parameters): Save the results returned by ZoomEye to a file, optional parameters, and the file name is the keyword you searched for.

**MAXPAGE**(Required parameters, default 1): Number of pages to get data.


### Scenarios
Take google.com as an example here
```
msf6 auxiliary(gather/zoomeye_domain) > set APIKEY 01234567-acbd-00000-1111-22222222222
APIKEY => 01234567-acbd-00000-1111-22222222222
msf6 auxiliary(gather/zoomeye_domain) > set ZOOMEYE_DORK google.com
QUERY => google.com
msf6 auxiliary(gather/zoomeye_domain) > set SOURCE 0
SOURCE => 0
msf6 auxiliary(gather/zoomeye_domain) > show options

Module options (auxiliary/gather/zoomeye_domain):

   Name          Current Setting                       Required  Description
   ----          ---------------                       --------  -----------
   APIKEY        01234567-acbd-00000-1111-22222222222  yes       The ZoomEye API KEY
   DATABASE      false                                 no        Add search results to the database
   MAXPAGE       1                                     yes       Max amount of pages to collect
   OUTFILE       true                                  no        A filename to store ZoomEye search raw data
   SOURCE        0                                     yes       Domain search type
   ZOOMEYE_DORK  google.com                            yes       The ZoomEye dork

msf6 auxiliary(gather/zoomeye_domain) > run

Web Search Result
=================

 IP                        NAME                                             TIMESTAMP
 --                        ----                                             ---------
 23.227.197.75             zotero-dev.groups.google.narkive.com             2021-06-27
 35.227.233.104            zygote-body-google-body-browser.en.softonic.com  2021-06-27
 45.38.185.207             zy22g.google.feixuesw.com                        2021-06-27
 76.164.204.34             zuozuo.ads-google.com.cn                         2021-06-27
 76.164.204.34             zuanban.ads-google.com.cn                        2021-06-27
 76.164.204.34             zhensan.ads-google.com.cn                        2021-06-27
 76.164.204.34             zoutan.ads-google.com.cn                         2021-06-27
 76.164.204.34             zhushao.ads-google.com.cn                        2021-06-27
 76.164.204.34             zaijue.ads-google.com.cn                         2021-06-27
 76.164.204.34             zukui.ads-google.com.cn                          2021-06-27
 93.190.235.135            zmu6y.google.mbsmlt.com                          2021-06-27
 142.250.217.83            zivuc9.feedproxy.ghs.google.com                  2021-06-27
 142.250.217.83            zkl24l.feedproxy.ghs.google.com                  2021-06-27
 142.250.217.115           zoiz5b.feedproxy.ghs.google.com                  2021-06-27
 162.209.195.136           zo9nt.google.51kuyue.com                         2021-06-27
 192.163.229.203           zoho-google.holdworkshop.com                     2021-06-27
 204.11.56.48              zpgszrn.google.3dtops.com                        2021-06-27
 204.11.56.48              zrfdvji.google.3dtops.com                        2021-06-27
 204.11.56.48              zthonnq.google.3dtops.com                        2021-06-27
 204.11.56.48              zvliay.google.3dtops.com                         2021-06-27
 204.11.56.48              zzvjkkb.google.3dtops.com                        2021-06-27
 204.11.56.48              ztaqb.google.3dtops.com                          2021-06-27
 216.58.194.179            zsy3g1.feedproxy.ghs.google.com                  2021-06-27
 216.58.195.83             zo94ey.feedproxy.ghs.google.com                  2021-06-27
 2607:f8b0:4005:804::2013  zard8j.feedproxy.ghs.google.com                  2021-06-27
 2607:f8b0:4005:804::2013  zsy3g1.feedproxy.ghs.google.com                  2021-06-27
 2607:f8b0:4005:807::2013  zo94ey.feedproxy.ghs.google.com                  2021-06-27
 2607:f8b0:400a:80a::2013  zivuc9.feedproxy.ghs.google.com                  2021-06-27
 2607:f8b0:400a:80a::2013  zkl24l.feedproxy.ghs.google.com                  2021-06-27
 2607:f8b0:400a:80b::2013  zoiz5b.feedproxy.ghs.google.com                  2021-06-27

[*] Total: 359391, Current 30 
[*] Auxiliary module execution completed
```
