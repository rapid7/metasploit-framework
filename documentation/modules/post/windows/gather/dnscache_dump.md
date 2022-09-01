## Vulnerable Application

This module displays the records stored in the DNS cache.  This is done by
loading the `dnsapi` DLL and calling the `DnsGetCacheDataTable` function.

## Verification Steps

1. Start msfconsole
1. Get a session on a Windows target
1. Do: `use post/windows/gather/dnscache_dump`
1. Do: `set session #`
1. Do: `run`
1. You should get the DNS entries in cache

## Options

## Scenarios

### Windows 10

```
msf6 post(windows/gather/dnscache_dump) > sessions -i 5
[*] Starting interaction with 5...

meterpreter > sysinfo
Computer        : MSEDGEWIN10
OS              : Windows 10 (10.0 Build 16299).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 5...
msf6 post(windows/gather/dnscache_dump) > run

[*] DNS Cached Entries
==================

   TYPE  DOMAIN
   ----  ------
   0001  api.mixpanel.com
   0001  developers.facebook.com
   0001  api.phantom.avira-vpn.com
   0001  settings.data.microsoft.com
   0001  activation-v2.sls.microsoft.com
   0001  api.flickr.com
   0001  win1710.ipv6.microsoft.com
   0001  smtp.gmail.com
   0001  client.wns.windows.com
   0001  bling2.midasplayer.com
   0001  www.bing.com
   0001  imap.gmail.com
   0001  www.msftncsi.com
   0001  v10.vortex-win.data.microsoft.com
   0001  evoke-windowsservices-tas.msedge.net
   0001  inference.location.live.net
   0001  settings-win.data.microsoft.com
   0001  ctldl.windowsupdate.com
   0001  tile-service.weather.microsoft.com
   0001  s.ss2.us
   0001  cdn.onenote.net
   0001  logincdn.msauth.net
   0001  telecommand.telemetry.microsoft.com
   0001  validation-v2.sls.microsoft.com
   0001  dns.msftncsi.com
   0001  dns.msftncsi.com
   0001  dispatch.avira-update.com
   0001  dispatch.avira-update.com
   0001  api.my.avira.com
   0001  prod.tl.avira.com
   0001  sls.update.microsoft.com
   0001  content.ivanti.com
   0001  api.facebook.com
   0001  login.live.com
   0001  personal.avira-update.com
   0001  g.live.com
   0001  candycrushsoda.king.com
   0001  ssldev.oes.avira.com
   0001  cdn.content.prod.cms.msn.com
   0001  v20.vortex-win.data.microsoft.com
   0001  geo2.adobe.com
   0001  o.ss2.us
   0001  time.windows.com
   0001  watson.telemetry.microsoft.com
   00ff  cxnsxtnu
   00ff  _ldap._tcp.dc._msdcs.msedgewin10
   00ff  wpad

[*] Post module execution completed
```
