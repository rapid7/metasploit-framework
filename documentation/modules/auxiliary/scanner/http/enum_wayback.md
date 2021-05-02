## Introduction

This module pulls and parses the URLs stored by Archive.org for the purpose of replaying
during a web assessment. Finding unlinked and old pages.  This module utilizes
[Archive.org's Wayback Machine](https://archive.org/web/)'s [API](https://archive.org/help/wayback_api.php).

## Usage

```
msf5 > use auxiliary/scanner/http/enum_wayback 
msf5 auxiliary(scanner/http/enum_wayback) > set domain rapid7.com
domain => rapid7.com
msf5 auxiliary(scanner/http/enum_wayback) > run

[*] Pulling urls from Archive.org
[*] Located 43656 addresses for rapid7.com
http://mailto:info@rapid7.com/
http://mailto:sales@rapid7.com/
http://mailto:sales@rapid7.com/robots.txt
http://rapid7.com
http://rapid7.com/
http://rapid7.com/GlobalStyleSheet.css
http://rapid7.com/WebResources/images/Background2.gif
http://rapid7.com/WebResources/images/GlobalNavigation/Downloads_u.gif
http://rapid7.com/WebResources/images/GlobalNavigation/Home_d.gif
http://rapid7.com/WebResources/images/GlobalNavigation/NeXpose_d.gif
http://rapid7.com/WebResources/images/GlobalNavigation/NeXpose_u.gif
http://rapid7.com/WebResources/images/GlobalNavigation/Support_d.gif
http://rapid7.com/WebResources/images/GlobalNavigation/Support_u.gif
...snip...
```
