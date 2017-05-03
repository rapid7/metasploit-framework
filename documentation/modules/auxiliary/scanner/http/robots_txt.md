## Description

This module will detect robots.txt files on web servers and analize its content.
This type of file can reveal interesting information about areas of the site that are not indexed.

## Vulnerable Application

This scanner work perfectly with one of the [Google](https://www.google.com/) servers.
You can easily get one of the IP addresses with a `ping google.com` command.

## Verification Steps

1. Do: `use auxiliary/scanner/http/robots_txt`
2. Do: `set rhosts <ip>`
3. Do: `run`
4. You should get the robots.txt file content

## Options

**PATH**

You can set the test path where the scanner will try to find robots.txt file. Default is / 

## Sample Output
```
msf> use auxiliary/scanner/http/robots_txt
msf auxiliary(robots_txt) > set RHOSTS 172.217.19.238
msf auxiliary(robots_txt) > run
[*] [172.217.19.238] /robots.txt found
[+] Contents of Robots.txt:
User-agent: *
Disallow: /search
Allow: /search/about
Disallow: /sdch
Disallow: /groups
Disallow: /index.html?
Disallow: /?

[...TL;DR...]

User-agent: facebookexternalhit
Allow: /imgres

Sitemap: http://www.gstatic.com/culturalinstitute/sitemaps/www_google_com_culturalinstitute/sitemap-index.xml
Sitemap: http://www.gstatic.com/earth/gallery/sitemaps/sitemap.xml
Sitemap: http://www.gstatic.com/s2/sitemaps/profiles-sitemap.xml
Sitemap: https://www.google.com/sitemap.xml

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
