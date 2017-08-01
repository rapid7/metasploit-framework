## Description

This module will detect `robots.txt` files on web servers and analyze its content.
The `robots.txt` file is a file which is supposed to be honored by web crawlers
and bots, as locations which are not to be indexed or specifically called out
to be indexed. This can be abused to reveal interesting information about areas
of the site which an admin may not want to be public knowledge.

## Vulnerable Application

You can use almost any web application to test this module, as `robots.txt`
is extremely common.

## Verification Steps

1. Do: `use auxiliary/scanner/http/robots_txt`
2. Do: `set rhosts [ip]`
3. Do: `run`
4. You should get the `robots.txt` file content

## Options

**PATH**

You can set the test path where the scanner will try to find `robots.txt` file.
Default is `/`

## Scenarios

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
```

[...Truncated...]

```
User-agent: facebookexternalhit
Allow: /imgres

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
