## Description 
This module scrapes data from a specific web page based on a regular expression.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/scraper```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

## Scenarios
By default this module scrapes the `title` of a web page.

```
msf > use auxiliary/scanner/http/scraper
msf auxiliary(scanner/http/scraper) > set RHOSTS 1.1.1.18
RHOSTS => 1.1.1.18
msf auxiliary(scanner/http/scraper) > run 

[+] 1.1.1.18 / [Index of /]
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/scraper) >
```

