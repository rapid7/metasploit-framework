## Description 
This module scrapes data from a specific web page based on a regular expression.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/scraper```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

## Options

### PATH 

The path from where the data is to be scraped from.
 
### PATTERN

A regular expression to capture data from webpage. Default value:`<title>(.*)</title>` which simply grabs the page title.

## Scenarios

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

The title of `1.1.1.18/` page is `Index of /`.

