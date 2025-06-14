## Description

This module is a http crawler, it will browse the links recursively from the
web site. If you have loaded a database plugin and connected to a database,
this module will report web pages and web forms.

## Vulnerable Application

You can use any web application to test the crawler.

## Options

  **URI**

  Default path is `/`

  **DirBust**

  Bruteforce common url path, default is `true` but may generate noise in reports.

  **HttpPassword**, **HttpUsername**, **HTTPAdditionalHeaders**, **HTTPCookie**

  You can add some login information

  **UserAgent**

  Default User Agent is `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`

## Verification Steps

1. Do: ```use auxiliary/scanner/http/crawler```
2. Do: ```set RHOST [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```set URI [PATH]```
4. Do: ```run```

## Scenarios

### Example against [WebGoat](https://github.com/WebGoat/WebGoat)

```
msf> use auxiliary/scanner/http/crawler
msf auxiliary(crawler) > set RHOST 127.0.0.1
msf auxiliary(crawler) > set RPORT 8080
msf auxiliary(crawler) > set URI /webgoat/
msf auxiliary(crawler) > set DirBust false
msf auxiliary(crawler) > run
[*] Crawling http://127.0.0.1:8008/webgoat/...
[*] [00001/00500]    302 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/ -> /webgoat/login.mvc
[*] [00002/00500]    200 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/login.mvc
[*]                         FORM: POST /webgoat/j_spring_security_check;jsessionid=8B1EAF2554B60EFC93A52AFCA4B6C202
[-] [00003/00500]    404 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/images/favicon.ico
[*] [00004/00500]    200 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/plugins/bootstrap/css/bootstrap.min.css
[*] [00005/00500]    200 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/css/font-awesome.min.css
[*] [00006/00500]    200 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/css/animate.css
[*] [00007/00500]    302 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/j_spring_security_check;jsessionid=8B1EAF2554B60EFC93A52AFCA4B6C202 -> /webgoat/login.mvc;jsessionid=8B1EAF2554B60EFC93A52AFCA4B6C202?error
[*] [00008/00500]    200 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/login.mvc;jsessionid=8B1EAF2554B60EFC93A52AFCA4B6C202?error
[*]                         FORM: GET /webgoat/login.mvc
[*]                         FORM: POST /webgoat/j_spring_security_check;jsessionid=8B1EAF2554B60EFC93A52AFCA4B6C202
[*] [00009/00500]    200 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/css/main.css
[*] [00010/00500]    302 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/start.mvc -> http://127.0.0.1:8008/webgoat/login.mvc
[*] [00011/00500]    200 - 127.0.0.1 - http://127.0.0.1:8008/webgoat/login.mvc
[*]                         FORM: POST /webgoat/j_spring_security_check
[*] Crawl of http://127.0.0.1:8008/webgoat/ complete
[*] Auxiliary module execution completed
```

## Follow-on: Wmap

As you see, the result is not very user friendly...

But you can view a tree of your website with the Wmap plugin. Simply run :

```
msf auxiliary(crawler) > load wmap
msf auxiliary(crawler) > wmap_sites -l
[*] Available sites
===============

     Id  Host           Vhost          Port  Proto  # Pages  # Forms
     --  ----           -----          ----  -----  -------  -------
     0   127.0.0.1      127.0.0.1      8080  http   70       80


msf auxiliary(crawler) > wmap_sites -s 0

    [127.0.0.1] (127.0.0.1)
    └── webgoat (7)
        ├── css (3)
        │   ├── animate.css
        │   ├── font-awesome.min.css
        │   └── main.css
        ├── j_spring_security_check;jsessionid=8B1EAF2554B60EFC93A52AFCA4B6C202
        ├── login.mvc
        ├── login.mvc;jsessionid=8B1EAF2554B60EFC93A52AFCA4B6C202
        ├── plugins (1)
        │   └── bootstrap (1)
        │       └── css (1)
        │           └── bootstrap.min.css
        ├── start.mvc
        └── j_spring_security_check

```
